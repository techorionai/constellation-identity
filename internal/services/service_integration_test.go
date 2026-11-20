//go:build integration

package services_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	platformsecrets "github.com/techorionai/constellation-platform-go/secrets"
	secretspg "github.com/techorionai/constellation-platform-go/secrets/postgres"

	"github.com/techorionai/constellation-identity/internal/adapters/postgres"
	"github.com/techorionai/constellation-identity/internal/domain"
	"github.com/techorionai/constellation-identity/internal/services"
	"github.com/techorionai/constellation-identity/resources/test/testserver"
)

var ctx = context.Background()

func jwksKeys(t *testing.T, s *testserver.Server) []map[string]any {
	t.Helper()
	resp, body := s.Get(t, "/.well-known/jwks.json")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks status = %d", resp.StatusCode)
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatal(err)
	}
	return set.Keys
}

func count(t *testing.T, s *testserver.Server, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.Pool(t).QueryRow(ctx, query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func readyz(t *testing.T, s *testserver.Server) int {
	t.Helper()
	resp, err := http.Get(s.AdminURL + "/readyz") //nolint:noctx,gosec // A test.
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestIntegration shares one pair of containers between the cases. Each case
// uses its own database.
func TestIntegration(t *testing.T) {
	env := testserver.NewEnv(t)

	// I1: start the service in the test process.
	t.Run("I1_start", func(t *testing.T) {
		s := env.Start(t)
		if got := readyz(t, s); got != http.StatusOK {
			t.Fatalf("/readyz = %d", got)
		}
		if n := count(t, s, `SELECT count(*) FROM information_schema.tables WHERE table_name = 'platform_secrets'`); n != 1 {
			t.Fatal("table platform_secrets is missing")
		}
		for _, table := range []string{"schema_migrations", "platform_secrets_schema_migrations", "signing_keys", "clients", "client_keys"} {
			if n := count(t, s, `SELECT count(*) FROM information_schema.tables WHERE table_name = $1`, table); n != 1 {
				t.Fatalf("table %s is missing", table)
			}
		}
		if n := count(t, s, `SELECT count(*) FROM signing_keys WHERE state = 'active'`); n != 1 {
			t.Fatalf("active keys = %d", n)
		}
	})

	// I2: two instances start at the same time on one database.
	t.Run("I2_two_instances", func(t *testing.T) {
		db := env.NewDB(t)
		mk := testserver.MasterKey(t)
		var wg sync.WaitGroup
		servers := make([]*testserver.Server, 2)
		errs := make([]error, 2)
		for i := range servers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				servers[i], errs[i] = env.TryStart(t, testserver.WithDB(db), testserver.WithMasterKey(mk, "test"))
			}()
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("instance %d: %v", i, err)
			}
		}
		if n := count(t, servers[0], `SELECT count(*) FROM signing_keys WHERE state = 'active'`); n != 1 {
			t.Fatalf("active keys = %d, want exactly 1", n)
		}
		if n := count(t, servers[0], `SELECT count(*) FROM signing_keys`); n != 1 {
			t.Fatalf("keys = %d, want exactly 1", n)
		}
	})

	// I3: the JWKS has one P-256 public key, and the database has no private key.
	t.Run("I3_jwks_and_storage", func(t *testing.T) {
		mk := testserver.MasterKey(t)
		s := env.Start(t, testserver.WithMasterKey(mk, "test"))
		resp, _ := s.Get(t, "/.well-known/jwks.json")
		if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=300" {
			t.Fatalf("Cache-Control = %q", cc)
		}
		keys := jwksKeys(t, s)
		if len(keys) != 1 || keys[0]["kty"] != "EC" || keys[0]["crv"] != "P-256" || keys[0]["alg"] != "ES256" || keys[0]["use"] != "sig" {
			t.Fatalf("keys = %v", keys)
		}
		for name := range keys[0] {
			if domain.IsPrivateJWKField(name) {
				t.Fatalf("jwks has the private field %s", name)
			}
		}

		pool := s.Pool(t)
		rows, err := pool.Query(ctx, `SELECT column_name FROM information_schema.columns WHERE table_name = 'signing_keys'`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var col string
			_ = rows.Scan(&col)
			if strings.Contains(col, "private_key") && col != "private_key_name" {
				t.Fatalf("signing_keys has the column %s", col)
			}
		}
		rows.Close()
		var jwkText string
		if err := pool.QueryRow(ctx, `SELECT public_jwk::text FROM signing_keys`).Scan(&jwkText); err != nil {
			t.Fatal(err)
		}
		var generic map[string]any
		_ = json.Unmarshal([]byte(jwkText), &generic)
		if _, has := generic["d"]; has {
			t.Fatal("public_jwk has the member d")
		}

		// The secret row holds ciphertext only. Open it with the master key to get
		// the raw private value, then search the row for it.
		var wrapped, ciphertext []byte
		if err := pool.QueryRow(ctx, `SELECT wrapped_dek, ciphertext FROM platform_secrets WHERE name LIKE 'identity/signing-keys/%'`).
			Scan(&wrapped, &ciphertext); err != nil {
			t.Fatal(err)
		}
		ring, err := platformsecrets.NewKeyRing(s.Config.Secrets)
		if err != nil {
			t.Fatal(err)
		}
		svc := platformsecrets.NewService(ring, secretspg.NewRepository(pool))
		names, err := svc.List(ctx, platformsecrets.ListParams{})
		if err != nil || len(names.Names) != 1 {
			t.Fatalf("names = %v, err %v", names, err)
		}
		pem, err := svc.Get(ctx, names.Names[0])
		if err != nil {
			t.Fatal(err)
		}
		priv, err := domain.DecodePrivateKey(pem)
		if err != nil {
			t.Fatal(err)
		}
		d, err := priv.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		for label, blob := range map[string][]byte{"wrapped_dek": wrapped, "ciphertext": ciphertext} {
			if strings.Contains(string(blob), "PRIVATE KEY") {
				t.Fatalf("%s has PEM text", label)
			}
			if strings.Contains(string(blob), string(d)) {
				t.Fatalf("%s has the raw private value", label)
			}
		}
	})

	// I4: the discovery document.
	t.Run("I4_discovery", func(t *testing.T) {
		s := env.Start(t)
		resp, body := s.Get(t, "/.well-known/openid-configuration")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		var doc map[string]any
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatal(err)
		}
		if doc["issuer"] != s.Config.Issuer {
			t.Fatalf("issuer = %v, want %s", doc["issuer"], s.Config.Issuer)
		}
		uri, _ := doc["jwks_uri"].(string)
		if !strings.HasPrefix(uri, s.Config.Issuer) {
			t.Fatalf("jwks_uri = %q", uri)
		}
		r, err := http.Get(uri) //nolint:noctx,gosec // A test.
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("jwks_uri status = %d", r.StatusCode)
		}
	})

	// I5: rotation. The values differ from the plan, see docs/development.md:
	// with a rotation period equal to the retire time, the second rotation
	// starts when the first retired key ends, so the JWKS never has one key.
	t.Run("I5_rotation", func(t *testing.T) {
		s := env.Start(t,
			testserver.WithKeyPolicy(domain.KeyPolicy{RotationPeriod: 4 * time.Second, PublishDelay: time.Second, RetireAfter: 2 * time.Second}),
			testserver.WithKeyIntervals(200*time.Millisecond, 200*time.Millisecond))

		first := jwksKeys(t, s)
		if len(first) != 1 {
			t.Fatalf("keys at start = %d", len(first))
		}
		firstKid := first[0]["kid"]

		var sawTwo, sawReplaced bool
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) && !sawReplaced {
			keys := jwksKeys(t, s)
			if len(keys) == 0 {
				t.Fatal("the JWKS has no key: there is a gap")
			}
			has := func(kid any) bool {
				for _, k := range keys {
					if k["kid"] == kid {
						return true
					}
				}
				return false
			}
			if len(keys) == 2 && has(firstKid) {
				sawTwo = true
			}
			if sawTwo && len(keys) == 1 && !has(firstKid) {
				sawReplaced = true
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !sawTwo {
			t.Fatal("the JWKS never had two keys")
		}
		if !sawReplaced {
			t.Fatal("the JWKS did not return to one key without the old key")
		}
	})

	// I6: clients file sync.
	t.Run("I6_clients_sync", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "clients.yaml")
		jwk := domain.PublicJWK{}
		{
			key, _, err := domain.NewSigningKey(time.Now(), domain.KeyActive, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			jwk = key.PublicJWK
		}
		entry := func(id string) string {
			return "  - id: " + id + "\n    app: " + id + "\n    name: Client " + id + "\n    keys:\n" +
				"      - kid: " + id + "-1\n        jwk: { kty: EC, crv: P-256, x: \"" + jwk.X + "\", y: \"" + jwk.Y + "\" }\n"
		}
		write := func(body string) {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		write("clients:\n" + entry("aaa") + entry("bbb"))

		db := env.NewDB(t)
		mk := testserver.MasterKey(t)
		opts := []testserver.Option{testserver.WithDB(db), testserver.WithMasterKey(mk, "test"), testserver.WithClientsFile(path)}
		s1 := env.Start(t, opts...)
		repo := postgres.NewClients(s1.Pool(t))
		for _, id := range []string{"aaa", "bbb"} {
			c, err := repo.Get(ctx, id)
			if err != nil || c.Disabled || c.Source != domain.SourceConfig || c.Type != domain.ClientTypeService {
				t.Fatalf("client %s = %+v, err %v", id, c, err)
			}
			if ks, err := repo.Keys(ctx, id); err != nil || len(ks) != 1 {
				t.Fatalf("keys of %s = %v, err %v", id, ks, err)
			}
		}
		now := time.Now()
		if _, err := s1.Pool(t).Exec(ctx, `INSERT INTO clients (id, type, app, name, disabled, source, created_at, updated_at)
			VALUES ('apiclient', 'service', 'apiapp', 'Api', false, 'api', $1, $1)`, now); err != nil {
			t.Fatal(err)
		}
		s1.Stop()

		write("clients:\n" + entry("aaa"))
		s2 := env.Start(t, opts...)
		repo = postgres.NewClients(s2.Pool(t))
		a, _ := repo.Get(ctx, "aaa")
		b, _ := repo.Get(ctx, "bbb")
		api, _ := repo.Get(ctx, "apiclient")
		if a.Disabled {
			t.Fatal("client aaa must be enabled")
		}
		if !b.Disabled {
			t.Fatal("client bbb must be disabled")
		}
		if api.Disabled || api.Source != domain.SourceAPI {
			t.Fatalf("the api client changed: %+v", api)
		}
	})

	// I6a, I6b: a different master key, then the forced rotation.
	t.Run("I6a_I6b_master_key", func(t *testing.T) {
		db := env.NewDB(t)
		key1 := testserver.MasterKey(t)
		s1 := env.Start(t, testserver.WithDB(db), testserver.WithMasterKey(key1, "k1"))
		oldKid := jwksKeys(t, s1)[0]["kid"].(string)
		pool := s1.Pool(t)
		s1.Stop()

		key2 := testserver.MasterKey(t)
		for _, id := range []string{"k2", "k1"} { // an unknown ID, then a known ID with a wrong key
			_, err := env.TryStart(t, testserver.WithDB(db), testserver.WithMasterKey(key2, id))
			if err == nil {
				t.Fatalf("id %s: the start must fail", id)
			}
			if !strings.Contains(err.Error(), "does not decrypt with the master key `"+id+"`") ||
				!strings.Contains(err.Error(), "rotate-signing-keys --force") {
				t.Fatalf("id %s: error = %v", id, err)
			}
			var keys, secretRows int
			_ = pool.QueryRow(ctx, `SELECT count(*) FROM signing_keys`).Scan(&keys)
			_ = pool.QueryRow(ctx, `SELECT count(*) FROM platform_secrets`).Scan(&secretRows)
			if keys != 1 || secretRows != 1 {
				t.Fatalf("id %s: keys = %d, secrets = %d, want 1 and 1: no new key", id, keys, secretRows)
			}
		}

		// I6b: force the rotation with the new master key.
		cfg := env.Config(t, testserver.WithDB(db), testserver.WithMasterKey(key2, "k2"))
		if err := services.ForceRotateSigningKeys(ctx, cfg, slog.Default()); err != nil {
			t.Fatal(err)
		}
		s2 := env.Start(t, testserver.WithDB(db), testserver.WithMasterKey(key2, "k2"))
		keys := jwksKeys(t, s2)
		if len(keys) != 1 || keys[0]["kid"] == oldKid {
			t.Fatalf("keys = %v, old kid %s", keys, oldKid)
		}
		if n := count(t, s2, `SELECT count(*) FROM signing_keys WHERE state = 'active'`); n != 1 {
			t.Fatalf("active keys = %d", n)
		}
		if n := count(t, s2, `SELECT count(*) FROM platform_secrets WHERE name LIKE 'identity/signing-keys/%'`); n != 1 {
			t.Fatalf("signing key secrets = %d, want 1", n)
		}
	})

	// I6c: the operations of later issues.
	t.Run("I6c_not_implemented", func(t *testing.T) {
		s := env.Start(t)
		resp, body := s.Get(t, "/v1/roles")
		if resp.StatusCode != http.StatusNotImplemented {
			t.Fatalf("/v1/roles = %d", resp.StatusCode)
		}
		var p map[string]any
		if err := json.Unmarshal(body, &p); err != nil || p["code"] != "not_implemented" {
			t.Fatalf("problem = %s", body)
		}
		if resp.Header.Get("X-Request-ID") == "" {
			t.Fatal("the response has no request ID")
		}
		resp, body = s.Post(t, "/oauth/token", "grant_type=client_credentials")
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("/oauth/token = %d", resp.StatusCode)
		}
		var e map[string]any
		if err := json.Unmarshal(body, &e); err != nil || e["error"] != "unsupported_grant_type" {
			t.Fatalf("error body = %s", body)
		}
	})
	// I5a (R23): a retired key has no secret from the time it is retired. The
	// row stays until RetireAfter.
	t.Run("I5a_retired_key_has_no_secret", func(t *testing.T) {
		s := env.Start(t,
			testserver.WithKeyPolicy(domain.KeyPolicy{RotationPeriod: 3 * time.Second, PublishDelay: time.Second, RetireAfter: time.Hour}),
			testserver.WithKeyIntervals(200*time.Millisecond, 200*time.Millisecond))
		deadline := time.Now().Add(20 * time.Second)
		for count(t, s, `SELECT count(*) FROM signing_keys WHERE state = 'retired'`) == 0 {
			if time.Now().After(deadline) {
				t.Fatal("no retired key")
			}
			time.Sleep(100 * time.Millisecond)
		}
		const query = `SELECT count(*) FROM signing_keys k JOIN platform_secrets p ON p.name = k.private_key_name WHERE k.state = 'retired'`
		for count(t, s, query) != 0 {
			if time.Now().After(deadline) {
				t.Fatal("the secret of a retired key stays")
			}
			time.Sleep(100 * time.Millisecond)
		}
		if n := count(t, s, `SELECT count(*) FROM signing_keys WHERE state = 'retired'`); n == 0 {
			t.Fatal("the retired row must stay until RetireAfter")
		}
	})

	// I8 (R22): the JWKS does not serve a row whose kid is not the thumbprint
	// of its key. The database refuses a second active row and a retired row
	// with no retired_at.
	t.Run("I8_rows_bound_to_kid", func(t *testing.T) {
		s := env.Start(t, testserver.WithKeyIntervals(time.Hour, 200*time.Millisecond))
		attacker, _, err := domain.NewSigningKey(time.Now(), domain.KeyPending, time.Now().AddDate(1, 0, 0))
		if err != nil {
			t.Fatal(err)
		}
		attacker.KID = "attacker"
		attacker.PublicJWK.Kid = "attacker"
		attacker.PrivateKeyName = domain.PrivateKeyName("attacker")
		jwk, err := json.Marshal(attacker.PublicJWK)
		if err != nil {
			t.Fatal(err)
		}
		pool := s.Pool(t)
		const insert = `INSERT INTO signing_keys (kid, alg, public_jwk, private_key_name, state, created_at, activates_at, retired_at)
			VALUES ($1, 'ES256', $2, $3, $4, now(), $5, $6)`
		if _, err := pool.Exec(ctx, insert, "attacker", jwk, attacker.PrivateKeyName, "pending", attacker.ActivatesAt, nil); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		for _, k := range jwksKeys(t, s) {
			if k["kid"] == "attacker" {
				t.Fatal("the JWKS serves a key whose kid is not its thumbprint")
			}
		}
		if _, err := pool.Exec(ctx, insert, "second", jwk, domain.PrivateKeyName("second"), "active", time.Now(), nil); err == nil {
			t.Fatal("the database must refuse a second active row")
		}
		if _, err := pool.Exec(ctx, insert, "gone", jwk, domain.PrivateKeyName("gone"), "retired", time.Now(), nil); err == nil {
			t.Fatal("the database must refuse a retired row with no retired_at")
		}
	})

	// insertAttacker inserts a pending row whose kid is not the thumbprint of
	// its key.
	insertAttacker := func(t *testing.T, s *testserver.Server, activatesAt time.Time) {
		t.Helper()
		attacker, _, err := domain.NewSigningKey(time.Now(), domain.KeyPending, activatesAt)
		if err != nil {
			t.Fatal(err)
		}
		attacker.PublicJWK.Kid = "attacker"
		jwk, err := json.Marshal(attacker.PublicJWK)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.Pool(t).Exec(ctx, `INSERT INTO signing_keys (kid, alg, public_jwk, private_key_name, state, created_at, activates_at)
			VALUES ('attacker', 'ES256', $1, $2, 'pending', now(), $3)`, jwk, domain.PrivateKeyName("attacker"), activatesAt)
		if err != nil {
			t.Fatal(err)
		}
	}

	// I9 (R22): an invalid pending row with a far activation time does not
	// stop the rotation.
	t.Run("I9_invalid_future_pending_row", func(t *testing.T) {
		s := env.Start(t,
			testserver.WithKeyPolicy(domain.KeyPolicy{RotationPeriod: 3 * time.Second, PublishDelay: time.Second, RetireAfter: time.Hour}),
			testserver.WithKeyIntervals(200*time.Millisecond, 200*time.Millisecond))
		insertAttacker(t, s, time.Now().AddDate(1, 0, 0))
		deadline := time.Now().Add(20 * time.Second)
		for count(t, s, `SELECT count(*) FROM signing_keys WHERE kid <> 'attacker' AND state <> 'retired'`) < 2 {
			if time.Now().After(deadline) {
				t.Fatal("the rotation does not make a valid pending key")
			}
			time.Sleep(100 * time.Millisecond)
		}
	})

	// I10 (R22): an invalid pending row that is due is not activated. The real
	// key stays active with its secret, and the service stays ready.
	t.Run("I10_invalid_due_pending_row", func(t *testing.T) {
		s := env.Start(t, testserver.WithKeyIntervals(200*time.Millisecond, 200*time.Millisecond))
		realKid := jwksKeys(t, s)[0]["kid"].(string)
		insertAttacker(t, s, time.Now().Add(-time.Hour))
		time.Sleep(2 * time.Second)
		if n := count(t, s, `SELECT count(*) FROM signing_keys WHERE kid = $1 AND state = 'active'`, realKid); n != 1 {
			t.Fatal("the real key is not active")
		}
		if n := count(t, s, `SELECT count(*) FROM signing_keys WHERE kid = 'attacker' AND state = 'pending'`); n != 1 {
			t.Fatal("the attacker row changed state")
		}
		if n := count(t, s, `SELECT count(*) FROM platform_secrets WHERE name = $1`, domain.PrivateKeyName(realKid)); n != 1 {
			t.Fatal("the secret of the real key is gone")
		}
		if got := readyz(t, s); got != http.StatusOK {
			t.Fatalf("readyz = %d", got)
		}
	})
}
