// Package webauthn is a software authenticator for tests. It makes the
// responses that a browser sends for navigator.credentials.create and
// navigator.credentials.get: no attestation, the user verification flag, the
// backup flags, and a sign count. The server checks the same data that a
// browser sends, so a test needs no real browser. Import it from test code only.
package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// Algorithm is the key type of a credential.
type Algorithm int

// The key types of the software authenticator.
const (
	ES256 Algorithm = iota
	EdDSA
)

// Flags of the authenticator data.
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
)

// Credential is a credential of the software authenticator.
type Credential struct {
	ID         []byte
	UserHandle []byte
	RPID       string
	SignCount  uint32
	alg        Algorithm
	ecKey      *ecdsa.PrivateKey
	edKey      ed25519.PrivateKey
}

// Authenticator is a software authenticator.
type Authenticator struct {
	// Origin and RPID are the values of the relying party. The client data has
	// the origin. The authenticator data has the hash of the RP ID.
	Origin string
	RPID   string
	Alg    Algorithm
	// UV is the flag UV that new responses have. The default is true.
	UV bool
	// BackupEligible and BackupState are the flags BE and BS of new responses.
	BackupEligible bool
	BackupState    bool
	// Creds are the credentials that Create made, in order.
	Creds []*Credential
}

// New makes an authenticator that verifies the user.
func New(origin, rpID string, alg Algorithm) *Authenticator {
	return &Authenticator{Origin: origin, RPID: rpID, Alg: alg, UV: true, BackupEligible: true, BackupState: true}
}

type call struct {
	origin       string
	rpID         string
	uv           *bool
	count        *uint32
	handle       []byte
	omitHandle   bool
	cred         *Credential
	challenge    string
	ceremonyType string
	credID       []byte
}

// CallOption changes one call. A test uses it to make a response that the
// server must refuse.
type CallOption func(*call)

// WithOrigin sets the origin in the client data.
func WithOrigin(o string) CallOption { return func(c *call) { c.origin = o } }

// WithRPID sets the RP ID of the hash in the authenticator data.
func WithRPID(id string) CallOption { return func(c *call) { c.rpID = id } }

// WithUV sets the flag UV.
func WithUV(v bool) CallOption { return func(c *call) { c.uv = &v } }

// WithCount sets the sign count of an assertion. It is stored in the credential.
func WithCount(n uint32) CallOption { return func(c *call) { c.count = &n } }

// WithUserHandle sets the user handle of an assertion.
func WithUserHandle(h []byte) CallOption { return func(c *call) { c.handle = h } }

// WithoutUserHandle leaves out the user handle of an assertion.
func WithoutUserHandle() CallOption { return func(c *call) { c.omitHandle = true } }

// WithCredential selects the credential of an assertion.
func WithCredential(cr *Credential) CallOption { return func(c *call) { c.cred = cr } }

// WithCredentialID sets the ID of the new credential of a registration.
func WithCredentialID(id []byte) CallOption { return func(c *call) { c.credID = id } }

// WithChallenge replaces the challenge in the client data (base64url).
func WithChallenge(ch string) CallOption { return func(c *call) { c.challenge = ch } }

// options is the part of the options that the authenticator reads.
type options struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		RPID             string `json:"rpId"`
		UserVerification string `json:"userVerification"`
		AuthSel          struct {
			UV          string `json:"userVerification"`
			ResidentKey string `json:"residentKey"`
		} `json:"authenticatorSelection"`
		Params []struct {
			Alg int `json:"alg"`
		} `json:"pubKeyCredParams"`
		Exclude []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
		Allow []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

func (o options) rpID() string {
	if o.PublicKey.RP.ID != "" {
		return o.PublicKey.RP.ID
	}
	return o.PublicKey.RPID
}

func parseOptions(t testing.TB, b []byte) options {
	t.Helper()
	var o options
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatalf("webauthn: options: %v", err)
	}
	return o
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(t testing.TB, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("webauthn: base64url %q: %v", s, err)
	}
	return b
}

func (a *Authenticator) newCall(opts []CallOption, typ string) call {
	c := call{origin: a.Origin, rpID: a.RPID, ceremonyType: typ}
	for _, o := range opts {
		o(&c)
	}
	return c
}

func (a *Authenticator) flags(c call, attested bool) byte {
	f := byte(flagUP)
	uv := a.UV
	if c.uv != nil {
		uv = *c.uv
	}
	if uv {
		f |= flagUV
	}
	if a.BackupEligible {
		f |= flagBE
	}
	if a.BackupEligible && a.BackupState {
		f |= flagBS
	}
	if attested {
		f |= flagAT
	}
	return f
}

func clientData(c call, challenge string) []byte {
	if c.challenge != "" {
		challenge = c.challenge
	}
	b, _ := json.Marshal(map[string]any{
		"type": c.ceremonyType, "challenge": challenge, "origin": c.origin, "crossOrigin": false,
	})
	return b
}

func (cr *Credential) sign(t testing.TB, data []byte) []byte {
	t.Helper()
	switch cr.alg {
	case ES256:
		sum := sha256.Sum256(data)
		sig, err := ecdsa.SignASN1(rand.Reader, cr.ecKey, sum[:])
		if err != nil {
			t.Fatalf("webauthn: sign: %v", err)
		}
		return sig
	default:
		return ed25519.Sign(cr.edKey, data)
	}
}

func rpHash(id string) []byte {
	h := sha256.Sum256([]byte(id))
	return h[:]
}

// Create makes the response of navigator.credentials.create for the creation
// options. It adds the credential to Creds. The response is the JSON that the
// script of the service sends.
func (a *Authenticator) Create(t testing.TB, optionsJSON []byte, opts ...CallOption) []byte {
	t.Helper()
	o := parseOptions(t, optionsJSON)
	c := a.newCall(opts, "webauthn.create")
	if c.rpID == "" {
		c.rpID = o.rpID()
	}
	cred := &Credential{ID: make([]byte, 32), UserHandle: unb64(t, o.PublicKey.User.ID), RPID: o.rpID(), alg: a.Alg}
	if _, err := rand.Read(cred.ID); err != nil {
		t.Fatalf("webauthn: random: %v", err)
	}
	if c.credID != nil {
		cred.ID = c.credID
	}
	var err error
	if a.Alg == ES256 {
		cred.ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		_, cred.edKey, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		t.Fatalf("webauthn: key: %v", err)
	}
	authData := a.authData(c, cred, 0, true)
	att, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		t.Fatalf("webauthn: attestation object: %v", err)
	}
	cd := clientData(c, o.PublicKey.Challenge)
	a.Creds = append(a.Creds, cred)
	return mustJSON(t, map[string]any{
		"id": b64(cred.ID), "rawId": b64(cred.ID), "type": "public-key",
		"response":               map[string]any{"attestationObject": b64(att), "clientDataJSON": b64(cd), "transports": []string{"internal"}},
		"clientExtensionResults": map[string]any{},
	})
}

func (a *Authenticator) authData(c call, cred *Credential, count uint32, attested bool) []byte {
	var buf bytes.Buffer
	buf.Write(rpHash(c.rpID))
	buf.WriteByte(a.flags(c, attested))
	_ = binary.Write(&buf, binary.BigEndian, count)
	if attested {
		buf.Write(make([]byte, 16))
		_ = binary.Write(&buf, binary.BigEndian, uint16(len(cred.ID))) //nolint:gosec // The ID has 32 bytes.
		buf.Write(cred.ID)
		buf.Write(cred.keyBytes())
	}
	return buf.Bytes()
}

func (cr *Credential) keyBytes() []byte {
	b, err := cr.coseBytes()
	if err != nil {
		panic(err)
	}
	return b
}

func (cr *Credential) coseBytes() ([]byte, error) {
	switch cr.alg {
	case ES256:
		return webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
			PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
			Curve:         int64(webauthncose.P256), XCoord: cr.ecKey.X.FillBytes(make([]byte, 32)), YCoord: cr.ecKey.Y.FillBytes(make([]byte, 32)),
		})
	default:
		return webauthncbor.Marshal(webauthncose.OKPPublicKeyData{
			PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.OctetKey), Algorithm: int64(webauthncose.AlgEdDSA)},
			Curve:         int64(webauthncose.Ed25519), XCoord: cr.edKey.Public().(ed25519.PublicKey),
		})
	}
}

// Get makes the response of navigator.credentials.get for the request
// options. It uses the first credential in the list of allowed credentials. If
// the list is empty, it uses the credential of the option WithCredential, or
// the last credential that Create made. The sign count of the credential
// grows by 1, unless the option WithCount sets it.
func (a *Authenticator) Get(t testing.TB, optionsJSON []byte, opts ...CallOption) []byte {
	t.Helper()
	o := parseOptions(t, optionsJSON)
	c := a.newCall(opts, "webauthn.get")
	if c.rpID == "" {
		c.rpID = o.rpID()
	}
	cred := c.cred
	if cred == nil {
		cred = a.pick(t, o)
	}
	if c.count != nil {
		cred.SignCount = *c.count
	} else {
		cred.SignCount++
	}
	authData := a.authData(c, cred, cred.SignCount, false)
	cd := clientData(c, o.PublicKey.Challenge)
	sum := sha256.Sum256(cd)
	sig := cred.sign(t, append(append([]byte{}, authData...), sum[:]...))
	resp := map[string]any{"authenticatorData": b64(authData), "clientDataJSON": b64(cd), "signature": b64(sig)}
	switch {
	case c.omitHandle:
	case c.handle != nil:
		resp["userHandle"] = b64(c.handle)
	default:
		resp["userHandle"] = b64(cred.UserHandle)
	}
	return mustJSON(t, map[string]any{
		"id": b64(cred.ID), "rawId": b64(cred.ID), "type": "public-key", "response": resp,
		"clientExtensionResults": map[string]any{},
	})
}

func (a *Authenticator) pick(t testing.TB, o options) *Credential {
	t.Helper()
	for _, al := range o.PublicKey.Allow {
		id := unb64(t, al.ID)
		for _, cr := range a.Creds {
			if bytes.Equal(cr.ID, id) {
				return cr
			}
		}
	}
	if len(o.PublicKey.Allow) > 0 || len(a.Creds) == 0 {
		t.Fatalf("webauthn: the authenticator has no credential for the request")
	}
	return a.Creds[len(a.Creds)-1]
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("webauthn: json: %v", err)
	}
	return b
}
