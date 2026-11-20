// Package argon2 is the adapter of the port passwordhasher. It hashes
// passwords with argon2id and limits the number of hashes that run at the same
// time.
package argon2

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"

	"github.com/techorionai/constellation-identity/internal/ports/passwordhasher"
)

// Parameters of the current hash.
const (
	DefaultMemoryKiB = 64 * 1024
	DefaultTime      = 3
	DefaultThreads   = 1
	saltLength       = 16
	keyLength        = 32

	// maxMemoryKiB and maxTime limit the parameters that Verify accepts from
	// a stored hash. A bad value must not make the service use unlimited memory.
	maxMemoryKiB = 512 * 1024
	maxTime      = 16
	maxThreads   = 16
)

// Config is the config of the hasher.
type Config struct {
	// MaxConcurrent is the number of hashes that can run at the same time.
	MaxConcurrent int
	// QueueTimeout is the longest wait for a slot.
	QueueTimeout time.Duration
	// MemoryKiB, Time, and Threads are the argon2id parameters. A zero value
	// means the default.
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// Hasher is the argon2id password hasher.
type Hasher struct {
	cfg      Config
	slots    chan struct{}
	rejected metric.Int64Counter
}

var _ passwordhasher.Hasher = (*Hasher)(nil)

// New makes the hasher.
func New(cfg Config) (*Hasher, error) {
	if cfg.MaxConcurrent < 1 {
		return nil, errors.New("argon2: MaxConcurrent must be 1 or more")
	}
	if cfg.QueueTimeout <= 0 {
		return nil, errors.New("argon2: QueueTimeout must be more than 0")
	}
	if cfg.MemoryKiB == 0 {
		cfg.MemoryKiB = DefaultMemoryKiB
	}
	if cfg.Time == 0 {
		cfg.Time = DefaultTime
	}
	if cfg.Threads == 0 {
		cfg.Threads = DefaultThreads
	}
	rejected, err := otel.Meter("identity").Int64Counter("identity.password.queue_rejected",
		metric.WithDescription("Password hashes that waited too long for a free slot."))
	if err != nil {
		return nil, fmt.Errorf("argon2: make the counter: %w", err)
	}
	return &Hasher{cfg: cfg, slots: make(chan struct{}, cfg.MaxConcurrent), rejected: rejected}, nil
}

// Normalize returns the password in NFC form.
func (h *Hasher) Normalize(password string) string { return norm.NFC.String(password) }

// acquire waits for a free slot. It returns passwordhasher.ErrBusy when the
// queue timeout ends first. It returns the error of ctx when ctx ends first.
func (h *Hasher) acquire(ctx context.Context) (release func(), err error) {
	timer := time.NewTimer(h.cfg.QueueTimeout)
	defer timer.Stop()
	select {
	case h.slots <- struct{}{}:
		return func() { <-h.slots }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		h.rejected.Add(context.WithoutCancel(ctx), 1)
		return nil, passwordhasher.ErrBusy
	}
}

// Hash returns the PHC string of a normalized password.
func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	release, err := h.acquire(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("argon2: random salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, h.cfg.Time, h.cfg.MemoryKiB, h.cfg.Threads, keyLength)
	return encode(h.cfg.MemoryKiB, h.cfg.Time, h.cfg.Threads, salt, key), nil
}

// Verify checks a normalized password against a PHC string. A string that is
// not valid is not an error of the caller. It gives ok false.
func (h *Hasher) Verify(ctx context.Context, password, encoded string) (ok, needsRehash bool, err error) {
	p, salt, key, perr := decode(encoded)
	if perr != nil {
		return false, false, nil //nolint:nilerr // A bad stored hash never matches.
	}
	release, err := h.acquire(ctx)
	if err != nil {
		return false, false, err
	}
	defer release()
	got := argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, uint32(len(key))) //nolint:gosec // The length is 32.
	if subtle.ConstantTimeCompare(got, key) != 1 {
		return false, false, nil
	}
	needs := p.memory != h.cfg.MemoryKiB || p.time != h.cfg.Time || p.threads != h.cfg.Threads || len(key) != keyLength
	return true, needs, nil
}

type params struct {
	memory  uint32
	time    uint32
	threads uint8
}

func encode(memory, t uint32, threads uint8, salt, key []byte) string {
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, t, threads, b64.EncodeToString(salt), b64.EncodeToString(key))
}

var errFormat = errors.New("argon2: the hash has a wrong format")

func decode(encoded string) (p params, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return params{}, nil, nil, errFormat
	}
	var m, t, th uint64
	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return params{}, nil, nil, errFormat
	}
	for i, prefix := range []string{"m=", "t=", "p="} {
		v, ok := strings.CutPrefix(fields[i], prefix)
		if !ok {
			return params{}, nil, nil, errFormat
		}
		n, perr := strconv.ParseUint(v, 10, 32)
		if perr != nil {
			return params{}, nil, nil, errFormat
		}
		switch i {
		case 0:
			m = n
		case 1:
			t = n
		default:
			th = n
		}
	}
	if m < 8 || m > maxMemoryKiB || t < 1 || t > maxTime || th < 1 || th > maxThreads {
		return params{}, nil, nil, errFormat
	}
	b64 := base64.RawStdEncoding
	salt, err = b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return params{}, nil, nil, errFormat
	}
	key, err = b64.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return params{}, nil, nil, errFormat
	}
	return params{memory: uint32(m), time: uint32(t), threads: uint8(th)}, salt, key, nil //nolint:gosec // The bounds are checked above.
}
