package testserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Web is a browser for the HTML pages. It keeps cookies by name and sends them
// to the server, also over http (a real browser accepts a Secure cookie on
// localhost). It does not follow redirects.
type Web struct {
	srv    *Server
	client *http.Client
	mu     sync.Mutex
	// Header gives extra request headers, for example Sec-Fetch-Site.
	Header  http.Header
	cookies map[string]string
}

// NewWeb makes a browser for the server.
func (s *Server) NewWeb() *Web {
	return &Web{
		srv: s,
		client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		Header:  http.Header{},
		cookies: map[string]string{},
	}
}

// Cookie returns the value of a cookie, or an empty string.
func (w *Web) Cookie(name string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cookies[name]
}

// SetCookie sets a cookie value, for example an old session cookie.
func (w *Web) SetCookie(name, value string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.cookies[name] = value
}

// Do sends a request. path is a path with a query, or a full URL. The body is
// sent as a form if form is not nil.
func (w *Web) Do(t testing.TB, method, path string, form url.Values) (Response, []byte) {
	t.Helper()
	if form != nil {
		return w.DoBody(t, method, path, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	}
	return w.DoBody(t, method, path, "", nil)
}

// PostJSON sends a POST request with a JSON body.
func (w *Web) PostJSON(t testing.TB, path string, body []byte) (Response, []byte) {
	t.Helper()
	return w.DoBody(t, http.MethodPost, path, "application/json", bytes.NewReader(body))
}

// DoBody sends a request with a body and a content type. An empty content type
// sets no header.
func (w *Web) DoBody(t testing.TB, method, path, contentType string, body io.Reader) (Response, []byte) {
	t.Helper()
	if i := strings.Index(path, "://"); i >= 0 {
		u, err := url.Parse(path)
		if err != nil {
			t.Fatalf("testserver: parse %q: %v", path, err)
		}
		path = u.RequestURI()
	}
	req, err := http.NewRequestWithContext(context.Background(), method, w.srv.PublicURL+path, body)
	if err != nil {
		t.Fatalf("testserver: request: %v", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, vs := range w.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	w.mu.Lock()
	for name, value := range w.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value}) //nolint:gosec // G124: a request cookie has no Secure or HttpOnly attribute.
	}
	w.mu.Unlock()
	resp, err := w.client.Do(req)
	if err != nil {
		t.Fatalf("testserver: %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("testserver: read body: %v", err)
	}
	w.mu.Lock()
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(w.cookies, c.Name)
		} else {
			w.cookies[c.Name] = c.Value
		}
	}
	w.mu.Unlock()
	return Response{StatusCode: resp.StatusCode, Header: resp.Header, Cookies: resp.Cookies()}, b
}

// Get sends a GET request.
func (w *Web) Get(t testing.TB, path string) (Response, []byte) {
	t.Helper()
	return w.Do(t, http.MethodGet, path, nil)
}

// PostForm sends a form POST request.
func (w *Web) PostForm(t testing.TB, path string, form url.Values) (Response, []byte) {
	t.Helper()
	return w.Do(t, http.MethodPost, path, form)
}

// LogCapture is a log handler that keeps the records as JSON lines.
type LogCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
	h   slog.Handler
}

// NewLogCapture makes a capture. Its Logger writes at the level debug.
func NewLogCapture() *LogCapture {
	c := &LogCapture{}
	c.h = slog.NewJSONHandler(&lockedWriter{c: c}, &slog.HandlerOptions{Level: slog.LevelDebug})
	return c
}

type lockedWriter struct{ c *LogCapture }

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.c.mu.Lock()
	defer w.c.mu.Unlock()
	return w.c.buf.Write(p)
}

// Logger returns a logger that writes to the capture.
func (c *LogCapture) Logger() *slog.Logger { return slog.New(c.h) }

// Text returns all records as text.
func (c *LogCapture) Text() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// Records returns the records as maps.
func (c *LogCapture) Records(t testing.TB) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(c.Text(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("testserver: log record: %v", err)
		}
		out = append(out, m)
	}
	return out
}

// SetupPendingMessage is the message of the log record that says a setup link
// exists. The record has the expiry and never the link.
const SetupPendingMessage = "identity: first-admin setup link pending"

// SetupPendingRecords returns the records that say a setup link exists, in
// order.
func (c *LogCapture) SetupPendingRecords(t testing.TB) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, r := range c.Records(t) {
		if r["msg"] == SetupPendingMessage {
			out = append(out, r)
		}
	}
	return out
}

// TokenOf returns the token query value of a link.
func TokenOf(t testing.TB, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("testserver: parse link: %v", err)
	}
	return u.Query().Get("token")
}
