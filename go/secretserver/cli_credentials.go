package secretserver

// Threats: CLICredentials lets a program reuse the developer's `ss login`
// session without handling refresh tokens. It runs the CLI from an argv array
// (no shell), bounds its runtime (30 s) and stdout (64 KiB), fails closed on
// any malformed answer, and never puts the access token or the CLI's stdout
// in an error. It does NOT protect against a malicious `ss` binary on PATH or
// in SS_CLI_PATH, or against other code running as the same OS user, which
// can run the CLI itself.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	defaultCLITimeout = 30 * time.Second
	maxCLIOutputBytes = 64 << 10
	maxCLIStderrBytes = 4 << 10
	// cliTokenRefreshSkew: a cached token is replaced this long before it
	// expires.
	cliTokenRefreshSkew = 60 * time.Second
)

// ErrCLINotLoggedIn is returned (wrapped) when `ss auth print-access-token`
// exits with status 2: there is no usable SSO session and the user must run
// `ss login`.
var ErrCLINotLoggedIn = errors.New("SecretServer CLI is not logged in: run `ss login`")

// CLICredentialProvider obtains short-lived access tokens from the `ss` CLI
// (`ss auth print-access-token --format json`) and caches each one in memory
// until 60 seconds before it expires. It is safe for concurrent use.
type CLICredentialProvider struct {
	// Path is the CLI executable. Empty means $SS_CLI_PATH, or `ss` on PATH.
	Path string

	timeout   time.Duration
	mu        sync.Mutex
	token     string
	expiresAt time.Time
	apiURL    string
}

// CLICredentials returns a provider backed by the `ss` CLI's SSO login. Use
// its Token method as Config.TokenProvider, or NewCLIClient to build a
// client directly from the CLI's session.
func CLICredentials() *CLICredentialProvider {
	return &CLICredentialProvider{}
}

// Token returns a valid access token, running the CLI only when the cached
// token is missing or expires within 60 seconds.
func (p *CLICredentialProvider) Token(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.token != "" && time.Now().Before(p.expiresAt.Add(-cliTokenRefreshSkew)) {
		return p.token, nil
	}
	p.token, p.expiresAt = "", time.Time{}
	out, err := p.run(ctx)
	if err != nil {
		return "", err
	}
	p.token, p.expiresAt, p.apiURL = out.AccessToken, out.expiresAt, out.APIURL
	return out.AccessToken, nil
}

// APIURL returns the API URL recorded by `ss login`, running the CLI first
// if there is no cached token.
func (p *CLICredentialProvider) APIURL(ctx context.Context) (string, error) {
	if _, err := p.Token(ctx); err != nil {
		return "", err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.apiURL, nil
}

type cliToken struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   string `json:"expires_at"`
	APIURL      string `json:"api_url"`
	TenantID    string `json:"tenant_id"`
	expiresAt   time.Time
}

func (p *CLICredentialProvider) run(ctx context.Context) (*cliToken, error) {
	path := p.Path
	if path == "" {
		path = os.Getenv("SS_CLI_PATH")
	}
	if path == "" {
		path = "ss"
	}
	timeout := p.timeout
	if timeout <= 0 {
		timeout = defaultCLITimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdout := &cappedBuffer{max: maxCLIOutputBytes}
	stderr := &cappedBuffer{max: maxCLIStderrBytes, truncate: true}
	cmd := exec.CommandContext(ctx, path, "auth", "print-access-token", "--format", "json")
	cmd.Stdin = nil
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// Bounds the wait for pipes held open by a killed CLI's children.
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()

	switch {
	case stdout.overflow:
		return nil, fmt.Errorf("`ss auth print-access-token` output exceeds %d bytes", maxCLIOutputBytes)
	case ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		return nil, fmt.Errorf("`ss auth print-access-token` timed out after %s", timeout)
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("SecretServer CLI %q not found: install `ss` or set SS_CLI_PATH", path)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.ExitCode() == 2 {
			return nil, ErrCLINotLoggedIn
		}
		return nil, fmt.Errorf("`ss auth print-access-token` failed (exit %d)%s", exitErr.ExitCode(), stderrExcerpt(stderr.Bytes()))
	}
	if err != nil {
		return nil, fmt.Errorf("running SecretServer CLI %q: %w", path, err)
	}

	var out cliToken
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("`ss auth print-access-token` returned invalid JSON")
	}
	if !validBearerToken(out.AccessToken) {
		return nil, fmt.Errorf("`ss auth print-access-token` returned no usable access_token")
	}
	if out.expiresAt, err = time.Parse(time.RFC3339, out.ExpiresAt); err != nil {
		return nil, fmt.Errorf("`ss auth print-access-token` returned an invalid expires_at")
	}
	return &out, nil
}

// validBearerToken reports whether t is non-empty printable ASCII without
// spaces, so it cannot alter the Authorization header.
func validBearerToken(t string) bool {
	if t == "" {
		return false
	}
	for i := 0; i < len(t); i++ {
		if t[i] <= 0x20 || t[i] >= 0x7f {
			return false
		}
	}
	return true
}

// stderrExcerpt returns the first line of the CLI's stderr, at most 200
// printable characters, for error messages. The CLI never writes tokens to
// stderr.
func stderrExcerpt(b []byte) string {
	line, _, _ := strings.Cut(string(bytes.TrimSpace(b)), "\n")
	line = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, line)
	if len(line) > 200 {
		line = line[:200]
	}
	if line == "" {
		return ""
	}
	return ": " + line
}

// cappedBuffer keeps at most max bytes and records whether more were written.
// Past the cap, writes fail (so the copy from the child stops) unless
// truncate is set, in which case the excess is discarded.
type cappedBuffer struct {
	buf      bytes.Buffer
	max      int
	truncate bool
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); len(p) > room {
		b.overflow = true
		if !b.truncate {
			return 0, errors.New("output limit exceeded")
		}
		b.buf.Write(p[:room])
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *cappedBuffer) Bytes() []byte { return b.buf.Bytes() }

// NewCLIClient returns a client authenticated by the `ss login` session.
// cfg may be nil; it must not set APIKey or TokenProvider. When cfg.APIURL
// is empty the API URL recorded by the CLI is used. When cfg.APIURL is set
// and the CLI reports a different origin, NewCLIClient refuses rather than
// send the `ss login` token to a host the session was not issued for.
func NewCLIClient(ctx context.Context, cfg *Config) (*Client, error) {
	var c Config
	if cfg != nil {
		c = *cfg
	}
	if c.APIKey != "" || c.TokenProvider != nil {
		return nil, errors.New("NewCLIClient: APIKey and TokenProvider must be empty")
	}
	p := CLICredentials()
	cliAPIURL, err := p.APIURL(ctx)
	if err != nil {
		return nil, err
	}
	if c.APIURL == "" {
		c.APIURL = cliAPIURL
	} else if cliAPIURL != "" && !sameAPIOrigin(c.APIURL, cliAPIURL) {
		return nil, fmt.Errorf("API URL %s does not match the `ss login` session for %s", c.APIURL, cliAPIURL)
	}
	c.TokenProvider = p.Token
	return NewClient(&c)
}

// NormalizeAPIURL lowercases the scheme and host, strips the scheme's
// default port (80 for http, 443 for https) and any trailing slash. It is
// not a general URL normalizer: it exists so callers (and other clients in
// this repo) can compare an explicitly configured API URL against the one
// an `ss login` session reports without false mismatches from case, a
// redundant default port, or a trailing slash. An unparsable URL is
// returned lowercased and otherwise unchanged.
func NormalizeAPIURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return strings.ToLower(strings.TrimSuffix(raw, "/"))
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host + strings.TrimSuffix(u.Path, "/")
}

// sameAPIOrigin reports whether a and b address the same API origin after
// NormalizeAPIURL.
func sameAPIOrigin(a, b string) bool {
	return NormalizeAPIURL(a) == NormalizeAPIURL(b)
}
