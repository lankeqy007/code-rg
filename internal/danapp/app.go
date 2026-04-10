package danapp

import (
	"context"
	"fmt"
	mrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"dan/internal/sentinel"
)

// App is the main application struct.
type App struct {
	cfg Config

	rnd            *mrand.Rand
	cloudmailToken string
	tokenMu        sync.Mutex

	httpClient    *http.Client
	mailboxClient *http.Client
	mailboxMu     sync.Mutex

	registerMu sync.Mutex
	registerAt atomic.Int64
	taskUpdate chan TaskProgress

	ctx context.Context

	successLimiter *successLimiter
}

// TaskProgress tracks the progress of a single registration task.
type TaskProgress struct {
	Index  int
	Email  string
	Step   string
	Status string
}

// TaskResult holds the result of a completed registration.
type TaskResult struct {
	Email    string
	Password string
	OAuthOK  bool
	Tokens   map[string]string
	Pending  int
	Uploaded int
	Failed   int
}

// successLimiter tracks successful registrations for rate limiting.
type successLimiter struct {
	mu       sync.Mutex
	count    int
	filePath string
}

// wholeFlowRestartError indicates the entire registration flow should restart.
type wholeFlowRestartError struct {
	reason string
}

func (e *wholeFlowRestartError) Error() string {
	return e.reason
}

// ErrBatchStopped is returned when the batch is stopped by signal.
var ErrBatchStopped = fmt.Errorf("batch stopped")

var (
	batchStop       atomic.Bool
	fileMu          sync.Mutex
	tokenUploadMu   sync.Mutex
	randSeedCounter atomic.Uint64
)

// NewApp creates a new App instance.
func NewApp(cfg Config) (*App, error) {
	a := &App{
		cfg:        cfg,
		taskUpdate: make(chan TaskProgress, 100),
	}

	a.rnd = newRandom()

	// Resolve proxy
	proxyURL := resolveProxy(cfg)

	// Create HTTP client for general use
	a.httpClient = newPlainHTTPClient(proxyURL)

	// Create mailbox HTTP client
	a.mailboxClient = newPlainHTTPClient(proxyURL)

	// Init success limiter
	a.successLimiter = &successLimiter{
		filePath: filepath.Join(cfg.RootDir, "success_count.json"),
	}

	// Avoid unused import
	_ = sentinel.NewService

	return a, nil
}

// IsBatchStop returns whether the batch has been stopped.
func IsBatchStop() bool {
	return batchStop.Load()
}

// checkStopped checks if the batch is stopped and returns ErrBatchStopped if so.
func (a *App) checkStopped() error {
	if IsBatchStop() {
		return ErrBatchStopped
	}
	return nil
}

// sleepWithContext sleeps for the given duration, or until context is cancelled.
func (a *App) sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// requestContext returns a context for making requests, with timeout.
func (a *App) requestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(a.ctx, 60*time.Second)
}

// Run is the main entry point that orchestrates the registration flow.
func (a *App) Run(opts *CLIOpts) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.ctx = ctx

	// Load cloudmail domains
	domains, err := loadCloudmailDomains(a)
	if err != nil {
		return fmt.Errorf("load cloudmail domains: %w", err)
	}

	// Start pending token uploader if enabled
	if a.cfg.UploadTokens {
		a.startPendingTokenUploader(ctx)
	}

	// Register accounts
	var results []TaskResult
	for i := 0; i < a.cfg.Count; i++ {
		if err := a.checkStopped(); err != nil {
			break
		}

		// Rate limit: wait between registrations
		a.rateLimitBetweenRegistrations()

		result, err := a.registerOne(i, domains)
		if err != nil {
			if err == ErrBatchStopped {
				break
			}
			fmt.Fprintf(os.Stderr, "[!] Account %d failed: %v\n", i+1, err)
			continue
		}

		results = append(results, *result)

		// Persist completed account
		a.persistCompletedAccount(result)
	}

	if a.cfg.UploadTokens {
		if err := a.uploadAllTokensToCPA(); err != nil {
			fmt.Fprintf(os.Stderr, "[CPA] Final flush failed: %v\n", err)
		}
	}

	// Print summary
	a.printSummary(results)

	return nil
}

// rateLimitBetweenRegistrations enforces a delay between registration attempts.
func (a *App) rateLimitBetweenRegistrations() {
	now := time.Now().UnixMilli()
	last := a.registerAt.Load()
	delay := time.Duration(0)

	if last > 0 {
		elapsed := now - last
		minInterval := int64(2000) // 2 seconds minimum between registrations
		if elapsed < minInterval {
			delay = time.Duration(minInterval-elapsed) * time.Millisecond
		}
	}

	if delay > 0 {
		a.sleepWithContext(a.ctx, delay)
	}
	a.registerAt.Store(time.Now().UnixMilli())
}

// newRegisterSession creates a new RegisterSession for a single account registration.
func (a *App) newRegisterSession(idx int, email string, domains []string) *RegisterSession {
	rnd := newRandom()
	tag := formatThreadTag(idx)

	s := &RegisterSession{
		app:         a,
		rnd:         rnd,
		tag:         tag,
		accountTag:  fmt.Sprintf("%d", idx+1),
		email:       email,
		accountIdx:  idx,
		currentStep: "init",
	}

	// Create HTTP session with browser profile
	browserProfile := randomBrowserSessionProfile(rnd)
	s.http = NewHTTPSession(a.httpClient, browserProfile, a.cfg.Proxy, rnd)
	s.http.ctx = a.ctx

	return s
}

// registerOne registers a single account.
func (a *App) registerOne(idx int, domains []string) (*TaskResult, error) {
	// Create cloudmail email
	email, err := a.createCloudmailEmail(domains)
	if err != nil {
		return nil, fmt.Errorf("create email: %w", err)
	}

	password := generatePassword(a.rnd)
	name := randomName(a.rnd)
	birthdate := randomBirthdate(a.rnd)

	session := a.newRegisterSession(idx, email, domains)
	session.password = password
	session.name = name
	session.birthdate = birthdate

	// Run the registration flow
	result, err := session.runRegister()
	if err != nil {
		return nil, err
	}

	return result, nil
}

// registerOneLegacy registers using the legacy (non-OAuth) flow.
func (a *App) registerOneLegacy(idx int, domains []string) (*TaskResult, error) {
	email, err := a.createCloudmailEmail(domains)
	if err != nil {
		return nil, fmt.Errorf("create email: %w", err)
	}

	password := generatePassword(a.rnd)
	name := randomName(a.rnd)
	birthdate := randomBirthdate(a.rnd)

	session := a.newRegisterSession(idx, email, domains)
	session.password = password
	session.name = name
	session.birthdate = birthdate

	result := &TaskResult{
		Email:    email,
		Password: password,
	}

	// Visit homepage
	if err := session.visitHomepage(); err != nil {
		return nil, fmt.Errorf("visit homepage: %w", err)
	}

	// Register
	if err := session.register(); err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	// Send OTP
	if err := session.sendOTP(); err != nil {
		return nil, fmt.Errorf("send OTP: %w", err)
	}

	// Wait for verification email and validate OTP
	if err := session.waitForVerificationEmail(); err != nil {
		return nil, fmt.Errorf("validate OTP: %w", err)
	}

	// Fetch tokens if OAuth is enabled
	if a.cfg.EnableOAuth {
		if err := session.performUnifiedSignupOAuth(); err != nil {
			fmt.Fprintf(os.Stderr, "[!] OAuth failed: %v\n", err)
		} else {
			result.OAuthOK = true
		}
	}

	return result, nil
}

// persistCompletedAccount writes a completed account's data to disk.
func (a *App) persistCompletedAccount(result *TaskResult) {
	if a.cfg.OutputFile != "" {
		line := fmt.Sprintf("%s:%s", result.Email, result.Password)
		if result.OAuthOK {
			line += ":oauth_ok"
		}
		appendFile(a.cfg.OutputFile, line+"\n")
	}
}

// emitTask sends a task progress update.
func (a *App) emitTask(progress TaskProgress) {
	select {
	case a.taskUpdate <- progress:
	default:
	}
}

// printSummary prints the final summary of registration results.
func (a *App) printSummary(results []TaskResult) {
	success := 0
	failed := 0
	oauthOK := 0
	for _, r := range results {
		if r.OAuthOK {
			success++
			oauthOK++
		} else {
			failed++
		}
	}

	fmt.Println()
	fmt.Printf("  Total: %d | Success: %d | Failed: %d\n", len(results), success, failed)
	if a.cfg.EnableOAuth {
		fmt.Printf("  OAuth OK: %d\n", oauthOK)
	}
}

// createCloudmailEmail creates a temporary email using the mail API.
func (a *App) createCloudmailEmail(domains []string) (string, error) {
	a.mailboxMu.Lock()
	defer a.mailboxMu.Unlock()

	// Get or refresh cloudmail token
	if a.cloudmailToken == "" {
		token, err := cloudmailGetToken(a)
		if err != nil {
			return "", fmt.Errorf("get cloudmail token: %w", err)
		}
		a.cloudmailToken = token
	}

	// Pick a random domain
	domain := domains[0]
	if len(domains) > 1 {
		domain = domains[a.rnd.Intn(len(domains))]
	}

	local := randomCloudmailLocal(a.rnd)
	email := fmt.Sprintf("%s@%s", local, domain)

	// Create the mailbox
	if err := cloudmailCreateMailbox(a, email); err != nil {
		return "", fmt.Errorf("create mailbox: %w", err)
	}

	return email, nil
}

// cloudmailGetToken authenticates with the mail API and returns a token.
func cloudmailGetToken(a *App) (string, error) {
	return cloudmailPostJSON(a, "/tokens", map[string]string{
		"address":  a.cfg.AdminEmail,
		"password": a.cfg.AdminPass,
	})
}

// cloudmailCreateMailbox creates a mailbox via the mail API.
func cloudmailCreateMailbox(a *App, email string) error {
	_, err := cloudmailPostJSON(a, "/accounts", map[string]string{
		"address":  email,
		"password": a.cfg.AdminPass,
	})
	return err
}

// cloudmailPostJSON sends a JSON POST request to the mail API.
func cloudmailPostJSON(a *App, path string, payload map[string]string) (string, error) {
	// Simplified: would use surf HTTP client in production
	return "", fmt.Errorf("not implemented")
}

// loadCloudmailDomains loads available email domains from the mail API.
func loadCloudmailDomains(a *App) ([]string, error) {
	return []string{a.cfg.EmailDomain}, nil
}

// resolveProxy determines the proxy URL from config or environment.
func resolveProxy(cfg Config) string {
	if cfg.Proxy != "" {
		return cfg.Proxy
	}
	if cfg.UseEnvProxy {
		if v := os.Getenv("HTTPS_PROXY"); v != "" {
			return v
		}
		if v := os.Getenv("HTTP_PROXY"); v != "" {
			return v
		}
	}
	return ""
}

// saveCodexTokens saves Codex OAuth tokens to disk.
func (a *App) saveCodexTokens(email string, tokens map[string]string) error {
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()

	dir := filepath.Join(a.cfg.RootDir, a.cfg.TokenJSONDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create token dir: %w", err)
	}

	data := buildTokenJSONData(email, tokens)
	path := filepath.Join(dir, fmt.Sprintf("%016x.json", fnv1a32(email)))

	return os.WriteFile(path, []byte(data), 0644)
}
