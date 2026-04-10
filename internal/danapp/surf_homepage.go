package danapp

import (
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

// RegisterSession manages a single account registration flow.
type RegisterSession struct {
	app  *App
	http *HTTPSession
	rnd  *mrand.Rand

	tag        string
	accountTag string

	callbackURL string
	lastURL     string
	lastStatus  int

	accountIdx   int
	email        string
	password     string
	name         string
	birthdate    string
	currentStep  string
	pkceVerifier string

	detailLog   bool
	oauthTokens map[string]string

	lastRegisterPasswordSentinelToken string
	lastCreateAccountReplay           *addPhoneReplayOriginalResult
}

// runRegister executes the full registration flow.
func (s *RegisterSession) runRegister() (*TaskResult, error) {
	result := &TaskResult{
		Email:    s.email,
		Password: s.password,
	}

	defer func() {
		s.app.emitTask(TaskProgress{
			Index:  s.accountIdx,
			Email:  s.email,
			Step:   s.currentStep,
			Status: "completed",
		})
	}()

	// Step 1: Visit homepage
	s.currentStep = "visit_homepage"
	s.updateTask("visiting homepage")
	if err := s.visitHomepage(); err != nil {
		return nil, s.formatErrorWithResponse("visit homepage", err)
	}

	// Step 2: Register (start the signup flow)
	s.currentStep = "register"
	s.updateTask("registering")
	if err := s.registerWithReferer(); err != nil {
		return nil, s.formatErrorWithResponse("register", err)
	}

	// Step 3: Send OTP to email
	s.currentStep = "send_otp"
	s.updateTask("sending OTP")
	if err := s.sendOTP(); err != nil {
		return nil, s.formatErrorWithResponse("send OTP", err)
	}

	// Step 4: Wait for verification email and validate OTP
	s.currentStep = "validate_otp"
	s.updateTask("validating OTP")
	if err := s.waitForVerificationEmail(); err != nil {
		return nil, s.formatErrorWithResponse("validate OTP", err)
	}

	// Step 5: OAuth / Codex token fetch
	if s.app.cfg.EnableOAuth {
		s.currentStep = "oauth"
		s.updateTask("fetching OAuth token")

		shouldRestart := true
		for restartCount := 0; shouldRestart && restartCount < 3; restartCount++ {
			err := s.performUnifiedSignupOAuth()
			if err != nil {
				if shouldRestartWholeFlow(err) {
					s.print("[OAuth] Restarting whole flow (attempt %d/3)", restartCount+1)
					continue
				}
				s.print("[OAuth] Failed: %v", err)
				if s.app.cfg.OAuthRequired {
					return nil, fmt.Errorf("OAuth required but failed: %w", err)
				}
			} else {
				result.OAuthOK = true
			}
			shouldRestart = false
		}
	}

	// Step 6: Save tokens
	if result.OAuthOK {
		result.Tokens = cloneStringMap(s.oauthTokens)
		if len(result.Tokens) == 0 {
			return nil, fmt.Errorf("OAuth completed but no tokens were captured")
		}
		if err := s.app.saveCodexTokens(s.email, result.Tokens); err != nil {
			return nil, fmt.Errorf("save tokens: %w", err)
		}
	}

	s.print("[OK] registered successfully: %s", s.email)
	return result, nil
}

// visitHomepage visits the target homepage to establish session.
func (s *RegisterSession) visitHomepage() error {
	homepageURL := "https://chatgpt.com"

	headers := s.http.homepageHeaders()
	resp, err := s.http.Request("GET", homepageURL, nil, headers)
	if err != nil {
		return fmt.Errorf("homepage request failed: %w", err)
	}

	s.lastURL = resp.URL
	s.lastStatus = resp.StatusCode

	if resp.StatusCode != 200 {
		return fmt.Errorf("homepage request failed: %d %s", resp.StatusCode, truncate(resp.Body, 200))
	}

	return nil
}

// register starts the registration process.
func (s *RegisterSession) register() error {
	registerURL := "https://chatgpt.com/auth/login"

	headers := s.http.pageHeaders(registerURL, s.lastURL)
	resp, err := s.http.Request("GET", registerURL, nil, headers)
	if err != nil {
		return fmt.Errorf("register request: %w", err)
	}

	s.lastURL = resp.URL
	s.lastStatus = resp.StatusCode

	return nil
}

// registerWithReferer starts registration with a referer header.
func (s *RegisterSession) registerWithReferer() error {
	// Build sentinel token for registration
	sentinelToken, err := s.buildRegisterPasswordSentinelToken()
	if err != nil {
		s.print("[Sentinel] Token generation failed: %v", err)
	}
	s.lastRegisterPasswordSentinelToken = sentinelToken

	// Visit the signup page
	signupURL := "https://auth.openai.com/authorize"

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {s.app.cfg.OAuthClientID},
		"redirect_uri":          {s.app.cfg.OAuthRedirectURI},
		"scope":                 {"openid profile email offline_access"},
		"state":                 {newUUID()},
		"code_challenge":        {},
		"code_challenge_method": {"S256"},
	}

	verifier, challenge := generatePKCE()
	s.pkceVerifier = verifier
	params.Set("code_challenge", challenge)

	fullURL := signupURL + "?" + params.Encode()

	headers := s.http.navigationHeaders(fullURL, s.lastURL)
	resp, err := s.http.Request("GET", fullURL, nil, headers)
	if err != nil {
		return fmt.Errorf("authorize request error: %w", err)
	}

	s.lastURL = resp.URL
	s.lastStatus = resp.StatusCode

	// Extract CSRF token
	csrf, err := s.getCSRF(resp.Body)
	if err == nil {
		s.http.baseHeaders["register.csrf"] = csrf
	}

	return nil
}

// sendOTP sends an OTP verification code to the registered email.
func (s *RegisterSession) sendOTP() error {
	otpURL := "https://auth.openai.com/api/accounts/email-otp/send"

	payload := map[string]string{
		"email": s.email,
	}

	headers := s.oauthJSONHeaders()
	resp, err := s.http.JSONRequest("POST", otpURL, payload, headers)
	if err != nil {
		return fmt.Errorf("send OTP request error: %w", err)
	}

	s.lastURL = resp.URL
	s.lastStatus = resp.StatusCode

	if resp.StatusCode != 200 {
		return fmt.Errorf("send OTP returned %d", resp.StatusCode)
	}

	return nil
}

// requestOTPVersion2 requests OTP using the v2 API.
func (s *RegisterSession) requestOTPVersion2() error {
	otpURL := "https://auth.openai.com/api/accounts/email-otp/send"

	payload := map[string]string{
		"email": s.email,
	}

	headers := s.oauthJSONHeaders()
	resp, err := s.http.JSONRequest("POST", otpURL, payload, headers)
	if err != nil {
		return fmt.Errorf("request OTP v2 error: %w", err)
	}

	if resp.StatusCode == 403 {
		return fmt.Errorf("signup validate_otp retry returned 403")
	}

	s.lastURL = resp.URL
	s.lastStatus = resp.StatusCode

	return nil
}

// resendOTPVersion2 resends the OTP code via the v2 API.
func (s *RegisterSession) resendOTPVersion2() error {
	return s.requestOTPVersion2()
}

// resendOTPAndRestartWait resends OTP and restarts the wait loop.
func (s *RegisterSession) resendOTPAndRestartWait() error {
	return s.resendOTPVersion2()
}

// waitForVerificationEmail waits for the verification email and extracts the OTP.
func (s *RegisterSession) waitForVerificationEmail() error {
	maxRetries := s.app.cfg.EffectiveOTPRetryCount()
	interval := time.Duration(s.app.cfg.EffectiveOTPRetryIntervalSeconds()) * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		s.print("[OTP] Waiting... (%d/%d)", attempt, maxRetries)

		// Wait before checking
		s.app.sleepWithContext(s.app.ctx, interval)

		// Check mailbox for OTP
		otp, err := s.app.fetchMailboxOTP(s.email)
		if err != nil {
			s.print("[OTP] Mailbox snapshot error: %v", err)
			if attempt < maxRetries {
				s.resendOTPAndRestartWait()
			}
			continue
		}

		if otp == "" {
			if attempt < maxRetries {
				continue
			}
			return fmt.Errorf("[OTP] Timeout after %d retries (%ds interval)", maxRetries, int(interval.Seconds()))
		}

		// Validate the OTP
		s.print("[OTP] Code received, validating...")
		if err := s.validateOTP(otp); err != nil {
			return fmt.Errorf("validate OTP: %w", err)
		}

		return nil
	}

	return fmt.Errorf("[OTP] Timeout after %d retries (%ds interval)", maxRetries, int(interval.Seconds()))
}

// validateOTP submits the OTP code for verification.
func (s *RegisterSession) validateOTP(code string) error {
	validateURL := "https://auth.openai.com/api/accounts/email-otp/validate"

	payload := map[string]string{
		"email": s.email,
		"otp":   code,
	}

	headers := s.oauthJSONHeaders()
	resp, err := s.http.JSONRequest("POST", validateURL, payload, headers)
	if err != nil {
		return fmt.Errorf("validate OTP request error: %w", err)
	}

	s.lastURL = resp.URL
	s.lastStatus = resp.StatusCode

	if resp.StatusCode == 403 {
		return fmt.Errorf("signup validate_otp retry returned 403")
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("validate OTP returned %d", resp.StatusCode)
	}

	return nil
}

// performUnifiedSignupOAuth performs the unified signup + OAuth flow.
func (s *RegisterSession) performUnifiedSignupOAuth() error {
	s.print("[OAuth] Starting unified signup + Codex token flow...")

	// Step 1: Bootstrap OAuth session
	if err := s.bootstrapOAuthSession(); err != nil {
		return fmt.Errorf("bootstrap OAuth: %w", err)
	}

	// Step 2: Authorize
	if err := s.authorize(); err != nil {
		return fmt.Errorf("authorize: %w", err)
	}

	// Step 3: Exchange OAuth code for tokens
	if err := s.exchangeOAuthCode(); err != nil {
		return fmt.Errorf("exchange code: %w", err)
	}

	// Step 4: Complete OAuth account setup
	if err := s.completeOAuthAccountSetup(); err != nil {
		return fmt.Errorf("complete account setup: %w", err)
	}

	// Step 5: Finalize Codex OAuth flow
	if err := s.finalizeCodexOAuthFlow(); err != nil {
		return fmt.Errorf("finalize Codex OAuth: %w", err)
	}

	s.print("[OAuth] Codex token acquired")
	return nil
}

// bootstrapOAuthSession initializes the OAuth session.
func (s *RegisterSession) bootstrapOAuthSession() error {
	url := "https://auth.openai.com/oauth/authorize/bootstrap"

	headers := s.oauthJSONHeaders()
	resp, err := s.http.JSONRequest("POST", url, map[string]string{}, headers)
	if err != nil {
		return fmt.Errorf("bootstrap request error: %w", err)
	}

	s.lastURL = resp.URL
	s.lastStatus = resp.StatusCode

	return nil
}

// authorize performs the OAuth authorize step.
func (s *RegisterSession) authorize() error {
	url := "https://auth.openai.com/authorize/continue"

	headers := s.oauthJSONHeaders()
	resp, err := s.http.JSONRequest("POST", url, map[string]string{
		"email": s.email,
	}, headers)
	if err != nil {
		return fmt.Errorf("authorize request error: %w", err)
	}

	s.lastURL = resp.URL
	s.lastStatus = resp.StatusCode
	s.captureOAuthCallback(resp.URL)

	if resp.StatusCode == 403 {
		return fmt.Errorf("signup authorize/continue returned 403")
	}

	return nil
}

// postAuthorizeContinue continues after authorization.
func (s *RegisterSession) postAuthorizeContinue() error {
	url := "https://auth.openai.com/authorize/continue"

	headers := s.oauthJSONHeaders()
	resp, err := s.http.JSONRequest("POST", url, map[string]string{
		"continue_url": s.callbackURL,
	}, headers)
	if err != nil {
		return err
	}

	s.lastURL = resp.URL
	s.lastStatus = resp.StatusCode
	s.captureOAuthCallback(resp.URL)

	return nil
}

// exchangeOAuthCode exchanges the OAuth authorization code for tokens.
func (s *RegisterSession) exchangeOAuthCode() error {
	// Extract code from callback URL
	callbackURL := s.callbackURL
	if callbackURL == "" {
		callbackURL = s.lastURL
	}
	code := extractCodeFromURL(callbackURL, "code")
	if code == "" {
		return fmt.Errorf("no OAuth code in callback URL")
	}
	s.callbackURL = callbackURL

	tokenURL := "https://auth.openai.com/oauth/token"

	payload := map[string]string{
		"grant_type":   "authorization_code",
		"code":         code,
		"redirect_uri": s.app.cfg.OAuthRedirectURI,
		"client_id":    s.app.cfg.OAuthClientID,
	}
	if s.pkceVerifier != "" {
		payload["code_verifier"] = s.pkceVerifier
	}

	headers := s.oauthJSONHeaders()
	resp, err := s.http.JSONRequest("POST", tokenURL, payload, headers)
	if err != nil {
		return fmt.Errorf("exchange code error: %w", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("exchange code returned %d", resp.StatusCode)
	}

	// Parse tokens from response
	var tokenResp map[string]any
	if err := json.Unmarshal([]byte(resp.Body), &tokenResp); err != nil {
		return fmt.Errorf("parse token response: %w", err)
	}

	s.mergeOAuthTokens(map[string]string{
		"access_token":  mapString(tokenResp, "access_token"),
		"refresh_token": mapString(tokenResp, "refresh_token"),
		"id_token":      mapString(tokenResp, "id_token"),
		"token_type":    mapString(tokenResp, "token_type"),
		"scope":         mapString(tokenResp, "scope"),
		"expires_in":    mapString(tokenResp, "expires_in"),
	})

	return nil
}

// completeOAuthAccountSetup completes the account setup after OAuth.
func (s *RegisterSession) completeOAuthAccountSetup() error {
	// Select workspace/org
	if err := s.oauthSubmitWorkspaceAndOrg(); err != nil {
		return fmt.Errorf("submit workspace/org: %w", err)
	}

	return nil
}

// oauthSubmitWorkspaceAndOrg submits workspace and organization selection.
func (s *RegisterSession) oauthSubmitWorkspaceAndOrg() error {
	url := "https://auth.openai.com/api/accounts/workspace/select"

	headers := s.oauthJSONHeaders()
	resp, err := s.http.JSONRequest("POST", url, map[string]string{}, headers)
	if err != nil {
		return err
	}

	s.lastURL = resp.URL
	s.lastStatus = resp.StatusCode
	return nil
}

// oauthFollowForCode follows OAuth redirects to extract the authorization code.
func (s *RegisterSession) oauthFollowForCode(startURL string) (string, error) {
	headers := s.http.navigationHeaders(startURL, s.lastURL)
	resp, err := s.http.Request("GET", startURL, nil, headers)
	if err != nil {
		return "", err
	}

	// Check if the response URL contains the code
	code := extractCodeFromURL(resp.URL, "code")
	if code != "" {
		s.callbackURL = resp.URL
		return code, nil
	}

	return "", fmt.Errorf("no callback URL found")
}

// finalizeCodexOAuthFlow finalizes the Codex-specific OAuth flow.
func (s *RegisterSession) finalizeCodexOAuthFlow() error {
	// Navigate to /sign-in-with-chatgpt/codex/consent
	consentURL := "https://chatgpt.com/sign-in-with-chatgpt/codex/consent"

	headers := s.http.navigationHeaders(consentURL, s.lastURL)
	resp, err := s.http.Request("GET", consentURL, nil, headers)
	if err != nil {
		return fmt.Errorf("codex consent error: %w", err)
	}

	s.lastURL = resp.URL
	s.lastStatus = resp.StatusCode
	s.captureOAuthCallback(resp.URL)

	if err := s.callbackAndGetSession(); err != nil {
		s.print("[Session] failed to fetch post-callback session: %v", err)
	}

	if len(s.oauthTokens) == 0 {
		return fmt.Errorf("OAuth flow completed but no tokens were captured")
	}

	return nil
}

// createAccount creates a new account with the given credentials.
func (s *RegisterSession) createAccount() error {
	createURL := "https://auth.openai.com/api/accounts/create_account"

	// Build sentinel token
	sentinelToken, err := s.buildCreateAccountSentinelToken()
	if err != nil {
		s.print("[Sentinel] create_account sentinel token unavailable: %v", err)
	}

	payload := map[string]any{
		"email":          s.email,
		"password":       s.password,
		"name":           s.name,
		"birthdate":      s.birthdate,
		"sentinel_token": sentinelToken,
	}

	headers := s.oauthJSONHeaders()
	resp, err := s.http.JSONRequest("POST", createURL, payload, headers)
	if err != nil {
		return fmt.Errorf("create account error: %w", err)
	}

	s.lastURL = resp.URL
	s.lastStatus = resp.StatusCode

	if resp.StatusCode != 200 {
		return fmt.Errorf("create account returned %d", resp.StatusCode)
	}

	return nil
}

// signin signs in with the registered credentials.
func (s *RegisterSession) signin() error {
	signinURL := "https://auth.openai.com/api/accounts/login"

	payload := map[string]string{
		"email":    s.email,
		"password": s.password,
	}

	headers := s.oauthJSONHeaders()
	resp, err := s.http.JSONRequest("POST", signinURL, payload, headers)
	if err != nil {
		return fmt.Errorf("signin error: %w", err)
	}

	s.lastURL = resp.URL
	s.lastStatus = resp.StatusCode

	return nil
}

// getCSRF extracts a CSRF token from an HTML response.
func (s *RegisterSession) getCSRF(body string) (string, error) {
	// Look for CSRF token in the response body
	// Common patterns: <input name="csrf" value="...">
	// or meta tag: <meta name="csrf-token" content="...">
	start := strings.Index(body, `name="csrf"`)
	if start == -1 {
		start = strings.Index(body, `name="_csrf"`)
	}
	if start == -1 {
		return "", fmt.Errorf("csrf token missing")
	}

	// Extract value attribute
	valStart := strings.Index(body[start:], `value="`)
	if valStart == -1 {
		return "", fmt.Errorf("csrf token missing")
	}
	valStart += len(`value="`)
	valEnd := strings.Index(body[start+valStart:], `"`)
	if valEnd == -1 {
		return "", fmt.Errorf("csrf token missing")
	}

	return body[start+valStart : start+valStart+valEnd], nil
}

// hasCookie checks if a cookie exists for the given URL.
func (s *RegisterSession) hasCookie(rawURL, name string) bool {
	for _, c := range s.http.cookies(rawURL) {
		if c.Name == name {
			return true
		}
	}
	return false
}

// callbackAndGetSession fetches the session after the OAuth callback.
func (s *RegisterSession) callbackAndGetSession() error {
	if s.callbackURL == "" {
		s.print("[!] No callback URL, skipping session fetch.")
		return nil
	}

	sessionURL := "https://chatgpt.com/api/auth/session"

	headers := s.http.navigationHeaders(sessionURL, s.lastURL)
	resp, err := s.http.Request("GET", sessionURL, nil, headers)
	if err != nil {
		s.print("[Session] /api/auth/session request error: %v", err)
		return err
	}

	s.lastURL = resp.URL
	s.lastStatus = resp.StatusCode

	if resp.StatusCode == 200 {
		var sessionData map[string]any
		if err := json.Unmarshal([]byte(resp.Body), &sessionData); err == nil {
			accessToken := mapString(sessionData, "accessToken")
			accountID := mapString(sessionData, "chatgpt_account_id")
			s.print("[Session] accessToken acquired, account_id=%s", accountID)
			s.mergeOAuthTokens(map[string]string{
				"session_access_token": accessToken,
				"chatgpt_account_id":   accountID,
			})
		}
	}

	return nil
}

// oauthJSONHeaders builds browser-like JSON request headers for OAuth endpoints.
func (s *RegisterSession) oauthJSONHeaders() map[string]string {
	targetURL := s.lastURL
	if targetURL == "" {
		targetURL = "https://auth.openai.com/"
	}

	headers := s.http.navigationHeaders(targetURL, s.lastURL)
	headers["Accept"] = "application/json, text/plain, */*"
	headers["Content-Type"] = "application/json"
	headers["Origin"] = "https://auth.openai.com"

	if s.lastURL != "" {
		headers["Referer"] = s.lastURL
	}
	for k, v := range s.http.cloneHeaders() {
		if v == "" || strings.Contains(k, ".") {
			continue
		}
		headers[k] = v
	}
	for k, v := range makeTraceHeaders() {
		if _, exists := headers[k]; !exists {
			headers[k] = v
		}
	}
	if s.http.DeviceID != "" {
		headers["oai-device-id"] = s.http.DeviceID
	}
	if csrf := s.http.baseHeaders["register.csrf"]; csrf != "" {
		headers["x-csrf-token"] = csrf
	}

	return headers
}

// captureOAuthCallback records a callback URL containing an OAuth code.
func (s *RegisterSession) captureOAuthCallback(rawURL string) {
	if extractCodeFromURL(rawURL, "code") != "" {
		s.callbackURL = rawURL
	}
}

// mergeOAuthTokens merges non-empty OAuth/session tokens into the session cache.
func (s *RegisterSession) mergeOAuthTokens(tokens map[string]string) {
	if s.oauthTokens == nil {
		s.oauthTokens = make(map[string]string)
	}
	for k, v := range tokens {
		if strings.TrimSpace(v) == "" {
			continue
		}
		s.oauthTokens[k] = v
	}
}

// cloneStringMap clones a map[string]string.
func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}

	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// decodeOAuthSessionCookie decodes the OAuth session cookie.
func (s *RegisterSession) decodeOAuthSessionCookie() (map[string]any, error) {
	cookies := s.http.cookies(s.lastURL)
	for _, c := range cookies {
		if c.Name == "session" || strings.Contains(c.Name, "oauth") {
			return decodeJWTPayload(c.Value)
		}
	}
	return nil, fmt.Errorf("no OAuth session cookie found")
}

// prepareUnifiedSignupPasswordPage prepares the password page for unified signup.
func (s *RegisterSession) prepareUnifiedSignupPasswordPage() error {
	passwordURL := "https://auth.openai.com/create-account/password"

	headers := s.http.pageHeaders(passwordURL, s.lastURL)
	resp, err := s.http.Request("GET", passwordURL, nil, headers)
	if err != nil {
		return err
	}

	s.lastURL = resp.URL
	s.lastStatus = resp.StatusCode

	return nil
}

// shouldRestartWholeFlow checks if the error warrants a full flow restart.
func shouldRestartWholeFlow(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*wholeFlowRestartError)
	return ok
}

// newWholeFlowRestartError creates a wholeFlowRestartError.
func newWholeFlowRestartError(reason string) *wholeFlowRestartError {
	return &wholeFlowRestartError{reason: reason}
}

// shouldSuppressRegisterSubmitNoise determines if register submit noise should be suppressed.
func shouldSuppressRegisterSubmitNoise(status int) bool {
	return status == 409 || status == 422
}

// snapshotSessionBrowserProfile captures the current browser profile.
func snapshotSessionBrowserProfile(s *RegisterSession) SessionBrowserProfile {
	return s.http.SessionBrowserProfile
}

// print prints a formatted message with the session tag.
func (s *RegisterSession) print(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s\n", s.tag, msg)
}

// updateTask sends a task progress update.
func (s *RegisterSession) updateTask(step string) {
	s.app.emitTask(TaskProgress{
		Index:  s.accountIdx,
		Email:  s.email,
		Step:   step,
		Status: "in_progress",
	})
}

// logPrefix returns the log prefix for this session.
func (s *RegisterSession) logPrefix() string {
	return fmt.Sprintf("%s[%s] ", s.tag, s.currentStep)
}

// logPath returns the log file path for this session.
func (s *RegisterSession) logPath() string {
	dir := runtimeLogDir(s.app.cfg.RootDir)
	return filepath.Join(dir, fmt.Sprintf("%s_%s.log", sanitizeLogName(s.email), s.accountTag))
}

// runtimeLogsEnabled checks if runtime logs are enabled.
func (s *RegisterSession) runtimeLogsEnabled() bool {
	return s.app.cfg.RuntimeLogs
}

// formatErrorWithResponse formats an error with HTTP response context.
func (s *RegisterSession) formatErrorWithResponse(step string, err error) error {
	if s.lastStatus > 0 {
		return fmt.Errorf("%s failed: %d %s: %w", step, s.lastStatus, truncate(s.lastURL, 100), err)
	}
	return fmt.Errorf("%s failed: %w", step, err)
}
