package danapp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// addPhoneReplayRecord stores replay data for the add-phone step.
type addPhoneReplayRecord struct {
	Cookies  []addPhoneReplayCookie
	LastStep addPhoneReplayLastStep
	HTTPEnv  addPhoneReplayHTTPEnv
}

// addPhoneReplayCookie stores a cookie for replay.
type addPhoneReplayCookie struct {
	Name     string
	Value    string
	Domain   string
	Path     string
	Secure   bool
	HTTPOnly bool
	SameSite string
}

// addPhoneReplayCookieBucket groups cookies by domain.
type addPhoneReplayCookieBucket struct {
	Domain  string
	Cookies []addPhoneReplayCookie
}

// addPhoneReplayLastStep records the last step for replay.
type addPhoneReplayLastStep struct {
	URL    string
	Status int
}

// addPhoneReplayHTTPEnv stores HTTP environment for replay.
type addPhoneReplayHTTPEnv struct {
	UserAgent string
	DeviceID  string
}

// addPhoneReplayOriginalResult stores the original result for replay comparison.
type addPhoneReplayOriginalResult struct {
	Status int
	Body   string
}

// addPhoneReplayDir returns the directory for add-phone replay files.
func addPhoneReplayDir(rootDir string) string {
	return filepath.Join(rootDir, "replay")
}

// newAddPhoneReplayRecord creates a new replay record.
func (s *RegisterSession) newAddPhoneReplayRecord() *addPhoneReplayRecord {
	return &addPhoneReplayRecord{
		Cookies: snapshotAddPhoneReplayCookies(s),
		HTTPEnv: addPhoneReplayHTTPEnv{
			UserAgent: s.http.UserAgent,
			DeviceID:  s.http.DeviceID,
		},
	}
}

// persistAddPhoneReplayRecord writes the replay record to disk.
func (s *RegisterSession) persistAddPhoneReplayRecord(record *addPhoneReplayRecord) error {
	dir := addPhoneReplayDir(s.app.cfg.RootDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create replay dir: %w", err)
	}

	filename := buildAddPhoneReplayFileName(s.email, s.currentStep)
	path := filepath.Join(dir, filename)

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal replay record: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// buildAddPhoneReplayFileName generates a filename for a replay record.
func buildAddPhoneReplayFileName(email, step string) string {
	safeEmail := sanitizeLogName(email)
	safeStep := sanitizeLogName(step)
	return fmt.Sprintf("%s_%s_%d.json", safeEmail, safeStep, time.Now().UnixMilli())
}

// snapshotAddPhoneReplayCookies captures current cookies for replay.
func snapshotAddPhoneReplayCookies(s *RegisterSession) []addPhoneReplayCookie {
	if s.http.client == nil || s.http.client.Jar == nil {
		return nil
	}

	var cookies []addPhoneReplayCookie
	targetURL := s.lastURL
	if targetURL == "" {
		targetURL = "https://chatgpt.com"
	}

	for _, c := range s.http.cookies(targetURL) {
		cookies = append(cookies, addPhoneReplayCookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HTTPOnly: c.HttpOnly,
			SameSite: cookieSameSiteString(c.SameSite),
		})
	}

	return cookies
}

// addPhoneReplayCookieURLs returns URLs for cookie replay.
func addPhoneReplayCookieURLs(cookies []addPhoneReplayCookie) []string {
	seen := make(map[string]struct{})
	var urls []string
	for _, c := range cookies {
		domain := strings.TrimPrefix(c.Domain, ".")
		if _, ok := seen[domain]; !ok {
			seen[domain] = struct{}{}
			urls = append(urls, "https://"+domain)
		}
	}
	return urls
}

// addPhoneContinueURLAndPageType determines the continue URL and page type.
func addPhoneContinueURLAndPageType(resp *HTTPResponse) (continueURL, pageType string) {
	if resp == nil {
		return "", ""
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(resp.Body), &data); err != nil {
		return "", ""
	}

	continueURL = mapString(data, "continue_url")
	pageType = mapString(data, "page_type")
	return
}

// isAddPhoneTarget checks if the current step targets the add-phone flow.
func isAddPhoneTarget(step string) bool {
	return step == "add_phone" || step == "verify_phone"
}

// isTransientReplayStatus checks if an HTTP status is transient for replay.
func isTransientReplayStatus(status int) bool {
	return status == 429 || status == 503 || status == 502 || status == 500
}

// cookieSameSiteString converts http.SameSite to string.
func cookieSameSiteString(sameSite http.SameSite) string {
	switch sameSite {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return ""
	}
}

// runHTTPStepWithReplay runs an HTTP step with replay capability.
func (s *RegisterSession) runHTTPStepWithReplay(step string, fn func() (*HTTPResponse, error)) (*HTTPResponse, error) {
	resp, err := fn()
	if err != nil {
		return nil, err
	}

	// Record the replay
	record := s.newAddPhoneReplayRecord()
	record.LastStep = addPhoneReplayLastStep{
		URL:    resp.URL,
		Status: resp.StatusCode,
	}

	// Persist if this is an add-phone step
	if isAddPhoneTarget(step) {
		s.persistAddPhoneReplayRecord(record)
	}

	return resp, nil
}

// runErrorStepWithReplay runs a step and handles replay on error.
func (s *RegisterSession) runErrorStepWithReplay(step string, fn func() (*HTTPResponse, error), maxReplay int) (*HTTPResponse, error) {
	for attempt := 0; attempt <= maxReplay; attempt++ {
		resp, err := s.runHTTPStepWithReplay(step, fn)
		if err != nil {
			if attempt < maxReplay && isTransientReplayStatus(0) {
				s.print("[Replay] %s retrying once", step)
				continue
			}
			return nil, err
		}

		if isTransientReplayStatus(resp.StatusCode) && attempt < maxReplay {
			s.print("[Replay] %s returned unexpected status %d, replay %d/%d", step, resp.StatusCode, attempt+1, maxReplay)
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("[Replay] %s retries exhausted", step)
}
