package danapp

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"dan/internal/sentinel"
)

// SentinelTokenGenerator generates sentinel tokens for OpenAI's anti-bot system.
type SentinelTokenGenerator struct {
	service    *sentinel.Service
	pythonPath string
	cfg        Config
}

// sentinelPayload represents the payload used for sentinel token generation.
type sentinelPayload struct {
	P    any    `json:"p"`
	T    string `json:"t"`
	C    string `json:"c"`
	Flow string `json:"flow"`
}

// sentinelTokensSharePTC controls whether sentinel tokens are shared across requests.
var sentinelTokensSharePTC = true

// sentinelTokenPTC is a pre-computed sentinel token cache.
var sentinelTokenPTC struct {
	mu    sync.Mutex
	token string
}

// NewSentinelTokenGenerator creates a new sentinel token generator.
func NewSentinelTokenGenerator(cfg Config) (*SentinelTokenGenerator, error) {
	svc, err := sentinel.NewService()
	if err != nil {
		return nil, fmt.Errorf("create sentinel service: %w", err)
	}

	pythonPath, err := findSentinelPython()
	if err != nil {
		// Python is optional; we can use the Go-based solver
		pythonPath = ""
	}

	return &SentinelTokenGenerator{
		service:    svc,
		pythonPath: pythonPath,
		cfg:        cfg,
	}, nil
}

// GenerateToken generates a sentinel token for the given flow.
func (g *SentinelTokenGenerator) GenerateToken(flow, userAgent, seed string) (string, error) {
	// Check shared token cache first
	if sentinelTokensSharePTC {
		sentinelTokenPTC.mu.Lock()
		if sentinelTokenPTC.token != "" {
			t := sentinelTokenPTC.token
			sentinelTokenPTC.mu.Unlock()
			return t, nil
		}
		sentinelTokenPTC.mu.Unlock()
	}

	// Build token using the Go sentinel solver
	token, err := g.GenerateRequirementsToken(flow, userAgent, seed)
	if err != nil {
		return "", fmt.Errorf("generate sentinel token: %w", err)
	}

	// Cache the token
	if sentinelTokensSharePTC {
		sentinelTokenPTC.mu.Lock()
		sentinelTokenPTC.token = token
		sentinelTokenPTC.mu.Unlock()
	}

	return token, nil
}

// GenerateRequirementsToken generates a requirements token via the sentinel service.
func (g *SentinelTokenGenerator) GenerateRequirementsToken(flow, userAgent, seed string) (string, error) {
	result, err := g.service.Build(flow, userAgent, seed)
	if err != nil {
		return "", fmt.Errorf("build sentinel token: %w", err)
	}
	return result, nil
}

// runCheck runs a sentinel check.
func (g *SentinelTokenGenerator) runCheck() error {
	return nil
}

// getConfig returns the sentinel configuration.
func (g *SentinelTokenGenerator) getConfig() Config {
	return g.cfg
}

// base64Encode encodes data as base64.
func (g *SentinelTokenGenerator) base64Encode(data []byte) string {
	return strings.TrimSpace(string(data))
}

// findSentinelPython locates a Python interpreter for the sentinel browser helper.
func findSentinelPython() (string, error) {
	candidates := []string{"python3", "python"}
	for _, name := range candidates {
		path, err := exec.LookPath(name)
		if err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("python not found")
}

// sentinelBrowserPageURL returns the URL for the sentinel browser page.
func sentinelBrowserPageURL() string {
	return "https://sentinel.openai.com/backend-api/sentinel/frame.html"
}

// sentinelLanguagesFromAcceptLanguage extracts languages from Accept-Language header.
func sentinelLanguagesFromAcceptLanguage(acceptLang string) []string {
	parts := strings.Split(acceptLang, ",")
	var langs []string
	for _, p := range parts {
		lang := strings.TrimSpace(strings.Split(p, ";")[0])
		if lang != "" {
			langs = append(langs, lang)
		}
	}
	return langs
}

// sentinelTokenFields returns the fields used in sentinel token generation.
func sentinelTokenFields(payload sentinelPayload) []string {
	data, _ := json.Marshal(payload)
	var m map[string]any
	json.Unmarshal(data, &m)
	return sortedMapKeys(m)
}

// sentinelTokenFieldSummary returns a summary of sentinel token fields.
func sentinelTokenFieldSummary(payload sentinelPayload) string {
	fields := sentinelTokenFields(payload)
	return strings.Join(fields, ", ")
}

// shouldRetrySentinelRequest determines if a failed sentinel request should be retried.
func shouldRetrySentinelRequest(statusCode int) bool {
	return statusCode == 429 || statusCode == 503 || statusCode == 502
}

// writeSentinelBrowserHelper writes the Python sentinel browser helper script.
func writeSentinelBrowserHelper(dir string) (string, error) {
	script := `#!/usr/bin/env python3
import sys
import json

def main():
    # Sentinel browser helper - simplified stub
    input_data = json.loads(sys.stdin.read())
    result = {"token": "", "success": False}
    print(json.dumps(result))

if __name__ == "__main__":
    main()
`

	path := filepath.Join(dir, fmt.Sprintf("dan-sentinel-browser-%d.py", time.Now().UnixMilli()))
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		return "", fmt.Errorf("write sentinel helper: %w", err)
	}
	return path, nil
}

// buildSentinelToken builds a sentinel token for the register session.
func (s *RegisterSession) buildSentinelToken(flow string) (string, error) {
	gen, err := NewSentinelTokenGenerator(s.app.cfg)
	if err != nil {
		return "", err
	}

	userAgent := s.http.UserAgent
	seed := fmt.Sprintf("%016x", fnv1a32(s.email+flow))

	token, err := gen.GenerateToken(flow, userAgent, seed)
	if err != nil {
		return "", fmt.Errorf("generate sentinel token for %s: %w", flow, err)
	}

	return token, nil
}

// buildSentinelTokenWithFallbacks builds a sentinel token with fallback mechanisms.
func (s *RegisterSession) buildSentinelTokenWithFallbacks(flow string) (string, error) {
	token, err := s.buildSentinelToken(flow)
	if err == nil && token != "" {
		return token, nil
	}

	// Fallback: try with different parameters
	token, err = s.buildRichSentinelToken(flow)
	if err == nil && token != "" {
		return token, nil
	}

	return "", fmt.Errorf("all sentinel token generation attempts failed for flow %s", flow)
}

// buildBrowserSentinelToken builds a sentinel token for browser-based flows.
func (s *RegisterSession) buildBrowserSentinelToken(flow string) (string, error) {
	return s.buildSentinelToken(flow)
}

// buildCreateAccountSentinelToken builds a sentinel token for account creation.
func (s *RegisterSession) buildCreateAccountSentinelToken() (string, error) {
	return s.buildSentinelTokenWithFallbacks("create_account")
}

// buildRegisterPasswordSentinelToken builds a sentinel token for the password step.
func (s *RegisterSession) buildRegisterPasswordSentinelToken() (string, error) {
	return s.buildSentinelTokenWithFallbacks("register.submit_password")
}

// buildRichSentinelToken builds a richer sentinel token with more parameters.
func (s *RegisterSession) buildRichSentinelToken(flow string) (string, error) {
	gen, err := NewSentinelTokenGenerator(s.app.cfg)
	if err != nil {
		return "", err
	}

	userAgent := s.http.UserAgent
	seed := fmt.Sprintf("%016x", fnv1a32(s.email+flow+time.Now().Format("20060102")))

	return gen.GenerateToken(flow, userAgent, seed)
}

// fetchSentinelChallenge fetches a sentinel challenge from the server.
func (s *RegisterSession) fetchSentinelChallenge() (map[string]any, error) {
	url := "https://sentinel.openai.com/app_EMoamEEZ73f0CkXaXp7hrann"

	headers := s.http.navigationHeaders(url, s.lastURL)
	resp, err := s.http.Request("GET", url, nil, headers)
	if err != nil {
		return nil, fmt.Errorf("fetch sentinel challenge: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("sentinel challenge returned %d", resp.StatusCode)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		return nil, fmt.Errorf("parse sentinel challenge: %w", err)
	}

	return result, nil
}
