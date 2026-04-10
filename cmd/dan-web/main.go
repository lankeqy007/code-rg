package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var version = "dev"

type webConfig struct {
	WebToken     string `json:"web_token"`
	Port         int    `json:"port"`
	CPABaseURL   string `json:"cpa_base_url"`
	CPAToken     string `json:"cpa_token"`
	MailAPIURL   string `json:"mail_api_url"`
	MailAPIKey   string `json:"mail_api_key"`
	DefaultProxy string `json:"default_proxy"`
}

type runtimeState struct {
	mu      sync.Mutex
	started time.Time
	lines   []string
}

func main() {
	root, err := detectProjectRoot()
	if err != nil {
		log.Fatalf("detect project root: %v", err)
	}

	cfgPath, cfg, err := loadWebConfig(root)
	if err != nil {
		log.Fatalf("load web config: %v", err)
	}
	if cfg.Port == 0 {
		cfg.Port = 25666
	}

	state := &runtimeState{started: time.Now()}
	logf(state, "dan-web starting")
	logf(state, "root=%s", root)
	logf(state, "web_config=%s", cfgPath)

	runtimeConfigPath, err := syncRuntimeConfig(root, cfg)
	if err != nil {
		logf(state, "config sync failed: %v", err)
	} else {
		logf(state, "runtime config synced: %s", runtimeConfigPath)
	}

	if _, err := os.Stat(filepath.Join(root, "dan")); err == nil {
		logf(state, "detected sidecar binary: %s", filepath.Join(root, "dan"))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "dan-web is running")
	})
	mux.HandleFunc("/api/status", authMiddleware(cfg.WebToken, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true,
			"state": map[string]any{
				"service":      "dan-web",
				"version":      version,
				"running":      true,
				"started_at":   state.started.Format(time.RFC3339),
				"port":         cfg.Port,
				"display_log":  state.displayLog(),
				"config_path":  cfgPath,
				"runtime_path": runtimeConfigPath,
			},
		})
	}))

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	logf(state, "listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

func detectProjectRoot() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("get executable: %w", err)
	}
	exeDir := filepath.Dir(exe)
	if looksLikeProjectRoot(exeDir) {
		return exeDir, nil
	}

	cwd, err := os.Getwd()
	if err == nil && looksLikeProjectRoot(cwd) {
		return cwd, nil
	}

	return exeDir, nil
}

func looksLikeProjectRoot(dir string) bool {
	for _, path := range []string{
		filepath.Join(dir, "web_config.json"),
		filepath.Join(dir, "config", "web_config.json"),
		filepath.Join(dir, "config.json"),
		filepath.Join(dir, "config", "config.json"),
	} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func loadWebConfig(root string) (string, webConfig, error) {
	candidates := []string{
		filepath.Join(root, "config", "web_config.json"),
		filepath.Join(root, "web_config.json"),
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg webConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return "", webConfig{}, fmt.Errorf("parse %s: %w", path, err)
		}
		return path, cfg, nil
	}
	return "", webConfig{}, fmt.Errorf("web_config.json not found under %s", root)
}

func syncRuntimeConfig(root string, wc webConfig) (string, error) {
	path := filepath.Join(root, "config.json")

	cfg := map[string]any{}
	if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, &cfg)
	}

	if v, ok := cfg["ak_file"]; !ok || stringValue(v) == "" {
		cfg["ak_file"] = "ak.txt"
	}
	if v, ok := cfg["rk_file"]; !ok || stringValue(v) == "" {
		cfg["rk_file"] = "rk.txt"
	}
	if v, ok := cfg["token_json_dir"]; !ok || stringValue(v) == "" {
		cfg["token_json_dir"] = "codex_tokens"
	}
	if v, ok := cfg["oauth_issuer"]; !ok || stringValue(v) == "" {
		cfg["oauth_issuer"] = "https://auth.openai.com"
	}
	if v, ok := cfg["oauth_client_id"]; !ok || stringValue(v) == "" {
		cfg["oauth_client_id"] = "app_EMoamEEZ73f0CkXaXp7hrann"
	}
	if v, ok := cfg["oauth_redirect_uri"]; !ok || stringValue(v) == "" {
		cfg["oauth_redirect_uri"] = "http://localhost:1455/auth/callback"
	}
	cfg["enable_oauth"] = true
	cfg["oauth_required"] = true

	if uploadURL := buildUploadAPIURL(wc.CPABaseURL); uploadURL != "" {
		cfg["upload_api_url"] = uploadURL
	}
	if wc.CPAToken != "" {
		cfg["upload_api_token"] = wc.CPAToken
	}
	if wc.MailAPIURL != "" {
		cfg["mail_api_url"] = wc.MailAPIURL
	}
	if wc.MailAPIKey != "" {
		cfg["mail_api_key"] = wc.MailAPIKey
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal runtime config: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return "", fmt.Errorf("write runtime config: %w", err)
	}
	return path, nil
}

func buildUploadAPIURL(base string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		return ""
	}
	base = strings.TrimRight(base, "/")
	if strings.Contains(base, "/v0/management/auth-files") {
		return base
	}
	return base + "/v0/management/auth-files"
}

func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func authMiddleware(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			next(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+token {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"ok":    false,
				"error": "unauthorized",
			})
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func logf(state *runtimeState, format string, args ...any) {
	line := fmt.Sprintf("%s %s", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
	log.Println(line)
	state.append(line)
}

func (s *runtimeState) append(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, line)
	if len(s.lines) > 200 {
		s.lines = s.lines[len(s.lines)-200:]
	}
}

func (s *runtimeState) displayLog() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, "\n")
}
