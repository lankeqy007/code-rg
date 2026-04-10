package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var version = "dev"

type webConfig struct {
	WebToken              string   `json:"web_token"`
	Port                  int      `json:"port"`
	CPABaseURL            string   `json:"cpa_base_url"`
	CPAToken              string   `json:"cpa_token"`
	MailAPIURL            string   `json:"mail_api_url"`
	MailAPIKey            string   `json:"mail_api_key"`
	DefaultProxy          string   `json:"default_proxy"`
	UseRegistrationProxy  bool     `json:"use_registration_proxy"`
	ManualDefaultThreads  int      `json:"manual_default_threads"`
	ManualRegisterRetries int      `json:"manual_register_retries"`
	RuntimeLogs           bool     `json:"runtime_logs"`
	Domains               []string `json:"domains"`
	AdminEmail            string   `json:"admin_email"`
	AdminPass             string   `json:"admin_pass"`
	EmailDomain           string   `json:"email_domain"`
	AutoStart             *bool    `json:"auto_start"`
}

type runtimeState struct {
	mu      sync.Mutex
	started time.Time
	lines   []string
}

type runnerState struct {
	mu         sync.Mutex
	cmd        *exec.Cmd
	running    bool
	startedAt  time.Time
	lastExit   string
	lastError  string
	lastArgs   []string
	lastPID    int
	lastStopAt time.Time
}

type server struct {
	root              string
	cfgPath           string
	runtimeConfigPath string
	cfg               webConfig
	state             *runtimeState
	runner            *runnerState
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
	if cfg.ManualDefaultThreads <= 0 {
		cfg.ManualDefaultThreads = 20
	}

	state := &runtimeState{started: time.Now()}
	srv := &server{
		root:    root,
		cfgPath: cfgPath,
		cfg:     cfg,
		state:   state,
		runner:  &runnerState{},
	}

	logf(state, "dan-web starting")
	logf(state, "root=%s", root)
	logf(state, "web_config=%s", cfgPath)

	runtimeConfigPath, err := syncRuntimeConfig(root, cfg)
	if err != nil {
		logf(state, "config sync failed: %v", err)
	} else {
		srv.runtimeConfigPath = runtimeConfigPath
		logf(state, "runtime config synced: %s", runtimeConfigPath)
	}

	if _, err := os.Stat(filepath.Join(root, "dan")); err == nil {
		logf(state, "detected sidecar binary: %s", filepath.Join(root, "dan"))
	}

	srv.maybeAutoStart()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "dan-web is running")
	})
	mux.HandleFunc("/api/status", authMiddleware(cfg.WebToken, srv.handleStatus))
	mux.HandleFunc("/api/start", authMiddleware(cfg.WebToken, srv.handleStart))
	mux.HandleFunc("/api/stop", authMiddleware(cfg.WebToken, srv.handleStop))

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)
	logf(state, "listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"state": map[string]any{
			"service":       "dan-web",
			"version":       version,
			"running":       true,
			"started_at":    s.state.started.Format(time.RFC3339),
			"port":          s.cfg.Port,
			"display_log":   s.state.displayLog(),
			"config_path":   s.cfgPath,
			"runtime_path":  s.runtimeConfigPath,
			"runner_state":  s.runner.snapshot(),
			"auto_starting": s.autoStartEnabled(),
		},
	})
}

func (s *server) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}

	threads := s.cfg.ManualDefaultThreads
	if v := strings.TrimSpace(r.URL.Query().Get("threads")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			threads = n
		}
	}

	if err := s.startDan(threads); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "started", "threads": threads})
}

func (s *server) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}

	if err := s.stopDan(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "stopped"})
}

func (s *server) autoStartEnabled() bool {
	if s.cfg.AutoStart == nil {
		return true
	}
	return *s.cfg.AutoStart
}

func (s *server) maybeAutoStart() {
	if !s.autoStartEnabled() {
		logf(s.state, "auto start disabled")
		return
	}
	if err := s.startDan(s.cfg.ManualDefaultThreads); err != nil {
		logf(s.state, "auto start skipped: %v", err)
	}
}

func (s *server) startDan(threads int) error {
	if threads <= 0 {
		threads = s.cfg.ManualDefaultThreads
	}
	if threads <= 0 {
		threads = 1
	}

	danPath := filepath.Join(s.root, "dan")
	if _, err := os.Stat(danPath); err != nil {
		return fmt.Errorf("dan binary not found: %s", danPath)
	}

	domains := effectiveDomains(s.cfg)
	if len(domains) == 0 {
		return fmt.Errorf("missing domains in web_config.json/config.json and unable to infer from mail_api_url")
	}

	args := []string{
		"--count", strconv.Itoa(threads),
		"--domains", strings.Join(domains, ","),
	}
	if s.cfg.RuntimeLogs {
		args = append(args, "--runtime-logs")
	}
	if s.cfg.UseRegistrationProxy && strings.TrimSpace(s.cfg.DefaultProxy) != "" {
		args = append(args, "--proxy", s.cfg.DefaultProxy)
	}
	if strings.TrimSpace(s.cfg.MailAPIURL) != "" {
		args = append(args, "--mail-api-url", s.cfg.MailAPIURL)
	}
	if strings.TrimSpace(s.cfg.MailAPIKey) != "" {
		args = append(args, "--mail-api-key", s.cfg.MailAPIKey)
	}
	if strings.TrimSpace(s.cfg.AdminEmail) != "" {
		args = append(args, "--admin-email", s.cfg.AdminEmail)
	}
	if strings.TrimSpace(s.cfg.AdminPass) != "" {
		args = append(args, "--admin-pass", s.cfg.AdminPass)
	}
	if strings.TrimSpace(s.cfg.EmailDomain) != "" {
		args = append(args, "--email-domain", s.cfg.EmailDomain)
	}

	s.runner.mu.Lock()
	defer s.runner.mu.Unlock()
	if s.runner.running && s.runner.cmd != nil && s.runner.cmd.Process != nil {
		return fmt.Errorf("dan is already running with pid=%d", s.runner.cmd.Process.Pid)
	}

	cmd := exec.Command(danPath, args...)
	cmd.Dir = s.root

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start dan: %w", err)
	}

	s.runner.cmd = cmd
	s.runner.running = true
	s.runner.startedAt = time.Now()
	s.runner.lastArgs = append([]string(nil), args...)
	s.runner.lastPID = cmd.Process.Pid
	s.runner.lastError = ""
	s.runner.lastExit = ""

	logf(s.state, "started dan pid=%d args=%s", cmd.Process.Pid, strings.Join(args, " "))

	go s.streamLogs("dan", stdout)
	go s.streamLogs("dan", stderr)
	go s.waitDan(cmd)

	return nil
}

func (s *server) stopDan() error {
	s.runner.mu.Lock()
	defer s.runner.mu.Unlock()

	if !s.runner.running || s.runner.cmd == nil || s.runner.cmd.Process == nil {
		return fmt.Errorf("dan is not running")
	}

	pid := s.runner.cmd.Process.Pid
	_ = s.runner.cmd.Process.Kill()
	s.runner.lastStopAt = time.Now()
	logf(s.state, "stop requested for dan pid=%d", pid)
	return nil
}

func (s *server) waitDan(cmd *exec.Cmd) {
	err := cmd.Wait()

	s.runner.mu.Lock()
	defer s.runner.mu.Unlock()

	s.runner.running = false
	if err != nil {
		s.runner.lastError = err.Error()
		s.runner.lastExit = fmt.Sprintf("exited with error at %s", time.Now().Format(time.RFC3339))
		logf(s.state, "dan exited with error: %v", err)
	} else {
		s.runner.lastError = ""
		s.runner.lastExit = fmt.Sprintf("exited normally at %s", time.Now().Format(time.RFC3339))
		logf(s.state, "dan exited normally")
	}
}

func (s *server) streamLogs(prefix string, rc interface{ Read([]byte) (int, error) }) {
	scanner := bufio.NewScanner(rc)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		logf(s.state, "[%s] %s", prefix, scanner.Text())
	}
}

func (r *runnerState) snapshot() map[string]any {
	r.mu.Lock()
	defer r.mu.Unlock()

	pid := 0
	if r.cmd != nil && r.cmd.Process != nil {
		pid = r.cmd.Process.Pid
	}

	return map[string]any{
		"running":      r.running,
		"pid":          pid,
		"started_at":   formatTime(r.startedAt),
		"last_exit":    r.lastExit,
		"last_error":   r.lastError,
		"last_args":    append([]string(nil), r.lastArgs...),
		"last_stop_at": formatTime(r.lastStopAt),
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
	if domains := effectiveDomains(wc); len(domains) > 0 {
		cfg["domains"] = domains
	}
	if wc.AdminEmail != "" {
		cfg["admin_email"] = wc.AdminEmail
	}
	if wc.AdminPass != "" {
		cfg["admin_pass"] = wc.AdminPass
	}
	if wc.EmailDomain != "" {
		cfg["email_domain"] = wc.EmailDomain
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
	if len(s.lines) > 400 {
		s.lines = s.lines[len(s.lines)-400:]
	}
}

func (s *runtimeState) displayLog() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, "\n")
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func effectiveDomains(cfg webConfig) []string {
	if len(cfg.Domains) > 0 {
		return normalizeDomains(cfg.Domains)
	}
	if cfg.EmailDomain != "" {
		return normalizeDomains([]string{cfg.EmailDomain})
	}
	if host := normalizedHostname(cfg.MailAPIURL); host != "" {
		return []string{host}
	}
	return nil
}

func normalizeDomains(domains []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, domain := range domains {
		domain = strings.TrimSpace(strings.ToLower(domain))
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	return out
}

func normalizedHostname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
