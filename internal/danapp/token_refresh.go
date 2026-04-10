package danapp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Token upload and refresh logic.

// startPendingTokenUploader starts a background goroutine to upload pending tokens.
func (a *App) startPendingTokenUploader(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.UploadPendingTokensDetailed()
			}
		}
	}()
}

// UploadPendingTokensDetailed uploads all pending tokens with detailed logging.
func (a *App) UploadPendingTokensDetailed() error {
	a.tokenMu.Lock()
	defer a.tokenMu.Unlock()

	paths, err := a.pendingTokenJSONPaths()
	if err != nil {
		return fmt.Errorf("list pending token JSON files: %w", err)
	}
	if len(paths) == 0 {
		return nil
	}

	uploaded, failed, pending := a.uploadPendingTokensLocked(paths)
	fmt.Printf("[CPA] Upload complete: uploaded=%d, failed=%d, pending=%d\n", uploaded, failed, pending)

	return nil
}

// uploadPendingTokensLocked uploads tokens while holding the lock.
func (a *App) uploadPendingTokensLocked(paths []string) (uploaded, failed, pending int) {
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			failed++
			continue
		}

		var tokenData map[string]any
		if err := json.Unmarshal(data, &tokenData); err != nil {
			failed++
			continue
		}

		email := mapString(tokenData, "email")
		if err := a.uploadTokenForEmail(email, tokenData); err != nil {
			fmt.Printf("[CPA] Upload failed for %s: %v\n", email, err)
			failed++
			continue
		}

		uploaded++

		// Remove the token file after successful upload
		os.Remove(path)
	}

	pending = len(paths) - uploaded - failed
	return
}

// uploadTokenForEmail uploads a token for a specific email.
func (a *App) uploadTokenForEmail(email string, tokenData map[string]any) error {
	return a.uploadTokenJSON(tokenData)
}

// uploadTokenJSON uploads token data as JSON to the CPA API.
func (a *App) uploadTokenJSON(data map[string]any) error {
	endpoint := normalizeUploadEndpoint(a.cfg.UploadAPIURL)
	if endpoint == "" {
		return fmt.Errorf("upload API URL not configured")
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal token data: %w", err)
	}

	headers := map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}
	if a.cfg.UploadAPIToken != "" {
		headers["Authorization"] = "Bearer " + a.cfg.UploadAPIToken
	}

	parentCtx := a.ctx
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	ctx, cancel := context.WithTimeout(parentCtx, 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("create upload request: %w", err)
	}
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("upload request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return fmt.Errorf("upload returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return nil
}

// uploadAllTokensToCPA uploads all tokens immediately.
func (a *App) uploadAllTokensToCPA() error {
	return a.UploadPendingTokensDetailed()
}

// pendingTokenJSONPaths returns paths of all pending token JSON files.
func (a *App) pendingTokenJSONPaths() ([]string, error) {
	dir := filepath.Join(a.cfg.RootDir, a.cfg.TokenJSONDir)
	if !dirExists(dir) {
		return nil, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var paths []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}

	return paths, nil
}

// uploadTokenPathLocked returns the upload token path (called with lock held).
func (a *App) uploadTokenPathLocked(email string) string {
	dir := filepath.Join(a.cfg.RootDir, a.cfg.TokenJSONDir)
	return filepath.Join(dir, fmt.Sprintf("%016x.json", fnv1a32(email)))
}

// buildTokenJSONData builds the JSON data for a token file.
func buildTokenJSONData(email string, tokens map[string]string) string {
	data := map[string]any{
		"email":     email,
		"tokens":    tokens,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	b, _ := json.MarshalIndent(data, "", "  ")
	return string(b)
}

// persist saves the success limiter state.
func (sl *successLimiter) persist() error {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	data, _ := json.Marshal(map[string]int{"count": sl.count})
	return os.WriteFile(sl.filePath, data, 0644)
}

// normalizeAPIRoot normalizes an API root URL.
func normalizeAPIRoot(url string) string {
	return strings.TrimRight(url, "/")
}

// normalizeUploadEndpoint normalizes the upload API endpoint.
func normalizeUploadEndpoint(url string) string {
	return normalizeAPIRoot(url)
}
