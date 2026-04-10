package danapp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// HTTPResponse wraps an HTTP response for logging.
type HTTPResponse struct {
	StatusCode int
	Headers    http.Header
	Body       string
	URL        string
}

// SessionBrowserProfile holds browser fingerprint data for a session.
type SessionBrowserProfile struct {
	UserAgent              string
	SecCHUA                string
	SecCHUAMobile          string
	SecCHUAPlatform        string
	SecCHUAArch            string
	SecCHUABitness         string
	ChromeFullVersion      string
	SecCHUAPlatformVersion string
	AcceptLanguage         string
	HomepageAccept         string
	NavigationAccept       string
	UpgradeInsecureRequest string
	SecFetchDest           string
	SecFetchMode           string
	SecFetchUser           string
	Priority               string
	CacheControl           string
	Pragma                 string
	NavigatorPlatform      string
	DeviceID               string
	AuthSessionLogID       string
}

// HTTPSession manages HTTP requests with browser-like headers and cookies.
type HTTPSession struct {
	client        *http.Client
	baseHeaders   map[string]string
	impersonate   string
	proxy         string
	ctx           context.Context
	cookieJarPath string

	SessionBrowserProfile
}

// NewHTTPSession creates a new HTTP session with browser profile.
func NewHTTPSession(client *http.Client, profile SessionBrowserProfile, proxy string, rnd *mrand.Rand) *HTTPSession {
	s := &HTTPSession{
		client:                client,
		proxy:                 proxy,
		ctx:                   context.Background(),
		SessionBrowserProfile: profile,
		baseHeaders:           make(map[string]string),
	}

	s.impersonate = "chrome"
	s.cookieJarPath = filepath.Join(os.TempDir(), fmt.Sprintf("dan-curl-cookies-%d.txt", time.Now().UnixNano()))
	return s
}

// homepageHeaders returns headers for a homepage request.
func (s *HTTPSession) homepageHeaders() map[string]string {
	h := s.navigationHeaders("", "")
	h["Accept"] = s.HomepageAccept
	h["Sec-Fetch-Dest"] = "document"
	h["Sec-Fetch-Mode"] = "navigate"
	h["Sec-Fetch-User"] = "?1"
	h["Upgrade-Insecure-Requests"] = "1"
	delete(h, "Referer")
	return h
}

// navigationHeaders returns headers for a navigation request.
func (s *HTTPSession) navigationHeaders(targetURL, referer string) map[string]string {
	h := map[string]string{
		"Accept":             s.NavigationAccept,
		"Accept-Language":    s.AcceptLanguage,
		"Cache-Control":      s.CacheControl,
		"Priority":           s.Priority,
		"Sec-CH-UA":          s.SecCHUA,
		"Sec-CH-UA-Mobile":   s.SecCHUAMobile,
		"Sec-CH-UA-Platform": s.SecCHUAPlatform,
		"Sec-Fetch-Dest":     "empty",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Site":     secFetchSiteValue(targetURL, referer),
	}

	if referer != "" {
		h["Referer"] = referer
	}

	if s.Pragma != "" {
		h["Pragma"] = s.Pragma
	}

	return h
}

// pageHeaders returns headers for an API page request.
func (s *HTTPSession) pageHeaders(targetURL, referer string) map[string]string {
	return s.navigationHeaders(targetURL, referer)
}

// Request makes an HTTP request with the given parameters.
func (s *HTTPSession) Request(method, rawURL string, body io.Reader, headers map[string]string) (*HTTPResponse, error) {
	return s.singleRequest(method, rawURL, body, headers)
}

// FormRequest makes a form POST request.
func (s *HTTPSession) FormRequest(rawURL string, data url.Values, headers map[string]string) (*HTTPResponse, error) {
	encoded := data.Encode()
	h := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	for k, v := range headers {
		h[k] = v
	}
	return s.singleRequest("POST", rawURL, strings.NewReader(encoded), h)
}

// JSONRequest makes a JSON request.
func (s *HTTPSession) JSONRequest(method, rawURL string, payload any, headers map[string]string) (*HTTPResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal JSON: %w", err)
	}

	h := map[string]string{
		"Content-Type": "application/json",
	}
	for k, v := range headers {
		h[k] = v
	}

	return s.singleRequest(method, rawURL, bytes.NewReader(body), h)
}

// singleRequest executes a single HTTP request.
func (s *HTTPSession) singleRequest(method, rawURL string, body io.Reader, headers map[string]string) (*HTTPResponse, error) {
	if shouldUseBrowserCurl(rawURL) {
		resp, err := s.curlRequest(method, rawURL, body, headers)
		if err == nil {
			return resp, nil
		}
		if !isMissingBinary(err) {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(s.ctx, method, rawURL, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Apply headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Set Host header
	if u, err := url.Parse(rawURL); err == nil {
		req.Host = u.Host
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return &HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       string(respBody),
		URL:        resp.Request.URL.String(),
	}, nil
}

func (s *HTTPSession) curlRequest(method, rawURL string, body io.Reader, headers map[string]string) (*HTTPResponse, error) {
	var bodyBytes []byte
	var err error
	if body != nil {
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
	}

	headerFile, err := os.CreateTemp("", "dan-curl-headers-*.txt")
	if err != nil {
		return nil, fmt.Errorf("create curl header file: %w", err)
	}
	headerPath := headerFile.Name()
	headerFile.Close()
	defer os.Remove(headerPath)

	bodyFile, err := os.CreateTemp("", "dan-curl-body-*.txt")
	if err != nil {
		return nil, fmt.Errorf("create curl body file: %w", err)
	}
	bodyPath := bodyFile.Name()
	bodyFile.Close()
	defer os.Remove(bodyPath)

	if _, err := os.Stat(s.cookieJarPath); err != nil {
		_ = os.WriteFile(s.cookieJarPath, []byte(""), 0600)
	}

	args := []string{
		"curl",
		"--max-time", "60",
		"--connect-timeout", "20",
		"-sS",
		"-L",
		"--http2",
		"--compressed",
		"-X", method,
		"-D", headerPath,
		"-o", bodyPath,
		"-w", "HTTP_CODE=%{http_code}\nFINAL_URL=%{url_effective}\n",
		"-b", s.cookieJarPath,
		"-c", s.cookieJarPath,
	}
	if s.proxy != "" {
		args = append(args, "--proxy", s.proxy)
	}
	if len(bodyBytes) > 0 {
		args = append(args, "--data-binary", "@-")
	}
	for _, pair := range orderedCurlHeaders(headers) {
		args = append(args, "-H", pair[0]+": "+pair[1])
	}
	args = append(args, rawURL)

	cmd := exec.CommandContext(s.ctx, "env", args...)
	if len(bodyBytes) > 0 {
		cmd.Stdin = bytes.NewReader(bodyBytes)
	}
	meta, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("browser-curl request failed: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err
	}

	respBody, _ := os.ReadFile(bodyPath)
	respHeaders, statusCode := parseCurlHeaderFile(headerPath)
	finalURL := parseCurlMetaLine(string(meta), "FINAL_URL")
	if finalURL == "" {
		finalURL = rawURL
	}
	if statusCode == 0 {
		if v := parseCurlMetaLine(string(meta), "HTTP_CODE"); v != "" {
			fmt.Sscanf(v, "%d", &statusCode)
		}
	}

	return &HTTPResponse{
		StatusCode: statusCode,
		Headers:    respHeaders,
		Body:       string(respBody),
		URL:        finalURL,
	}, nil
}

func orderedCurlHeaders(headers map[string]string) [][2]string {
	merged := map[string]string{
		"sec-ch-ua":                 `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`,
		"sec-ch-ua-mobile":          "?0",
		"sec-ch-ua-platform":        `"Linux"`,
		"upgrade-insecure-requests": "1",
		"user-agent":                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		"accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"accept-language":           "en-US,en;q=0.9",
		"accept-encoding":           "gzip, deflate, br, zstd",
		"sec-fetch-site":            "none",
		"sec-fetch-mode":            "navigate",
		"sec-fetch-user":            "?1",
		"sec-fetch-dest":            "document",
		"cache-control":             "max-age=0",
		"priority":                  "u=0, i",
	}
	for k, v := range headers {
		merged[strings.ToLower(k)] = v
	}

	order := []string{
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"upgrade-insecure-requests",
		"user-agent",
		"accept",
		"accept-language",
		"accept-encoding",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-user",
		"sec-fetch-dest",
		"cache-control",
		"priority",
		"content-type",
		"origin",
		"referer",
		"x-csrf-token",
		"authorization",
		"oai-device-id",
	}

	var out [][2]string
	seen := map[string]struct{}{}
	for _, key := range order {
		if v := strings.TrimSpace(merged[key]); v != "" {
			out = append(out, [2]string{http.CanonicalHeaderKey(key), v})
			seen[key] = struct{}{}
		}
	}
	for k, v := range merged {
		k = strings.ToLower(k)
		if _, ok := seen[k]; ok || strings.TrimSpace(v) == "" {
			continue
		}
		out = append(out, [2]string{http.CanonicalHeaderKey(k), v})
	}
	return out
}

func parseCurlHeaderFile(path string) (http.Header, int) {
	data, _ := os.ReadFile(path)
	blocks := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n\n")
	var last string
	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if strings.HasPrefix(block, "HTTP/") {
			last = block
		}
	}
	headers := make(http.Header)
	if last == "" {
		return headers, 0
	}

	lines := strings.Split(last, "\n")
	statusCode := 0
	if len(lines) > 0 {
		fmt.Sscanf(lines[0], "HTTP/%*s %d", &statusCode)
	}
	for _, line := range lines[1:] {
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			headers.Add(key, val)
		}
	}
	return headers, statusCode
}

func parseCurlMetaLine(meta, key string) string {
	for _, line := range strings.Split(meta, "\n") {
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimSpace(strings.TrimPrefix(line, key+"="))
		}
	}
	return ""
}

func shouldUseBrowserCurl(rawURL string) bool {
	host := normalizedHostname(rawURL)
	return strings.Contains(host, "chatgpt.com") || strings.Contains(host, "auth.openai.com")
}

func isMissingBinary(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "executable file not found")
}

// setCookie sets a cookie for the given URL.
func (s *HTTPSession) setCookie(rawURL, name, value string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	s.setHTTPCookie(u, &http.Cookie{
		Name:  name,
		Value: value,
	})
}

// setHTTPCookie sets an HTTP cookie on the cookie jar.
func (s *HTTPSession) setHTTPCookie(u *url.URL, cookie *http.Cookie) {
	if s.client != nil && s.client.Jar != nil {
		s.client.Jar.SetCookies(u, []*http.Cookie{cookie})
	}
}

// cookies returns all cookies for the given URL.
func (s *HTTPSession) cookies(rawURL string) []*http.Cookie {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	return s.client.Jar.Cookies(u)
}

// cloneHeaders returns a copy of the headers map.
func (s *HTTPSession) cloneHeaders() map[string]string {
	m := make(map[string]string, len(s.baseHeaders))
	for k, v := range s.baseHeaders {
		m[k] = v
	}
	return m
}

// newPlainHTTPClient creates a standard HTTP client, optionally with proxy.
func newPlainHTTPClient(proxyURL string) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if proxyURL != "" {
		if pu, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(pu)
		}
	}

	jar, _ := cookiejar.New(nil)

	return &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   60 * time.Second,
	}
}

// secFetchSiteValue determines the Sec-Fetch-Site header value.
func secFetchSiteValue(targetURL, referer string) string {
	if referer == "" {
		return "none"
	}
	return "same-origin"
}

// isRedirectStatus returns true if the status code indicates a redirect.
func isRedirectStatus(status int) bool {
	return status == 301 || status == 302 || status == 303 || status == 307 || status == 308
}

// isStatusExpected returns true if the status code is in the expected set.
func isStatusExpected(status int, expected ...int) bool {
	for _, s := range expected {
		if status == s {
			return true
		}
	}
	return false
}

// isLocalhostRedirect checks if a URL redirects to localhost.
func isLocalhostRedirect(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// mailboxHeaders returns headers for mailbox API requests.
func mailboxHeaders(token string) map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + token,
		"Accept":        "application/json",
	}
}

// homepageAcceptHeaders returns the Accept header for homepage requests.
func homepageAcceptHeaders() string {
	return "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
}

// navigationAcceptHeaders returns the Accept header for navigation requests.
func navigationAcceptHeaders() string {
	return "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
}

// acceptLanguages returns a list of Accept-Language values.
func acceptLanguages(rnd *mrand.Rand) []string {
	return []string{"en-US,en;q=0.9", "en-US,en;q=0.8", "en-US,en;q=0.7"}
}

// randomAcceptLanguage returns a random Accept-Language header value.
func randomAcceptLanguage(rnd *mrand.Rand) string {
	langs := acceptLanguages(rnd)
	return langs[rnd.Intn(len(langs))]
}

// priorityHeaderValues returns possible Priority header values.
func priorityHeaderValues() []string {
	return []string{"u=0, i", "u=1, i", "u=2, i"}
}

// cacheControlHeaderValues returns possible Cache-Control header values.
func cacheControlHeaderValues() []string {
	return []string{"max-age=0", "no-cache"}
}

// makeTraceHeaders creates distributed tracing headers.
func makeTraceHeaders() map[string]string {
	return map[string]string{
		"oai-device-id": newUUID(),
	}
}

// resolveURL resolves a possibly relative URL against a base.
func resolveURL(base, ref string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return baseURL.ResolveReference(refURL).String()
}
