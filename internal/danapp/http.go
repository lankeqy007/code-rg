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
	"path/filepath"
	"strings"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/surf"
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
	proxy         string
	ctx           context.Context
	cookieJarPath string

	SessionBrowserProfile
}

// NewHTTPSession creates a new HTTP session with browser profile.
func NewHTTPSession(client *http.Client, profile SessionBrowserProfile, proxy string, rnd *mrand.Rand) (*HTTPSession, error) {
	_ = client
	_ = rnd

	surfClient, err := newSurfHTTPClient(proxy, 60*time.Second, false)
	if err != nil {
		return nil, err
	}

	s := &HTTPSession{
		client:                surfClient,
		proxy:                 proxy,
		ctx:                   context.Background(),
		SessionBrowserProfile: profile,
		baseHeaders:           make(map[string]string),
	}

	s.cookieJarPath = filepath.Join(os.TempDir(), fmt.Sprintf("dan-curl-cookies-%d.txt", time.Now().UnixNano()))

	if profile.UserAgent != "" {
		s.baseHeaders["User-Agent"] = profile.UserAgent
	}
	if profile.AcceptLanguage != "" {
		s.baseHeaders["Accept-Language"] = profile.AcceptLanguage
	}
	if profile.SecCHUA != "" {
		s.baseHeaders["Sec-CH-UA"] = profile.SecCHUA
	}
	if profile.SecCHUAMobile != "" {
		s.baseHeaders["Sec-CH-UA-Mobile"] = profile.SecCHUAMobile
	}
	if profile.SecCHUAPlatform != "" {
		s.baseHeaders["Sec-CH-UA-Platform"] = profile.SecCHUAPlatform
	}
	if profile.SecCHUAArch != "" {
		s.baseHeaders["Sec-CH-UA-Arch"] = profile.SecCHUAArch
	}
	if profile.SecCHUABitness != "" {
		s.baseHeaders["Sec-CH-UA-Bitness"] = profile.SecCHUABitness
	}
	if profile.ChromeFullVersion != "" {
		s.baseHeaders["Sec-CH-UA-Full-Version"] = profile.ChromeFullVersion
		s.baseHeaders["Sec-CH-UA-Full-Version-List"] = fmt.Sprintf(`"Not:A-Brand";v="99.0.0.0", "Google Chrome";v="%s", "Chromium";v="%s"`, profile.ChromeFullVersion, profile.ChromeFullVersion)
	}
	if profile.SecCHUAPlatformVersion != "" {
		s.baseHeaders["Sec-CH-UA-Platform-Version"] = profile.SecCHUAPlatformVersion
	}
	if profile.DeviceID != "" {
		s.baseHeaders["oai-device-id"] = profile.DeviceID
	}

	return s, nil
}

// homepageHeaders returns headers for a homepage request.
func (s *HTTPSession) homepageHeaders() map[string]string {
	h := s.pageHeaders("https://chatgpt.com/", "")
	h["Accept"] = s.HomepageAccept
	return h
}

// navigationHeaders returns headers for a navigation request.
func (s *HTTPSession) navigationHeaders(targetURL, referer string) map[string]string {
	h := map[string]string{
		"Accept":                      s.NavigationAccept,
		"Accept-Language":             s.AcceptLanguage,
		"Sec-CH-UA":                   s.SecCHUA,
		"Sec-CH-UA-Mobile":            s.SecCHUAMobile,
		"Sec-CH-UA-Platform":          s.SecCHUAPlatform,
		"Sec-CH-UA-Full-Version-List": s.secCHUAFullVersionList(),
		"Sec-Fetch-Dest":              "document",
		"Sec-Fetch-Mode":              "navigate",
		"Sec-Fetch-Site":              secFetchSiteValue(targetURL, referer),
		"Sec-Fetch-User":              firstNonEmpty(s.SecFetchUser, "?1"),
		"Upgrade-Insecure-Requests":   firstNonEmpty(s.UpgradeInsecureRequest, "1"),
		"User-Agent":                  s.UserAgent,
	}

	if referer != "" {
		h["Referer"] = referer
	}

	if s.CacheControl != "" {
		h["Cache-Control"] = s.CacheControl
	}
	if s.Priority != "" {
		h["Priority"] = s.Priority
	}
	if s.Pragma != "" {
		h["Pragma"] = s.Pragma
	}
	if s.SecCHUAArch != "" {
		h["Sec-CH-UA-Arch"] = s.SecCHUAArch
	}
	if s.SecCHUABitness != "" {
		h["Sec-CH-UA-Bitness"] = s.SecCHUABitness
	}
	if s.SecCHUAPlatformVersion != "" {
		h["Sec-CH-UA-Platform-Version"] = s.SecCHUAPlatformVersion
	}
	if s.ChromeFullVersion != "" {
		h["Sec-CH-UA-Full-Version"] = s.ChromeFullVersion
	}
	if s.DeviceID != "" {
		h["oai-device-id"] = s.DeviceID
	}

	return h
}

// pageHeaders returns headers for an API page request.
func (s *HTTPSession) pageHeaders(targetURL, referer string) map[string]string {
	return s.navigationHeaders(targetURL, referer)
}

// fetchHeaders returns browser-like headers for XHR/fetch JSON requests.
func (s *HTTPSession) fetchHeaders(targetURL, referer string) map[string]string {
	h := map[string]string{
		"Accept":                      "application/json, text/plain, */*",
		"Accept-Language":             s.AcceptLanguage,
		"Content-Type":                "application/json",
		"Sec-CH-UA":                   s.SecCHUA,
		"Sec-CH-UA-Mobile":            s.SecCHUAMobile,
		"Sec-CH-UA-Platform":          s.SecCHUAPlatform,
		"Sec-CH-UA-Full-Version-List": s.secCHUAFullVersionList(),
		"Sec-Fetch-Dest":              "empty",
		"Sec-Fetch-Mode":              "cors",
		"Sec-Fetch-Site":              secFetchSiteValue(targetURL, referer),
		"User-Agent":                  s.UserAgent,
	}

	if referer != "" {
		h["Referer"] = referer
	}

	targetOrigin := originFromURL(targetURL)
	if targetOrigin != "" {
		h["Origin"] = targetOrigin
	}
	if s.CacheControl != "" {
		h["Cache-Control"] = s.CacheControl
	}
	if s.Pragma != "" {
		h["Pragma"] = s.Pragma
	}
	if s.Priority != "" {
		h["Priority"] = s.Priority
	}
	if s.SecCHUAArch != "" {
		h["Sec-CH-UA-Arch"] = s.SecCHUAArch
	}
	if s.SecCHUABitness != "" {
		h["Sec-CH-UA-Bitness"] = s.SecCHUABitness
	}
	if s.SecCHUAPlatformVersion != "" {
		h["Sec-CH-UA-Platform-Version"] = s.SecCHUAPlatformVersion
	}
	if s.ChromeFullVersion != "" {
		h["Sec-CH-UA-Full-Version"] = s.ChromeFullVersion
	}
	if s.DeviceID != "" {
		h["oai-device-id"] = s.DeviceID
	}

	return h
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
	req, err := http.NewRequestWithContext(s.ctx, method, rawURL, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	for k, v := range s.cloneHeaders() {
		if v == "" || strings.Contains(k, ".") {
			continue
		}
		req.Header.Set(k, v)
	}

	// Apply request-specific headers
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

func newSurfHTTPClient(proxyURL string, timeout time.Duration, followRedirects bool) (*http.Client, error) {
	builder := surf.NewClient().
		Builder().
		Impersonate().
		Chrome().
		Session().
		Timeout(timeout)

	if proxyURL = strings.TrimSpace(proxyURL); proxyURL != "" {
		builder = builder.Proxy(g.String(proxyURL))
	}
	if !followRedirects {
		builder = builder.NotFollowRedirects()
	}

	result := builder.Build()
	if result.IsErr() {
		return nil, fmt.Errorf("create surf client: %w", result.Err())
	}

	client := result.Unwrap().Std()
	if client == nil {
		return nil, fmt.Errorf("surf std client is nil")
	}

	client.Timeout = timeout

	return client, nil
}

func (s *HTTPSession) secCHUAFullVersionList() string {
	if s.ChromeFullVersion == "" {
		return ""
	}
	return fmt.Sprintf(`"Not:A-Brand";v="99.0.0.0", "Google Chrome";v="%s", "Chromium";v="%s"`, s.ChromeFullVersion, s.ChromeFullVersion)
}

// secFetchSiteValue determines the Sec-Fetch-Site header value.
func secFetchSiteValue(targetURL, referer string) string {
	targetHost := normalizedHostname(targetURL)
	if targetHost == "" {
		return "none"
	}

	refererHost := normalizedHostname(referer)
	if refererHost == "" {
		return "none"
	}
	if strings.EqualFold(targetHost, refererHost) {
		return "same-origin"
	}
	if sameSiteHost(targetURL, referer) {
		return "same-site"
	}
	return "cross-site"
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

func originFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
