package danapp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
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
	client      *http.Client
	baseHeaders map[string]string
	impersonate string
	proxy       string
	ctx         context.Context

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
