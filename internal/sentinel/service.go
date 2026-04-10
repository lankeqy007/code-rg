package sentinel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// Service provides sentinel token generation.
type Service struct {
	seed string
}

// Session represents a sentinel session.
type Session struct {
	ID     string
	Flow   string
	Seed   string
	Rand   *mrand.Rand
}

// NewService creates a new sentinel Service.
func NewService() (*Service, error) {
	return &Service{
		seed: randomHex(16),
	}, nil
}

// Build generates a sentinel token for the given flow.
func (s *Service) Build(flow, userAgent, seed string) (string, error) {
	if seed == "" {
		seed = s.seed
	}

	sdk := newSDK(flow, userAgent, seed)

	// Generate requirements token
	reqToken, err := sdk.RequirementsToken()
	if err != nil {
		return "", fmt.Errorf("requirements token: %w", err)
	}

	// Generate enforcement token
	enfToken, err := sdk.EnforcementToken(reqToken)
	if err != nil {
		return "", fmt.Errorf("enforcement token: %w", err)
	}

	// Solve turnstile if needed
	result, err := solveTurnstileDXWithSession(flow, userAgent, seed, enfToken)
	if err != nil {
		return "", fmt.Errorf("solve turnstile: %w", err)
	}

	return result, nil
}

// Do executes a sentinel session.
func (s *Session) Do() (string, error) {
	sdk := newSDK(s.Flow, "", s.Seed)

	reqToken, err := sdk.RequirementsToken()
	if err != nil {
		return "", err
	}

	enfToken, err := sdk.EnforcementToken(reqToken)
	if err != nil {
		return "", err
	}

	return enfToken, nil
}

// sdk wraps the sentinel SDK functionality.
type sdk struct {
	flow      string
	userAgent string
	seed      string
	dateStr   string
	config    fingerprintConfig
}

// newSDK creates a new SDK instance.
func newSDK(flow, userAgent, seed string) *sdk {
	now := time.Now()
	return &sdk{
		flow:      flow,
		userAgent: userAgent,
		seed:      seed,
		dateStr:   dateString(now),
		config:    newFingerprintConfig(),
	}
}

// dateString formats a time as the sentinel date string.
func dateString(t time.Time) string {
	return t.Format("Mon Jan 02 2006 15:04:05") + " GMT" + formatTimezoneOffset(t)
}

// formatTimezoneOffset formats the timezone offset.
func formatTimezoneOffset(t time.Time) string {
	_, offset := t.Zone()
	sign := "+"
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	hours := offset / 3600
	minutes := (offset % 3600) / 60
	return fmt.Sprintf("%s%02d%02d", sign, hours, minutes)
}

// RequirementsToken generates the requirements token.
func (s *sdk) RequirementsToken() (string, error) {
	probe := sentinelProbeDefaults()
	navProbe := s.navigatorProbe()
	docProbe := s.documentProbe()
	winProbe := s.windowProbe()

	payload := map[string]any{
		"version":       "1.0",
		"flow":          s.flow,
		"navigator":     navProbe,
		"document":      docProbe,
		"window":        winProbe,
		"date":          s.dateStr,
		"probe":         probe,
		"fingerprint":   s.config,
		"userAgent":     s.userAgent,
		"hardwareConcurrency": 8,
		"language":      "en-US",
		"languages":     []string{"en-US", "en"},
	}

	return mustB64JSON(payload), nil
}

// EnforcementToken generates the enforcement token.
func (s *sdk) EnforcementToken(requirementsToken string) (string, error) {
	payload := map[string]any{
		"requirements_token": requirementsToken,
		"flow":              s.flow,
		"timestamp":         time.Now().UnixMilli(),
		"seed":              s.seed,
	}

	return mustB64JSON(payload), nil
}

// solve runs the solver.
func (s *sdk) solve(challenge string) (string, error) {
	return solveTurnstileDXWithSession(s.flow, s.userAgent, s.seed, challenge)
}

// navigatorProbe returns navigator properties.
func (s *sdk) navigatorProbe() map[string]any {
	return map[string]any{
		"userAgent":     s.userAgent,
		"language":      "en-US",
		"languages":     []string{"en-US", "en"},
		"platform":      "Win32",
		"vendor":        "Google Inc.",
		"hardwareConcurrency": 8,
		"maxTouchPoints":   0,
		"webdriver":     false,
		"cookieEnabled": true,
		"onLine":        true,
	}
}

// documentProbe returns document properties.
func (s *sdk) documentProbe() map[string]any {
	return map[string]any{
		"charset":        "UTF-8",
		"compatMode":     "CSS1Compat",
		"contentType":    "text/html",
		"documentMode":   nil,
		"implementation": nil,
	}
}

// windowProbe returns window properties.
func (s *sdk) windowProbe() map[string]any {
	return map[string]any{
		"innerWidth":     1920,
		"innerHeight":    969,
		"outerWidth":     1920,
		"outerHeight":    1040,
		"screenX":        0,
		"screenY":        0,
		"pageXOffset":    0,
		"pageYOffset":    0,
		"devicePixelRatio": 1,
		"screen": map[string]any{
			"width":       1920,
			"height":      1080,
			"availWidth":  1920,
			"availHeight": 1040,
			"colorDepth":  24,
			"pixelDepth":  24,
		},
	}
}

// fingerprintConfig holds browser fingerprint configuration.
type fingerprintConfig map[string]any

// newFingerprintConfig creates a fingerprint config.
func newFingerprintConfig() fingerprintConfig {
	return fingerprintConfig{
		"architecture":    "x86",
		"bitness":         "64",
		"model":           "",
		"platformVersion": "15.0.0",
		"fullVersionList": []map[string]string{
			{"brand": "Not A(Brand", "version": "120.0.0.0"},
			{"brand": "Chromium", "version": "120.0.0.0"},
			{"brand": "Google Chrome", "version": "120.0.0.0"},
		},
	}
}

// mustB64JSON JSON-encodes and base64-encodes a value. Panics on error.
func mustB64JSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

// sentinelProbeDefaults returns default sentinel probe values.
func sentinelProbeDefaults() map[string]any {
	return map[string]any{
		"indexedDB":      true,
		"localStorage":   true,
		"sessionStorage": true,
		"openDatabase":   true,
		"webGL":          true,
		"canvas":         true,
		"webRTC":         true,
	}
}

// localizedTimezoneName returns the localized timezone name.
func localizedTimezoneName() string {
	return "Central European Standard Time"
}

// browserEntropyFallback returns a fallback entropy value.
func browserEntropyFallback() string {
	return randomHex(8)
}

// mixedFNV computes a mixed FNV hash.
func mixedFNV(data string) uint32 {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for _, c := range data {
		h ^= uint32(c)
		h *= prime32
	}
	return h
}

// appendOrderedKey appends an ordered key to a JSON builder.
func appendOrderedKey(b []byte, key string) []byte {
	b = append(b, '"')
	b = append(b, key...)
	b = append(b, '"')
	b = append(b, ':')
	return b
}

// keysOfMap returns sorted keys of a map.
func keysOfMap(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// withOrderedKeys creates a JSON byte slice with ordered keys.
func withOrderedKeys(m map[string]any) []byte {
	keys := keysOfMap(m)
	var b []byte
	b = append(b, '{')
	for i, k := range keys {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendOrderedKey(b, k)
		v, _ := json.Marshal(m[k])
		b = append(b, v...)
	}
	b = append(b, '}')
	return b
}

// regKey returns the registry key for a given index.
func regKey(idx int) string {
	return fmt.Sprintf("r%d", idx)
}

// objectKeys returns the keys of a JS-like object.
func objectKeys(m map[string]any) []string {
	return keysOfMap(m)
}

// jsJSONStringify mimics JSON.stringify for a value.
func jsJSONStringify(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(data)
}

// jsonString creates a JSON string.
func jsonString(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}

// jsonFloat formats a float for JSON.
func jsonFloat(f float64) string {
	if f == math.Trunc(f) {
		return fmt.Sprintf("%.0f", f)
	}
	return fmt.Sprintf("%g", f)
}

// toIntIndex converts a value to an int index.
func toIntIndex(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	}
	return 0, false
}

// stringSliceToAny converts []string to []any.
func stringSliceToAny(ss []string) []any {
	result := make([]any, len(ss))
	for i, s := range ss {
		result[i] = s
	}
	return result
}

// copyAnySlice creates a copy of []any.
func copyAnySlice(src []any) []any {
	dst := make([]any, len(src))
	copy(dst, src)
	return dst
}

// isInternalMetaKey checks if a key is an internal meta key.
func isInternalMetaKey(key string) bool {
	return strings.HasPrefix(key, "__") && strings.HasSuffix(key, "__")
}

// latin1Base64Encode encodes a Latin1 string as base64.
func latin1Base64Encode(s string) string {
	b := latin1StringToBytes(s)
	return base64.StdEncoding.EncodeToString(b)
}

// latin1Base64Decode decodes a base64 Latin1 string.
func latin1Base64Decode(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return bytesToLatin1Runes(b), nil
}

// latin1StringToBytes converts a Latin1 string to bytes.
func latin1StringToBytes(s string) []byte {
	b := make([]byte, len(s))
	for i := range s {
		b[i] = byte(s[i])
	}
	return b
}

// bytesToLatin1Runes converts bytes to a Latin1 string.
func bytesToLatin1Runes(b []byte) string {
	runes := make([]rune, len(b))
	for i, v := range b {
		runes[i] = rune(v)
	}
	return string(runes)
}

// maxInt returns the maximum of two ints.
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// splitScreenSum splits a screen dimension sum.
func splitScreenSum(total int) (int, int) {
	return total / 2, total - total/2
}

// truncateText truncates text to a maximum length.
func truncateText(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// xorString XORs two strings.
func xorString(a, b string) string {
	result := make([]byte, len(a))
	for i := range a {
		if i < len(b) {
			result[i] = a[i] ^ b[i]
		}
	}
	return string(result)
}

// perfNow returns a performance.now()-like value.
func perfNow() float64 {
	return float64(time.Now().UnixMilli() % 10000)
}
