package danapp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

var sanitizeLogNameRe = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// newRandom creates a new pseudo-random generator seeded from current time.
func newRandom() *mrand.Rand {
	return mrand.New(mrand.NewSource(time.Now().UnixNano()))
}

// randomName generates a random full name.
func randomName(rnd *mrand.Rand) string {
	first := firstNames[rnd.Intn(len(firstNames))]
	last := lastNames[rnd.Intn(len(lastNames))]
	return first + " " + last
}

// randomBirthdate generates a random birthdate string.
func randomBirthdate(rnd *mrand.Rand) string {
	year := 1985 + rnd.Intn(15) // 1985-1999
	month := 1 + rnd.Intn(12)
	day := 1 + rnd.Intn(28)
	return fmt.Sprintf("%04d-%02d-%02d", year, month, day)
}

// generatePassword creates a random password.
func generatePassword(rnd *mrand.Rand) string {
	const (
		uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lowercase = "abcdefghijklmnopqrstuvwxyz"
		digits    = "0123456789"
		special   = "!@#$%^&*"
		all       = uppercase + lowercase + digits + special
	)

	length := 12 + rnd.Intn(5) // 12-16 chars
	b := make([]byte, length)
	for i := range b {
		b[i] = all[rnd.Intn(len(all))]
	}
	// Ensure at least one of each type
	b[0] = uppercase[rnd.Intn(len(uppercase))]
	b[1] = lowercase[rnd.Intn(len(lowercase))]
	b[2] = digits[rnd.Intn(len(digits))]
	b[3] = special[rnd.Intn(len(special))]

	// Shuffle
	for i := len(b) - 1; i > 0; i-- {
		j := rnd.Intn(i + 1)
		b[i], b[j] = b[j], b[i]
	}

	return string(b)
}

// randomBrowserSessionProfile creates a random browser fingerprint.
func randomBrowserSessionProfile(rnd *mrand.Rand) SessionBrowserProfile {
	chromeVersion := 120 + rnd.Intn(10) // Chrome 120-129
	fullVersion := fmt.Sprintf("%d.0.%d.%d", chromeVersion, 5000+rnd.Intn(5000), rnd.Intn(200))

	platform := "Windows"
	platformVersion := "15.0.0"
	if rnd.Intn(2) == 0 {
		platform = "macOS"
		platformVersion = "14.0.0"
	}

	return SessionBrowserProfile{
		UserAgent:              fmt.Sprintf("Mozilla/5.0 (%s; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%s Safari/537.36", platform, fullVersion),
		SecCHUA:                buildSecCHUAFullVersionList(chromeVersion, fullVersion),
		SecCHUAMobile:          "?0",
		SecCHUAPlatform:        fmt.Sprintf(`"%s"`, platform),
		SecCHUAArch:            `"x86"`,
		SecCHUABitness:         `"64"`,
		ChromeFullVersion:      fullVersion,
		SecCHUAPlatformVersion: fmt.Sprintf(`"%s"`, platformVersion),
		AcceptLanguage:         randomAcceptLanguage(rnd),
		HomepageAccept:         homepageAcceptHeaders(),
		NavigationAccept:       navigationAcceptHeaders(),
		UpgradeInsecureRequest: "1",
		SecFetchDest:           "document",
		SecFetchMode:           "navigate",
		SecFetchUser:           "?1",
		Priority:               "u=0, i",
		CacheControl:           "max-age=0",
		Pragma:                 "",
		NavigatorPlatform:      "Win32",
		DeviceID:               newUUID(),
		AuthSessionLogID:       newUUID(),
	}
}

// buildSecCHUAFullVersionList builds the Sec-CH-UA-Full-Version-List header.
func buildSecCHUAFullVersionList(chromeVersion int, fullVersion string) string {
	return fmt.Sprintf(`"Not A(Brand";v="%d.0.0.0", "Chromium";v="%d.0.0.0", "Google Chrome";v="%d.0.0.0"`, chromeVersion, chromeVersion, chromeVersion)
}

// newUUID generates a random UUID v4.
func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// generatePKCE generates a PKCE code_verifier and code_challenge.
func generatePKCE() (verifier, challenge string) {
	b := make([]byte, 32)
	rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

// randomCloudmailLocal generates a random email local part.
func randomCloudmailLocal(rnd *mrand.Rand) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8+rnd.Intn(8))
	for i := range b {
		b[i] = chars[rnd.Intn(len(chars))]
	}
	return string(b)
}

// randomDelay sleeps for a random duration.
func randomDelay(rnd *mrand.Rand, min, max time.Duration) {
	d := min + time.Duration(rnd.Int63n(int64(max-min)))
	time.Sleep(d)
}

// fnv1a32 computes the FNV-1a 32-bit hash.
func fnv1a32(s string) uint32 {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for _, c := range s {
		h ^= uint32(c)
		h *= prime32
	}
	return h
}

// decodeJSON decodes JSON bytes into a map.
func decodeJSON(data []byte) (map[string]any, error) {
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	return result, nil
}

// decodeJWTPayload decodes the payload part of a JWT token.
func decodeJWTPayload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	return decodeJSON(payload)
}

// extractVerificationCode extracts a verification code from email text.
func extractVerificationCode(body string) (string, error) {
	re := regexp.MustCompile(`\b\d{6}\b`)
	match := re.FindString(body)
	if match == "" {
		return "", fmt.Errorf("no verification code found")
	}
	return match, nil
}

// extractCodeFromURL extracts a verification code from a URL parameter.
func extractCodeFromURL(rawURL, param string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Query().Get(param)
}

// verificationCodeRegex returns the regex for verification codes.
func verificationCodeRegex() *regexp.Regexp {
	return regexp.MustCompile(`\d{6}`)
}

// fileExists checks if a file exists.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// dirExists checks if a directory exists.
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// appendFile appends a line to a file.
func appendFile(path, line string) {
	fileMu.Lock()
	defer fileMu.Unlock()

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(line)
}

// appendLine appends a line to a file (alias for appendFile).
func appendLine(path, line string) {
	appendFile(path, line)
}

// valueOrNone returns the string value or "<none>".
func valueOrNone(v string) string {
	if v == "" {
		return "<none>"
	}
	return v
}

// boolText returns "yes" or "no" for a boolean.
func boolText(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// yesNo returns "yes" or "no" for a boolean.
func yesNo(b bool) string {
	return boolText(b)
}

// firstNonEmpty returns the first non-empty string from the arguments.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// hasAnyNonEmptyString returns true if any of the strings are non-empty.
func hasAnyNonEmptyString(vals ...string) bool {
	for _, v := range vals {
		if v != "" {
			return true
		}
	}
	return false
}

// dedupeStrings removes duplicate strings from a slice.
func dedupeStrings(ss []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(ss))
	for _, s := range ss {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}

// sortedMapKeys returns sorted keys of a map[string]any.
func sortedMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// cloneMap clones a map[string]any.
func cloneMap(m map[string]any) map[string]any {
	result := make(map[string]any, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

// cloneAnyMap clones a map[string]any (alias).
func cloneAnyMap(m map[string]any) map[string]any {
	return cloneMap(m)
}

// mapString extracts a string value from a map.
func mapString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}

// mapInt extracts an int value from a map.
func mapInt(m map[string]any, key string) int {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	}
	return 0
}

// mapBool extracts a bool value from a map.
func mapBool(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok {
		return false
	}
	b, ok := v.(bool)
	return b
}

// mapAny extracts any value from a map.
func mapAny(m map[string]any, key string) any {
	return m[key]
}

// mapStringAny extracts a string from map[string]any.
func mapStringAny(m map[string]any, key string) string {
	return mapString(m, key)
}

// mapIntAny extracts an int from map[string]any.
func mapIntAny(m map[string]any, key string) int {
	return mapInt(m, key)
}

// parseBool parses a string as boolean.
func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "1" || s == "yes"
}

// envBool reads a boolean from an environment variable.
func envBool(key string) bool {
	return parseBool(os.Getenv(key))
}

// absInt returns the absolute value of an int.
func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// truncate truncates a string to n characters.
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	runes := []rune(s)
	return string(runes[:n])
}

// fixedNowString returns the current time in a fixed format.
func fixedNowString() string {
	return time.Now().Format("2006-01-02T15:04:05-07:00")
}

// stripUTF8BOM removes UTF-8 BOM from data.
func stripUTF8BOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}

// runtimeLogDir returns the directory used for runtime log files.
func runtimeLogDir(rootDir string) string {
	return filepath.Join(rootDir, "runtime_logs")
}

// sanitizeLogName sanitizes a string for use as a filename.
func sanitizeLogName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	s = sanitizeLogNameRe.ReplaceAllString(s, "_")
	s = strings.Trim(s, "._-")
	if s == "" {
		return "unknown"
	}
	return s
}

// randomWildcardDomainLabel generates a random subdomain label.
func randomWildcardDomainLabel(rnd *mrand.Rand) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 6+rnd.Intn(6))
	for i := range b {
		b[i] = chars[rnd.Intn(len(chars))]
	}
	return string(b)
}

// normalizeDomains normalizes a list of domains.
func normalizeDomains(domains []string) []string {
	result := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.TrimSpace(strings.ToLower(d))
		if d != "" {
			result = append(result, d)
		}
	}
	return dedupeStrings(result)
}

// normalizedHostname returns the hostname portion of a URL, normalized.
func normalizedHostname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return strings.ToLower(u.Hostname())
}

// registrableHost returns the registrable domain from a hostname.
func registrableHost(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) > 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

// sameSiteHost checks if two URLs share the same registrable domain.
func sameSiteHost(url1, url2 string) bool {
	return registrableHost(normalizedHostname(url1)) == registrableHost(normalizedHostname(url2))
}

// mustParseHost parses a URL and returns its host.
func mustParseHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Host
}

// mustParsePath parses a URL and returns its path.
func mustParsePath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "/"
	}
	return u.Path
}

// anySliceToStrings converts []any to []string.
func anySliceToStrings(slice []any) []string {
	result := make([]string, 0, len(slice))
	for _, v := range slice {
		result = append(result, fmt.Sprintf("%v", v))
	}
	return result
}

// sliceAny converts []string to []any.
func sliceAny(ss []string) []any {
	result := make([]any, 0, len(ss))
	for _, s := range ss {
		result = append(result, s)
	}
	return result
}

// stringAny converts a string to any.
func stringAny(s string) any {
	return s
}

// intAny converts an int to any.
func intAny(n int) any {
	return n
}

// randUint64Range generates a random uint64 in [min, max).
func randUint64Range(rnd *mrand.Rand, min, max uint64) uint64 {
	n, _ := rand.Int(rnd, big.NewInt(int64(max-min)))
	return min + uint64(n.Int64())
}

// tokenExpiryString formats a token expiry time.
func tokenExpiryString(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Format(time.RFC3339)
}

// tokenURLSafe encodes a token in URL-safe base64.
func tokenURLSafe(token string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(token))
}

// formatThreadTag formats a thread tag for logging.
func formatThreadTag(idx int) string {
	return fmt.Sprintf("[%d]", idx+1)
}

// statusDataErr creates an error from response status and data.
func statusDataErr(status int, data string, err error) error {
	if err != nil {
		return fmt.Errorf("status %d: %s: %w", status, data, err)
	}
	return fmt.Errorf("status %d: %s", status, data)
}

// Name lists for random name generation.
var firstNames = []string{
	"James", "John", "Robert", "Michael", "David", "William", "Richard", "Joseph",
	"Thomas", "Christopher", "Charles", "Daniel", "Matthew", "Anthony", "Mark",
	"Donald", "Steven", "Paul", "Andrew", "Joshua", "Kenneth", "Kevin", "Brian",
	"George", "Timothy", "Ronald", "Edward", "Jason", "Jeffrey", "Ryan",
	"Mary", "Patricia", "Jennifer", "Linda", "Barbara", "Elizabeth", "Susan",
	"Jessica", "Sarah", "Karen", "Lisa", "Nancy", "Betty", "Margaret", "Sandra",
	"Ashley", "Dorothy", "Kimberly", "Emily", "Donna",
}

var lastNames = []string{
	"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
	"Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
	"Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
	"White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
}
