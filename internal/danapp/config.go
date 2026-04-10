package danapp

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// Config holds all configuration for the dan application.
type Config struct {
	RootDir     string
	Count       int
	OutputFile  string
	Proxy       string
	UseEnvProxy bool
	Domains     []string

	// Boolean flags
	RuntimeLogs   bool
	Cleanup       bool
	EnableOAuth   bool
	OAuthRequired bool
	UploadTokens  bool

	// Mail API configuration
	MailAPIURL  string
	MailAPIKey  string
	AdminEmail  string
	AdminPass   string
	EmailDomain string

	// Key files
	AKFile string
	RKFile string

	// Token storage
	TokenJSONDir string

	// Upload API
	UploadAPIURL   string
	UploadAPIToken string

	// OAuth configuration
	OAuthIssuer      string
	OAuthClientID    string
	OAuthRedirectURI string

	// OTP retry settings
	OTPRetryCount           int
	OTPRetryIntervalSeconds int
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig(root string) Config {
	return Config{
		RootDir:                 root,
		Count:                   1,
		RuntimeLogs:             false,
		Cleanup:                 false,
		EnableOAuth:             true,
		OAuthRequired:           false,
		UploadTokens:            true,
		OTPRetryCount:           5,
		OTPRetryIntervalSeconds: 10,
		MailAPIURL:              "https://api.mail.tm",
		TokenJSONDir:            "tokens",
		OAuthIssuer:             "https://auth.openai.com/",
		OAuthClientID:           "",
		OAuthRedirectURI:        "http://localhost:1455/auth/callback",
	}
}

// EffectiveOTPRetryCount returns the OTP retry count, defaulting if zero.
func (cfg Config) EffectiveOTPRetryCount() int {
	if cfg.OTPRetryCount <= 0 {
		return 5
	}
	return cfg.OTPRetryCount
}

// EffectiveOTPRetryIntervalSeconds returns the OTP retry interval, defaulting if zero.
func (cfg Config) EffectiveOTPRetryIntervalSeconds() int {
	if cfg.OTPRetryIntervalSeconds <= 0 {
		return 10
	}
	return cfg.OTPRetryIntervalSeconds
}

// Validate checks the config for required fields and consistency.
func (cfg Config) Validate() error {
	if cfg.Count <= 0 {
		return fmt.Errorf("invalid --count value: %d", cfg.Count)
	}
	if cfg.MailAPIURL == "" {
		return fmt.Errorf("missing --mail-api-url")
	}
	if cfg.MailAPIKey == "" {
		return fmt.Errorf("missing --mail-api-key")
	}
	if len(cfg.Domains) == 0 {
		return fmt.Errorf("missing values for --domains")
	}
	if cfg.UploadTokens && cfg.UploadAPIURL == "" {
		return fmt.Errorf("missing --upload-api-url when --upload-tokens is enabled")
	}
	return nil
}

// CLIOpts holds parsed CLI options (non-config flags).
type CLIOpts struct {
	Help    bool
	Count   int
	NoOAuth bool
}

// ParseCLI parses command-line flags and returns options, config, and error.
func ParseCLI(root string) (*CLIOpts, *Config, error) {
	fs := flag.NewFlagSet("dan", flag.ContinueOnError)

	opts := &CLIOpts{}
	cfg := DefaultConfig(root)
	var domainsCSV string

	applyProjectConfig(&cfg, root)
	if path := preferredWebConfigPath(root); path != "" {
		if webConfig := readWebConfigData(path); webConfig != nil {
			applyWebConfig(&cfg, webConfig)
		}
	}
	applyRuntimeConfigFile(&cfg, root)

	fs.BoolVar(&opts.Help, "help", false, "show usage")
	fs.IntVar(&opts.Count, "count", cfg.Count, "number of accounts to register")
	fs.StringVar(&cfg.OutputFile, "output", cfg.OutputFile, "output file for results")
	fs.StringVar(&cfg.Proxy, "proxy", cfg.Proxy, "HTTP proxy URL")
	fs.BoolVar(&cfg.UseEnvProxy, "env-proxy", cfg.UseEnvProxy, "use HTTP_PROXY/HTTPS_PROXY from environment")
	fs.StringVar(&domainsCSV, "domains", "", "comma-separated list of target domains")
	fs.BoolVar(&cfg.RuntimeLogs, "runtime-logs", cfg.RuntimeLogs, "enable detailed runtime logging")
	fs.BoolVar(&cfg.Cleanup, "cleanup", cfg.Cleanup, "clean up temporary files after registration")
	fs.BoolVar(&cfg.EnableOAuth, "oauth", cfg.EnableOAuth, "enable OAuth / Codex token fetch")
	fs.BoolVar(&cfg.OAuthRequired, "oauth-required", cfg.OAuthRequired, "require OAuth token (fail if not obtained)")
	fs.BoolVar(&cfg.UploadTokens, "upload-tokens", cfg.UploadTokens, "upload tokens to CPA")
	fs.StringVar(&cfg.MailAPIURL, "mail-api-url", cfg.MailAPIURL, "mail API base URL")
	fs.StringVar(&cfg.MailAPIKey, "mail-api-key", cfg.MailAPIKey, "mail API key")
	fs.StringVar(&cfg.AdminEmail, "admin-email", cfg.AdminEmail, "mail API admin email")
	fs.StringVar(&cfg.AdminPass, "admin-pass", cfg.AdminPass, "mail API admin password")
	fs.StringVar(&cfg.EmailDomain, "email-domain", cfg.EmailDomain, "email domain for registration")
	fs.StringVar(&cfg.AKFile, "ak-file", cfg.AKFile, "access key file path")
	fs.StringVar(&cfg.RKFile, "rk-file", cfg.RKFile, "refresh key file path")
	fs.StringVar(&cfg.TokenJSONDir, "token-dir", cfg.TokenJSONDir, "directory for token JSON files")
	fs.StringVar(&cfg.UploadAPIURL, "upload-api-url", cfg.UploadAPIURL, "CPA upload API URL")
	fs.StringVar(&cfg.UploadAPIToken, "upload-api-token", cfg.UploadAPIToken, "CPA upload API token")
	fs.StringVar(&cfg.OAuthIssuer, "oauth-issuer", cfg.OAuthIssuer, "OAuth issuer URL")
	fs.StringVar(&cfg.OAuthClientID, "oauth-client-id", cfg.OAuthClientID, "OAuth client ID")
	fs.StringVar(&cfg.OAuthRedirectURI, "oauth-redirect-uri", cfg.OAuthRedirectURI, "OAuth redirect URI")
	fs.IntVar(&cfg.OTPRetryCount, "otp-retry-count", cfg.OTPRetryCount, "OTP verification retry count")
	fs.IntVar(&cfg.OTPRetryIntervalSeconds, "otp-retry-interval", cfg.OTPRetryIntervalSeconds, "OTP verification retry interval in seconds")

	fs.BoolVar(&opts.NoOAuth, "no-oauth", false, "skip OAuth / Codex token fetch")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return nil, nil, err
	}

	if opts.Help {
		Usage()
		os.Exit(0)
	}

	// Parse domains from comma-separated string
	if domainsCSV != "" {
		parts := strings.Split(domainsCSV, ",")
		cfg.Domains = cfg.Domains[:0]
		for _, d := range parts {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			cfg.Domains = append(cfg.Domains, d)
		}
	}

	cfg.Count = opts.Count
	if opts.NoOAuth {
		cfg.EnableOAuth = false
	}

	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}

	return opts, &cfg, nil
}

// Usage prints the CLI usage information.
func Usage() {
	fmt.Fprintf(os.Stderr, "Usage: dan [options]\n\n")
	fmt.Fprintf(os.Stderr, "Options:\n")
	fmt.Fprintf(os.Stderr, "  --count <n>              Number of accounts to register\n")
	fmt.Fprintf(os.Stderr, "  --domains <domains>      Target domains (comma-separated)\n")
	fmt.Fprintf(os.Stderr, "  --proxy <url>            HTTP proxy URL\n")
	fmt.Fprintf(os.Stderr, "  --env-proxy              Use HTTP_PROXY from environment\n")
	fmt.Fprintf(os.Stderr, "  --mail-api-url <url>     Mail API base URL\n")
	fmt.Fprintf(os.Stderr, "  --mail-api-key <key>     Mail API key\n")
	fmt.Fprintf(os.Stderr, "  --admin-email <email>    Mail API admin email\n")
	fmt.Fprintf(os.Stderr, "  --admin-pass <pass>      Mail API admin password\n")
	fmt.Fprintf(os.Stderr, "  --email-domain <domain>  Email domain for registration\n")
	fmt.Fprintf(os.Stderr, "  --oauth                  Enable OAuth / Codex token fetch\n")
	fmt.Fprintf(os.Stderr, "  --no-oauth               Skip OAuth / Codex token fetch\n")
	fmt.Fprintf(os.Stderr, "  --oauth-required         Require OAuth token\n")
	fmt.Fprintf(os.Stderr, "  --upload-tokens          Upload tokens to CPA\n")
	fmt.Fprintf(os.Stderr, "  --upload-api-url <url>   CPA upload API URL\n")
	fmt.Fprintf(os.Stderr, "  --upload-api-token <tok> CPA upload API token\n")
	fmt.Fprintf(os.Stderr, "  --ak-file <path>         Access key file path\n")
	fmt.Fprintf(os.Stderr, "  --rk-file <path>         Refresh key file path\n")
	fmt.Fprintf(os.Stderr, "  --token-dir <path>       Directory for token JSON files\n")
	fmt.Fprintf(os.Stderr, "  --oauth-issuer <url>     OAuth issuer URL\n")
	fmt.Fprintf(os.Stderr, "  --oauth-client-id <id>   OAuth client ID\n")
	fmt.Fprintf(os.Stderr, "  --oauth-redirect-uri <url> OAuth redirect URI\n")
	fmt.Fprintf(os.Stderr, "  --otp-retry-count <n>    OTP retry count\n")
	fmt.Fprintf(os.Stderr, "  --otp-retry-interval <n> OTP retry interval (seconds)\n")
	fmt.Fprintf(os.Stderr, "  --output <file>          Output file for results\n")
	fmt.Fprintf(os.Stderr, "  --runtime-logs           Enable detailed runtime logging\n")
	fmt.Fprintf(os.Stderr, "  --cleanup                Clean up temporary files\n")
	fmt.Fprintf(os.Stderr, "  --help                   Show this help\n")
}
