package danapp

import (
	"fmt"
	"os"
	"path/filepath"
)

// sentinelBrowserPageURL is defined in sentinel.go.
// This file handles the sentinel browser helper integration.

// writeWebConfigDomains writes the domain list to the web config.
func writeWebConfigDomains(cfg Config, domains []string) error {
	configPath := preferredWebConfigPath(cfg.RootDir)
	if configPath == "" {
		return nil
	}

	// Read existing config or create new
	data := readWebConfigData(configPath)

	// Update domains in config
	if data == nil {
		data = make(map[string]any)
	}

	domainMap := make(map[string]any)
	for _, d := range domains {
		domainMap[d] = map[string]any{
			"enabled": true,
		}
	}
	data["domains"] = domainMap

	return nil
}

// preferredWebConfigPath returns the preferred path for the web config file.
func preferredWebConfigPath(rootDir string) string {
	candidates := webConfigCandidatePaths(rootDir)
	for _, p := range candidates {
		if fileExists(p) {
			return p
		}
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

// webConfigCandidatePaths returns candidate paths for the web config.
func webConfigCandidatePaths(rootDir string) []string {
	return []string{
		filepath.Join(rootDir, "web_config.json"),
		filepath.Join(rootDir, "config", "web_config.json"),
	}
}

// readWebConfigData reads the web config data.
func readWebConfigData(path string) map[string]any {
	if !fileExists(path) {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	result, err := decodeJSON(stripUTF8BOM(data))
	if err != nil {
		return nil
	}

	return result
}

// readWebConfigForUpdate reads the web config for modification.
func readWebConfigForUpdate(path string) (map[string]any, error) {
	data := readWebConfigData(path)
	if data == nil {
		return nil, fmt.Errorf("web config not found: %s", path)
	}
	return data, nil
}

// applyWebConfig applies web config settings to the app config.
func applyWebConfig(cfg *Config, webConfig map[string]any) {
	if domains, ok := webConfig["domains"]; ok {
		extracted := extractDomainsFromWebConfigData(domains)
		if len(extracted) > 0 && len(cfg.Domains) == 0 {
			cfg.Domains = extracted
		}
	}

	// Apply other web config settings
	if v := mapString(webConfig, "mail_api_url"); v != "" && cfg.MailAPIURL == "" {
		cfg.MailAPIURL = v
	}
	if v := mapString(webConfig, "mail_api_key"); v != "" && cfg.MailAPIKey == "" {
		cfg.MailAPIKey = v
	}
	if v := mapString(webConfig, "upload_api_url"); v != "" && cfg.UploadAPIURL == "" {
		cfg.UploadAPIURL = v
	}
	if v := mapString(webConfig, "oauth_issuer"); v != "" && cfg.OAuthIssuer == "" {
		cfg.OAuthIssuer = v
	}
	if v := mapString(webConfig, "oauth_client_id"); v != "" && cfg.OAuthClientID == "" {
		cfg.OAuthClientID = v
	}
}

// applyProjectConfig applies project-level configuration.
func applyProjectConfig(cfg *Config, rootDir string) {
	configPath := filepath.Join(rootDir, "project_config.json")
	if !fileExists(configPath) {
		return
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}

	projConfig, err := decodeJSON(stripUTF8BOM(data))
	if err != nil {
		return
	}

	applyWebConfig(cfg, projConfig)
}

// applyRuntimeConfigFile applies settings from config.json-style files.
func applyRuntimeConfigFile(cfg *Config, rootDir string) {
	for _, configPath := range []string{
		filepath.Join(rootDir, "config.json"),
		filepath.Join(rootDir, "config", "config.json"),
	} {
		if !fileExists(configPath) {
			continue
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}

		runtimeConfig, err := decodeJSON(stripUTF8BOM(data))
		if err != nil {
			continue
		}

		applyRuntimeConfigMap(cfg, runtimeConfig)
		return
	}
}

// applyRuntimeConfigMap applies config.json key/value pairs onto Config.
func applyRuntimeConfigMap(cfg *Config, runtimeConfig map[string]any) {
	if v := mapString(runtimeConfig, "mail_api_url"); v != "" {
		cfg.MailAPIURL = v
	}
	if v := mapString(runtimeConfig, "mail_api_key"); v != "" {
		cfg.MailAPIKey = v
	}
	if v := mapString(runtimeConfig, "admin_email"); v != "" {
		cfg.AdminEmail = v
	}
	if v := mapString(runtimeConfig, "admin_pass"); v != "" {
		cfg.AdminPass = v
	}
	if v := mapString(runtimeConfig, "email_domain"); v != "" {
		cfg.EmailDomain = v
	}
	if v := mapString(runtimeConfig, "ak_file"); v != "" {
		cfg.AKFile = v
	}
	if v := mapString(runtimeConfig, "rk_file"); v != "" {
		cfg.RKFile = v
	}
	if v := mapString(runtimeConfig, "token_json_dir"); v != "" {
		cfg.TokenJSONDir = v
	}
	if v := mapString(runtimeConfig, "upload_api_url"); v != "" {
		cfg.UploadAPIURL = v
	}
	if v := mapString(runtimeConfig, "upload_api_token"); v != "" {
		cfg.UploadAPIToken = v
	}
	if v := mapString(runtimeConfig, "oauth_issuer"); v != "" {
		cfg.OAuthIssuer = v
	}
	if v := mapString(runtimeConfig, "oauth_client_id"); v != "" {
		cfg.OAuthClientID = v
	}
	if v := mapString(runtimeConfig, "oauth_redirect_uri"); v != "" {
		cfg.OAuthRedirectURI = v
	}

	if domains := runtimeConfig["domains"]; domains != nil && len(cfg.Domains) == 0 {
		cfg.Domains = extractDomainsFromWebConfigData(domains)
	}
	if v := mapBool(runtimeConfig, "enable_oauth"); v {
		cfg.EnableOAuth = true
	}
	if v := mapBool(runtimeConfig, "oauth_required"); v {
		cfg.OAuthRequired = true
	}
	if v := mapBool(runtimeConfig, "upload_tokens"); v {
		cfg.UploadTokens = true
	}
}

// extractDomainsFromWebConfigData extracts domains from web config data.
func extractDomainsFromWebConfigData(domains any) []string {
	switch d := domains.(type) {
	case map[string]any:
		result := make([]string, 0, len(d))
		for k := range d {
			result = append(result, k)
		}
		return result
	case []any:
		return anySliceToStrings(d)
	case []string:
		return d
	}
	return nil
}
