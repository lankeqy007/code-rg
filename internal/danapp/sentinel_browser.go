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

	var projConfig map[string]any
	if err := decodeJSON(stripUTF8BOM(data)); err != nil {
		// Try as the return value
		result, e := decodeJSON(stripUTF8BOM(data))
		if e != nil {
			return
		}
		projConfig = result
	}

	applyWebConfig(cfg, projConfig)
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
