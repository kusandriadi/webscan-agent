package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"red-team-agent/internal/config"
	"red-team-agent/internal/knowledge"
)

// RunInfra — Phase 8: Infrastructure security testing
func (s *Scanner) RunInfra(ctx context.Context, target config.Target) (result *PhaseResult) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Infra] Panic recovered: %v", r)
			if result == nil {
				result = &PhaseResult{Phase: "Infrastructure"}
			}
		}
	}()
	start := time.Now()
	result = &PhaseResult{Phase: "Infrastructure"}

	baseURL := strings.TrimRight(target.URL, "/")

	// Security headers audit
	result.Findings = append(result.Findings, s.auditSecurityHeadersInfra(baseURL)...)
	// Cookie security
	result.Findings = append(result.Findings, s.auditCookiesInfra(baseURL)...)
	// Information disclosure
	discFindings, discEndpoints := s.checkInfoDisclosureInfra(baseURL)
	result.Findings = append(result.Findings, discFindings...)
	result.Endpoints = append(result.Endpoints, discEndpoints...)
	// Path traversal / LFI
	result.Findings = append(result.Findings, s.testPathTraversalInfra(baseURL)...)
	// Backup file detection
	result.Findings = append(result.Findings, s.detectBackupFilesInfra(baseURL)...)
	// Debug mode detection
	result.Findings = append(result.Findings, s.detectDebugModeInfra(baseURL)...)
	// SSRF via URL parameters
	s.testSSRFInfra(ctx, target, result)
	// Subdomain takeover check
	s.testSubdomainTakeover(ctx, target, result)
	// Certificate Transparency check
	s.testCertificateTransparency(ctx, target, result)
	// HTTPS misconfiguration
	s.testHTTPSMisconfiguration(ctx, target, result)

	result.Duration = time.Since(start)
	log.Printf("[Infra] Complete: %d findings", len(result.Findings))
	return result
}

func (s *Scanner) auditSecurityHeadersInfra(baseURL string) []Finding {
	var findings []Finding
	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
		Method:  "GET",
		URL:     baseURL,
		Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
	})
	if err != nil {
		return findings
	}

	requiredHeaders := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY or SAMEORIGIN",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=...",
		"Referrer-Policy":           "strict-origin...",
		"Permissions-Policy":        "camera=(), microphone=()...",
	}

	var missing []string
	for header := range requiredHeaders {
		if getHeader(resp.Headers, header) == "" {
			missing = append(missing, header)
		}
	}

	if len(missing) > 0 {
		severity := "low"
		if len(missing) >= 4 {
			severity = "medium"
		}
		findings = append(findings, Finding{
			Type:        "security-headers",
			Severity:    severity,
			Title:       fmt.Sprintf("Missing Security Headers (%d)", len(missing)),
			Description: fmt.Sprintf("Missing: %s", strings.Join(missing, ", ")),
			URL:         baseURL,
			Evidence:    fmt.Sprintf("Missing: %v", missing),
			Remediation: "Implement all recommended security headers.",
		})
	}

	return findings
}

func (s *Scanner) auditCookiesInfra(baseURL string) []Finding {
	var findings []Finding
	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
		Method:  "GET",
		URL:     baseURL,
		Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
	})
	if err != nil {
		return findings
	}

	sessionNames := map[string]bool{
		"session": true, "sessionid": true, "phpsessid": true,
		"jsessionid": true, "token": true, "auth_token": true,
	}

	for _, cookies := range resp.Headers {
		for _, raw := range cookies {
			parts := strings.SplitN(raw, "=", 2)
			if len(parts) < 1 {
				continue
			}
			name := strings.TrimSpace(parts[0])
			if !sessionNames[strings.ToLower(name)] {
				continue
			}
			var issues []string
			if !strings.Contains(strings.ToLower(raw), "httponly") {
				issues = append(issues, "Missing HttpOnly")
			}
			if !strings.Contains(strings.ToLower(raw), "secure") {
				issues = append(issues, "Missing Secure")
			}
			if !strings.Contains(strings.ToLower(raw), "samesite") {
				issues = append(issues, "Missing SameSite")
			}
			if len(issues) > 0 {
				findings = append(findings, Finding{
					Type:        "cookie",
					Severity:    "medium",
					Title:       fmt.Sprintf("Insecure Cookie: %s", name),
					Description: fmt.Sprintf("Cookie '%s' issues: %s", name, strings.Join(issues, ", ")),
					URL:         baseURL,
					Evidence:    fmt.Sprintf("Raw cookie: %s", truncateStr(raw, 200)),
					Remediation: "Set HttpOnly, Secure, and SameSite flags on all session cookies.",
				})
			}
		}
	}
	return findings
}

func (s *Scanner) checkInfoDisclosureInfra(baseURL string) ([]Finding, []knowledge.Endpoint) {
	var findings []Finding
	var endpoints []knowledge.Endpoint
	paths := []string{"/.env", "/.git/config", "/.git/HEAD", "/.htaccess",
		"/robots.txt", "/sitemap.xml", "/server-status", "/server-info",
		"/phpinfo.php", "/actuator", "/actuator/env", "/actuator/configprops",
		"/swagger.json", "/api/swagger.json", "/graphql",
		"/.well-known/security.txt", "/.DS_Store", "/web.config",
		"/wp-config.php", "/config.php", "/.env.local", "/.env.production",
	}

	for _, path := range paths {
		url := baseURL + path
		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method:  "GET",
			URL:     url,
			Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
		})
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 && len(resp.Body) > 0 {
			bodyStr := strings.ToLower(resp.Body)

			sensitive := strings.Contains(bodyStr, "password") ||
				strings.Contains(bodyStr, "secret") ||
				strings.Contains(bodyStr, "api_key") ||
				strings.Contains(bodyStr, "private") ||
				strings.Contains(bodyStr, "swagger") ||
				strings.Contains(bodyStr, "graphql") ||
				strings.Contains(bodyStr, "user-agent:") ||
				path == "/robots.txt" || path == "/sitemap.xml"

			if sensitive || path == "/.env" || path == "/.git/config" || path == "/.DS_Store" {
				severity := "medium"
				if path == "/.env" || path == "/.git/config" {
					severity = "high"
				}
				findings = append(findings, Finding{
					Type:        "info-disclosure",
					Severity:    severity,
					Title:       "Information Disclosure: " + path,
					Description: fmt.Sprintf("Endpoint %s is accessible.", path),
					URL:         url,
					Evidence:    truncateStr(resp.Body, 500),
					Remediation: fmt.Sprintf("Restrict access to %s.", path),
				})
				endpoints = append(endpoints, knowledge.Endpoint{
					URL:          url,
					DiscoveredBy: "infra",
				})
			}
		}
	}
	return findings, endpoints
}

func (s *Scanner) testPathTraversalInfra(baseURL string) []Finding {
	var findings []Finding
	payloads := GetPathTraversalPayloads()

	for _, payload := range payloads {
		url := baseURL + "/" + payload
		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method:  "GET",
			URL:     url,
			Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
		})
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			if strings.Contains(resp.Body, "root:") || strings.Contains(resp.Body, "[extensions]") {
				findings = append(findings, Finding{
					Type:        "path-traversal",
					Severity:    "critical",
					Title:       "Path Traversal Vulnerability",
					Description: fmt.Sprintf("Server allows path traversal with payload: %s", payload),
					URL:         url,
					Payload:     payload,
					Evidence:    truncateStr(resp.Body, 300),
					Remediation: "Validate and sanitize all file path inputs.",
				})
			}
		}
	}
	return findings
}

func (s *Scanner) detectBackupFilesInfra(baseURL string) []Finding {
	var findings []Finding
	paths := []string{"/backup.sql", "/database.sql", "/dump.sql", "/db.sqlite3",
		"/.env.backup", "/.env.bak", "/config.json.bak", "/.svn/entries",
		"/backup.zip", "/backup.tar.gz", "/site.tar.gz", "/www.zip",
		"/web.config.bak", "/.env.save", "/.env.old", "/config.yml.bak",
		"/app.tar.gz", "/dump.rdb", "/data.sql.gz"}

	for _, path := range paths {
		url := baseURL + path
		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method:  "GET",
			URL:     url,
			Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
		})
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 {
			findings = append(findings, Finding{
				Type:        "backup-file",
				Severity:    "high",
				Title:       "Backup File Exposed: " + path,
				Description: "Backup file is publicly accessible.",
				URL:         url,
				Remediation: "Remove backup files from the web root.",
			})
		}
	}
	return findings
}

func (s *Scanner) detectDebugModeInfra(baseURL string) []Finding {
	var findings []Finding
	paths := []string{"/debug", "/trace", "/_debugbar", "/api/debug",
		"/.well-known/security.txt", "/status", "/healthz",
		"/actuator", "/actuator/health", "/actuator/info",
		"/actuator/metrics", "/actuator/beans", "/actuator/mappings",
		"/actuator/env", "/actuator/configprops", "/actuator/heapdump",
		"/api/_debug", "/_profiler", "/phpinfo.php"}

	for _, path := range paths {
		url := baseURL + path
		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method:  "GET",
			URL:     url,
			Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
		})
		if err != nil {
			continue
		}

		bodyStr := strings.ToLower(resp.Body)

		if resp.StatusCode == 200 {
			if strings.Contains(bodyStr, "debug") ||
				strings.Contains(bodyStr, "stack") ||
				strings.Contains(bodyStr, "trace") ||
				strings.Contains(bodyStr, "profile") ||
				strings.Contains(bodyStr, "actuator") ||
				strings.Contains(bodyStr, "health") ||
				strings.Contains(bodyStr, "beans") ||
				strings.Contains(bodyStr, "phpinfo") {
				findings = append(findings, Finding{
					Type:        "debug-mode",
					Severity:    "medium",
					Title:       "Debug Endpoint Exposed: " + path,
					Description: "Debug/trace endpoint is accessible.",
					URL:         url,
					Evidence:    truncateStr(resp.Body, 300),
					Remediation: "Disable debug endpoints in production.",
				})
			}
		}
	}
	return findings
}

// testSSRFInfra tests SSRF via URL parameters on discovered parameters
func (s *Scanner) testSSRFInfra(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Infra] Testing SSRF via URL parameters")

	baseURL := strings.TrimRight(target.URL, "/")
	ssrfPayloads := GetSSRFPayloads()

	// URL-like parameters
	urlParams := []string{"url", "redirect", "path", "link", "site", "goto", "dest",
		"destination", "return", "next", "image", "img", "src", "callback",
		"feed", "proxy", "uri", "api", "query", "page", "file", "doc",
		"document", "folder", "content", "data", "reference", "location"}

	// Test on common endpoint patterns
	testEndpoints := []string{"/", "/api", "/fetch", "/proxy", "/render", "/preview", "/load", "/api/v1/fetch"}

	for _, endpoint := range testEndpoints {
		for _, param := range urlParams {
			for _, payload := range ssrfPayloads {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Only test a subset to avoid too many requests
				if !strings.Contains(payload, "169.254") && !strings.Contains(payload, "127.0.0.1") && !strings.Contains(payload, "metadata") {
					continue
				}

				url := baseURL + endpoint
				resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
					Method:  "GET",
					URL:     url,
					Params:  map[string]string{param: payload},
					Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
				})
				if err != nil {
					continue
				}

				body := strings.ToLower(resp.Body)
				indicators := []string{"ami-id", "instance-id", "reservation-id", "security-credentials",
					"root:", "meta-data", "computeMetadata", "project-id"}

				for _, indicator := range indicators {
					if strings.Contains(body, indicator) {
						result.Findings = append(result.Findings, Finding{
							Type:        "ssrf",
							Severity:    "critical",
							Title:       fmt.Sprintf("SSRF via '%s' parameter", param),
							Description: fmt.Sprintf("Server-side request forgery possible through parameter %s", param),
							URL:         url,
							Parameter:   param,
							Payload:     payload,
							Evidence:    fmt.Sprintf("Response contains: %s", indicator),
							Remediation: "Validate and whitelist URLs. Block requests to internal/private IPs.",
						})
						s.KB.RecordTechnique("ssrf-infra", "infra", true)
						break
					}
				}
			}
		}
	}
}

// testSubdomainTakeover checks CNAME records for potential takeover
func (s *Scanner) testSubdomainTakeover(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Infra] Checking for subdomain takeover")

	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		return
	}
	hostname := parsedURL.Hostname()

	// Resolve CNAME records
	cname, err := net.LookupCNAME(hostname)
	if err != nil {
		return
	}

	// Check if CNAME points to known takeover-vulnerable services
	takeoverServices := map[string]string{
		"cloudfront.net":          "AWS CloudFront",
		"s3.amazonaws.com":        "AWS S3",
		"s3-website":              "AWS S3 Website",
		"herokuapp.com":           "Heroku",
		"ghost.io":                "Ghost.io",
		"pantheon.io":             "Pantheon",
		"zendesk.com":             "Zendesk",
		"github.io":               "GitHub Pages",
		"gitlab.io":               "GitLab Pages",
		"surge.sh":                "Surge.sh",
		"bitbucket.io":            "Bitbucket",
		"intercom.help":           "Intercom",
		"webflow.io":              "Webflow",
		"readme.io":               "Readme.io",
		"statuspage.io":           "StatusPage",
		"custom-api.cdn.ampproject.org": "Google AMP",
		"azureedge.net":           "Azure CDN",
		"azurewebsites.net":       "Azure App Service",
		"cloudapp.net":            "Azure Cloud App",
		"trafficmanager.net":      "Azure Traffic Manager",
	}

	for serviceSuffix, serviceName := range takeoverServices {
		if strings.Contains(cname, serviceSuffix) {
			// Verify: check if the subdomain returns NXDOMAIN or takeover error
			resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
				Method:  "GET",
				URL:     target.URL,
				Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
			})
			if err != nil {
				// DNS resolution failure might indicate dangling CNAME
				result.Findings = append(result.Findings, Finding{
					Type:        "subdomain-takeover",
					Severity:    "high",
					Title:       fmt.Sprintf("Potential Subdomain Takeover (%s)", serviceName),
					Description: fmt.Sprintf("CNAME points to %s but DNS resolution fails - possible dangling CNAME", serviceName),
					URL:         target.URL,
					Evidence:    fmt.Sprintf("CNAME: %s, DNS error: %v", cname, err),
					Remediation: "Remove dangling CNAME records or claim the resource on the target platform",
				})
				s.KB.RecordTechnique("subdomain-takeover", "infra", true)
				return
			}

			// Check response body for takeover indicators
			body := strings.ToLower(resp.Body)
			takeoverIndicators := map[string]string{
				"herokucdn error":    "Heroku",
				"no such app":        "Heroku",
				"isn't registered":   "GitHub Pages",
				"there isn't a github pages site here": "GitHub Pages",
				"project not found":  "GitLab Pages",
				"do you want to register": "Surge.sh",
				"no such bucket":     "AWS S3",
				"the specified bucket does not exist": "AWS S3",
				"bad request:":       "Ghost.io",
				"404 error unknown site": "Pantheon",
				"help center not active": "Zendesk",
				"repository not found": "Bitbucket",
			}

			for indicator, svc := range takeoverIndicators {
				if strings.Contains(body, indicator) && svc == serviceName {
					result.Findings = append(result.Findings, Finding{
						Type:        "subdomain-takeover",
						Severity:    "high",
						Title:       fmt.Sprintf("Subdomain Takeover: %s (%s)", hostname, serviceName),
						Description: fmt.Sprintf("CNAME points to %s and returns takeover indicator", serviceName),
						URL:         target.URL,
						Evidence:    fmt.Sprintf("CNAME: %s, Indicator: %s", cname, indicator),
						Remediation: "Remove dangling CNAME records or claim the resource",
					})
					s.KB.RecordTechnique("subdomain-takeover", "infra", true)
					return
				}
			}
		}
	}
}

// testCertificateTransparency checks CT logs for subdomains
func (s *Scanner) testCertificateTransparency(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Infra] Checking Certificate Transparency logs")

	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		return
	}
	hostname := parsedURL.Hostname()

	// Extract root domain (simple approach: take last 2 parts for non-country TLDs)
	parts := strings.Split(hostname, ".")
	rootDomain := hostname
	if len(parts) > 2 {
		rootDomain = strings.Join(parts[len(parts)-2:], ".")
	}

	// Use crt.sh for CT log lookup
	ctURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", rootDomain)
	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
		Method:  "GET",
		URL:     ctURL,
		Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
	})
	if err != nil || resp.StatusCode != 200 {
		// CT log check is informational, don't fail hard
		log.Printf("[Infra] CT log lookup failed for %s: %v", rootDomain, err)
		return
	}

	// Parse unique subdomains from CT response
	body := resp.Body
	subdomainSet := make(map[string]bool)

	// Simple extraction of common_name values
	lines := strings.Split(body, ",")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "common_name") || strings.Contains(line, "name_value") {
			// Extract domain between quotes
			start := strings.Index(line, `"`)
			end := strings.LastIndex(line, `"`)
			if start != -1 && end > start {
				domain := line[start+1 : end]
				if strings.Contains(domain, rootDomain) && !strings.Contains(domain, "*") {
					subdomainSet[domain] = true
				}
			}
		}
	}

	if len(subdomainSet) > 0 {
		subdomains := make([]string, 0, len(subdomainSet))
		for sd := range subdomainSet {
			subdomains = append(subdomains, sd)
		}

		result.Findings = append(result.Findings, Finding{
			Type:        "ct-subdomains",
			Severity:    "info",
			Title:       fmt.Sprintf("Certificate Transparency: %d Subdomains Found", len(subdomainSet)),
			Description: fmt.Sprintf("CT logs reveal %d subdomains for %s. These should be checked for security.", len(subdomainSet), rootDomain),
			URL:         ctURL,
			Evidence:    fmt.Sprintf("Subdomains: %s", strings.Join(subdomains[:min(10, len(subdomains))], ", ")),
			Remediation: "Review all discovered subdomains for security. Consider using certificate pinning.",
		})

		// Store subdomains as discovered endpoints for further testing
		for _, sd := range subdomains {
			ep := knowledge.Endpoint{
				URL:           "https://" + sd,
				Method:        "GET",
				DiscoveredAt:  time.Now(),
				DiscoveredBy:  "ct-logs",
			}
			result.Endpoints = append(result.Endpoints, ep)
		}
	}
}

// testHTTPSMisconfiguration checks TLS/SSL configuration
func (s *Scanner) testHTTPSMisconfiguration(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Infra] Testing HTTPS/TLS configuration")

	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		return
	}

	if parsedURL.Scheme != "https" {
		// Already flagged in recon phase
		return
	}

	hostname := parsedURL.Hostname()
	port := "443"
	if parsedURL.Port() != "" {
		port = parsedURL.Port()
	}

	// Connect and check TLS
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		hostname+":"+port,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		result.Findings = append(result.Findings, Finding{
			Type:        "tls-error",
			Severity:    "medium",
			Title:       "TLS Connection Error",
			Description: fmt.Sprintf("Could not establish TLS connection to %s: %v", hostname, err),
			URL:         target.URL,
			Evidence:    err.Error(),
			Remediation: "Fix TLS configuration on the server",
		})
		return
	}
	defer conn.Close()

	// Check certificate validity
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		cert := certs[0]

		// Check if certificate is expired
		if time.Now().After(cert.NotAfter) {
			result.Findings = append(result.Findings, Finding{
				Type:        "tls-cert-expired",
				Severity:    "high",
				Title:       "TLS Certificate Expired",
				Description: fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format("2006-01-02")),
				URL:         target.URL,
				Evidence:    fmt.Sprintf("NotAfter: %s", cert.NotAfter),
				Remediation: "Renew the TLS certificate",
			})
		}

		// Check if certificate is self-signed
		if cert.Issuer.CommonName == cert.Subject.CommonName && len(cert.Issuer.Organization) == 0 {
			result.Findings = append(result.Findings, Finding{
				Type:        "tls-self-signed",
				Severity:    "medium",
				Title:       "Self-Signed TLS Certificate",
				Description: "The server uses a self-signed certificate which may indicate a development environment",
				URL:         target.URL,
				Evidence:    fmt.Sprintf("Issuer: %s, Subject: %s", cert.Issuer.CommonName, cert.Subject.CommonName),
				Remediation: "Use a certificate from a trusted Certificate Authority",
			})
		}

		// Check hostname mismatch
		if err := cert.VerifyHostname(hostname); err != nil {
			result.Findings = append(result.Findings, Finding{
				Type:        "tls-hostname-mismatch",
				Severity:    "high",
				Title:       "TLS Certificate Hostname Mismatch",
				Description: "Certificate does not match the server hostname",
				URL:         target.URL,
				Evidence:    fmt.Sprintf("Cert names: %v, Hostname: %s", cert.DNSNames, hostname),
				Remediation: "Ensure the certificate includes the correct hostname",
			})
		}

		// Check certificate expiration soon (< 30 days)
		daysUntilExpiry := time.Until(cert.NotAfter).Hours() / 24
		if daysUntilExpiry > 0 && daysUntilExpiry < 30 {
			result.Findings = append(result.Findings, Finding{
				Type:        "tls-cert-expiring",
				Severity:    "medium",
				Title:       fmt.Sprintf("TLS Certificate Expiring Soon (%.0f days)", daysUntilExpiry),
				Description: fmt.Sprintf("Certificate expires on %s (%.0f days from now)", cert.NotAfter.Format("2006-01-02"), daysUntilExpiry),
				URL:         target.URL,
				Evidence:    fmt.Sprintf("NotAfter: %s", cert.NotAfter),
				Remediation: "Renew the TLS certificate before it expires",
			})
		}

		// Check for weak signature algorithm
		if cert.SignatureAlgorithm == x509.SHA1WithRSA || cert.SignatureAlgorithm == x509.DSAWithSHA1 || cert.SignatureAlgorithm == x509.ECDSAWithSHA1 {
			result.Findings = append(result.Findings, Finding{
				Type:        "tls-weak-sig",
				Severity:    "high",
				Title:       "Weak TLS Certificate Signature Algorithm",
				Description: fmt.Sprintf("Certificate uses weak signature algorithm: %s", cert.SignatureAlgorithm),
				URL:         target.URL,
				Evidence:    fmt.Sprintf("SignatureAlgorithm: %s", cert.SignatureAlgorithm),
				Remediation: "Use SHA-256 or stronger signature algorithms",
			})
		}
	}

	// Check TLS version
	version := conn.ConnectionState().Version
	switch version {
	case tls.VersionTLS10:
		result.Findings = append(result.Findings, Finding{
			Type:        "tls-version",
			Severity:    "medium",
			Title:       "Weak TLS Version: TLS 1.0",
			Description: "Server supports TLS 1.0 which is deprecated and insecure",
			URL:         target.URL,
			Evidence:    "TLS 1.0",
			Remediation: "Disable TLS 1.0 and TLS 1.1, use TLS 1.2+ only",
		})
	case tls.VersionTLS11:
		result.Findings = append(result.Findings, Finding{
			Type:        "tls-version",
			Severity:    "medium",
			Title:       "Weak TLS Version: TLS 1.1",
			Description: "Server supports TLS 1.1 which is deprecated",
			URL:         target.URL,
			Evidence:    "TLS 1.1",
			Remediation: "Disable TLS 1.0 and TLS 1.1, use TLS 1.2+ only",
		})
	}

	// Check for HSTS header
	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
		Method:  "GET",
		URL:     target.URL,
		Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
	})
	if err == nil {
		hsts := getHeader(resp.Headers, "Strict-Transport-Security")
		if hsts == "" {
			result.Findings = append(result.Findings, Finding{
				Type:        "missing-hsts",
				Severity:    "medium",
				Title:       "Missing HSTS Header",
				Description: "Strict-Transport-Security header is not set. HTTPS connections may be downgraded.",
				URL:         target.URL,
				Remediation: "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
			})
		} else {
			// Check HSTS max-age
			if !strings.Contains(hsts, "max-age=") {
				result.Findings = append(result.Findings, Finding{
					Type:        "hsts-weak",
					Severity:    "low",
					Title:       "Weak HSTS Configuration",
					Description: "HSTS header doesn't include max-age directive",
					URL:         target.URL,
					Evidence:    hsts,
					Remediation: "Set proper max-age value (recommended: 31536000)",
				})
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
