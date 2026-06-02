package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"red-team-agent/internal/config"
	"red-team-agent/internal/knowledge"
)

// RunInjection - Phase 5: Injection Testing
func (s *Scanner) RunInjection(ctx context.Context, target config.Target) *PhaseResult {
	start := time.Now()
	result := &PhaseResult{Phase: "Injection"}

	log.Printf("[Injection] Starting injection testing for %s", target.URL)

	// Get all endpoints and parameters to test
	endpoints := s.KB.Endpoints
	params := s.KB.Parameters

	if len(endpoints) == 0 {
		endpoints = append(endpoints, knowledge.Endpoint{
			URL: target.URL, Method: "GET", DiscoveredAt: time.Now(), DiscoveredBy: "default",
		})
	}
	if len(params) == 0 {
		params = append(params, knowledge.Parameter{
			Name: "q", URL: target.URL, Method: "GET", Type: "query",
		})
	}

	// SQL Injection
	s.testSQLInjection(ctx, target, endpoints, params, result)

	// XSS
	s.testXSS(ctx, target, endpoints, params, result)

	// Command Injection
	s.testCommandInjection(ctx, target, endpoints, params, result)

	// SSTI
	s.testSSTI(ctx, target, endpoints, params, result)

	// LDAP Injection
	s.testLDAPInjection(ctx, target, endpoints, params, result)

	// XXE
	s.testXXE(ctx, target, endpoints, params, result)

	// CRLF Injection
	s.testCRLFInjection(ctx, target, endpoints, params, result)

	// SSRF
	s.testSSRF(ctx, target, endpoints, params, result)

	// Prototype Pollution
	s.testPrototypePollution(ctx, target, endpoints, params, result)

	// Host Header Injection
	s.testHostHeaderInjection(ctx, target, result)

	// HTTP Method Tampering
	s.testHTTPMethodTampering(ctx, target, endpoints, result)

	// Multi-method injection (POST, PUT, PATCH, DELETE)
	s.testMultiMethodInjection(ctx, target, endpoints, params, result)

	result.Duration = time.Since(start)
	log.Printf("[Injection] Completed: %d findings", len(result.Findings))
	return result
}

func (s *Scanner) testSQLInjection(ctx context.Context, target config.Target, endpoints []knowledge.Endpoint, params []knowledge.Parameter, result *PhaseResult) {
	log.Printf("[Injection] Testing SQL Injection")

	sqliPayloads := GetSQLiPayloads()
	errorPatterns := GetSQLErrorPatterns()

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range sqliPayloads {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if s.KB.WasPayloadUsed(payload, ep.URL) {
					continue
				}

				url := buildURL(ep.URL, param.Name, payload)
				resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
					Method:  ep.Method,
					URL:     url,
					Headers: map[string]string{},
				})
				if err != nil {
					continue
				}

				s.KB.AddPayloadRecord(knowledge.PayloadRecord{
					Payload: payload, Type: "sqli", Endpoint: ep.URL,
					Result: "miss", Timestamp: time.Now(),
				})

				body := strings.ToLower(resp.Body)

				// Check for SQL error patterns
				for _, pattern := range errorPatterns {
					if strings.Contains(body, strings.ToLower(pattern)) {
						result.Findings = append(result.Findings, Finding{
							Type:        "sqli-error",
							Severity:    "high",
							Title:       fmt.Sprintf("SQL Injection (Error-based) in %s", param.Name),
							Description: fmt.Sprintf("SQL error revealed when injecting payload into parameter %s at %s", param.Name, ep.URL),
							URL:         ep.URL,
							Parameter:   param.Name,
							Payload:     payload,
							Evidence:    fmt.Sprintf("Error pattern: %s", pattern),
							Remediation: "Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
						})
						s.KB.RecordTechnique("sqli-error", "injection", true)
						break
					}
				}

				// Check for time-based (if payload was time-based)
				if strings.Contains(payload, "SLEEP") || strings.Contains(payload, "sleep") || strings.Contains(payload, "WAITFOR") {
					if resp.Duration > 4*time.Second {
						result.Findings = append(result.Findings, Finding{
							Type:        "sqli-time",
							Severity:    "high",
							Title:       fmt.Sprintf("SQL Injection (Time-based) in %s", param.Name),
							Description: fmt.Sprintf("Time delay observed when injecting SLEEP payload into %s", param.Name),
							URL:         ep.URL,
							Parameter:   param.Name,
							Payload:     payload,
							Evidence:    fmt.Sprintf("Response time: %v (expected ~5s delay)", resp.Duration),
							Remediation: "Use parameterized queries and whitelist allowed input patterns",
						})
						s.KB.RecordTechnique("sqli-time", "injection", true)
					}
				}
			}
		}
	}
}

func (s *Scanner) testXSS(ctx context.Context, target config.Target, endpoints []knowledge.Endpoint, params []knowledge.Parameter, result *PhaseResult) {
	log.Printf("[Injection] Testing XSS")

	xssPayloads := GetXSSPayloads()

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range xssPayloads {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if s.KB.WasPayloadUsed(payload, ep.URL) {
					continue
				}

				url := buildURL(ep.URL, param.Name, payload)
				resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
					Method:  ep.Method,
					URL:     url,
					Headers: map[string]string{},
				})
				if err != nil {
					continue
				}

				s.KB.AddPayloadRecord(knowledge.PayloadRecord{
					Payload: payload, Type: "xss", Endpoint: ep.URL,
					Result: "miss", Timestamp: time.Now(),
				})

				// Check if payload is reflected in response
				if strings.Contains(resp.Body, payload) {
					result.Findings = append(result.Findings, Finding{
						Type:        "xss-reflected",
						Severity:    "high",
						Title:       fmt.Sprintf("Reflected XSS in %s", param.Name),
						Description: fmt.Sprintf("User input is reflected without encoding in parameter %s at %s", param.Name, ep.URL),
						URL:         ep.URL,
						Parameter:   param.Name,
						Payload:     payload,
						Evidence:    "Payload reflected in response body",
						Remediation: "Encode all user input before rendering in HTML. Use Content-Security-Policy headers.",
					})
					s.KB.RecordTechnique("xss-reflected", "injection", true)
				} else {
					s.KB.RecordTechnique("xss-reflected", "injection", false)
				}
			}
		}
	}
}

func (s *Scanner) testCommandInjection(ctx context.Context, target config.Target, endpoints []knowledge.Endpoint, params []knowledge.Parameter, result *PhaseResult) {
	log.Printf("[Injection] Testing Command Injection")

	cmdPayloads := GetCmdInjectionPayloads()

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range cmdPayloads {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if s.KB.WasPayloadUsed(payload, ep.URL) {
					continue
				}

				url := buildURL(ep.URL, param.Name, payload)
				resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
					Method:  ep.Method,
					URL:     url,
					Headers: map[string]string{},
				})
				if err != nil {
					continue
				}

				s.KB.AddPayloadRecord(knowledge.PayloadRecord{
					Payload: payload, Type: "cmdi", Endpoint: ep.URL,
					Result: "miss", Timestamp: time.Now(),
				})

				// Check for command execution indicators
				cmdOutputPatterns := []string{
					"uid=", "gid=", "root:", "total ", "drwx",
					"volume serial", "directory of", "command not found",
					"/bin/sh", "/bin/bash", "no such file",
				}

				body := strings.ToLower(resp.Body)
				for _, pattern := range cmdOutputPatterns {
					if strings.Contains(body, strings.ToLower(pattern)) {
						result.Findings = append(result.Findings, Finding{
							Type:        "command-injection",
							Severity:    "critical",
							Title:       fmt.Sprintf("Command Injection in %s", param.Name),
							Description: fmt.Sprintf("OS command execution possible via parameter %s at %s", param.Name, ep.URL),
							URL:         ep.URL,
							Parameter:   param.Name,
							Payload:     payload,
							Evidence:    fmt.Sprintf("Command output pattern: %s", pattern),
							Remediation: "Never pass user input to OS commands. Use proper API alternatives.",
						})
						s.KB.RecordTechnique("cmd-injection", "injection", true)
						break
					}
				}
			}
		}
	}
}

func (s *Scanner) testSSTI(ctx context.Context, target config.Target, endpoints []knowledge.Endpoint, params []knowledge.Parameter, result *PhaseResult) {
	log.Printf("[Injection] Testing SSTI")

	sstiPayloads := GetSSTIPayloads()
	sstiPatterns := GetSSTIPatterns()

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range sstiPayloads {
				select {
				case <-ctx.Done():
					return
				default:
				}

				url := buildURL(ep.URL, param.Name, payload)
				resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
					Method:  ep.Method,
					URL:     url,
					Headers: map[string]string{},
				})
				if err != nil {
					continue
				}

				for pattern, engine := range sstiPatterns {
					if strings.Contains(resp.Body, pattern) {
						result.Findings = append(result.Findings, Finding{
							Type:        "ssti",
							Severity:    "critical",
							Title:       fmt.Sprintf("Server-Side Template Injection (%s) in %s", engine, param.Name),
							Description: fmt.Sprintf("Template injection detected in %s, engine: %s", param.Name, engine),
							URL:         ep.URL,
							Parameter:   param.Name,
							Payload:     payload,
							Evidence:    fmt.Sprintf("Engine: %s, Pattern: %s", engine, pattern),
							Remediation: "Never render user input as template code. Use sandboxed template engines.",
						})
						s.KB.RecordTechnique("ssti-"+engine, "injection", true)
						break
					}
				}
			}
		}
	}
}

func (s *Scanner) testLDAPInjection(ctx context.Context, target config.Target, endpoints []knowledge.Endpoint, params []knowledge.Parameter, result *PhaseResult) {
	log.Printf("[Injection] Testing LDAP Injection")

	ldapPayloads := GetLDAPPayloads()

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range ldapPayloads {
				url := buildURL(ep.URL, param.Name, payload)
				resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
					Method:  ep.Method,
					URL:     url,
					Headers: map[string]string{},
				})
				if err != nil {
					continue
				}

				// LDAP error or different response indicates potential injection
				if resp.StatusCode == 200 {
					body := strings.ToLower(resp.Body)
					ldapErrors := []string{"ldap", "dn=", "dc=", "ou=", "invalid dn"}
					for _, ldapErr := range ldapErrors {
						if strings.Contains(body, ldapErr) {
							result.Findings = append(result.Findings, Finding{
								Type:        "ldap-injection",
								Severity:    "high",
								Title:       fmt.Sprintf("LDAP Injection in %s", param.Name),
								Description: "LDAP query manipulation possible via user input",
								URL:         ep.URL,
								Parameter:   param.Name,
								Payload:     payload,
								Evidence:    fmt.Sprintf("LDAP reference found: %s", ldapErr),
								Remediation: "Use parameterized LDAP queries and escape special characters",
							})
							break
						}
					}
				}
			}
		}
	}
}

func (s *Scanner) testXXE(ctx context.Context, target config.Target, endpoints []knowledge.Endpoint, params []knowledge.Parameter, result *PhaseResult) {
	log.Printf("[Injection] Testing XXE")

	xxePayloads := GetXXEPayloads()

	for _, ep := range endpoints {
		for _, payload := range xxePayloads {
			resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
				Method:  "POST",
				URL:     ep.URL,
				Headers: map[string]string{"Content-Type": "application/xml"},
				Body:    payload,
			})
			if err != nil {
				continue
			}

			body := strings.ToLower(resp.Body)
			xxeIndicators := []string{"root:", "/etc/passwd", "<?xml", "<!entity"}
			for _, indicator := range xxeIndicators {
				if strings.Contains(body, indicator) {
					result.Findings = append(result.Findings, Finding{
						Type:        "xxe",
						Severity:    "critical",
						Title:       "XML External Entity (XXE) Injection",
						Description: "XML parser processes external entities, allowing file read",
						URL:         ep.URL,
						Payload:     truncate(payload, 100),
						Evidence:    fmt.Sprintf("XXE indicator: %s", indicator),
						Remediation: "Disable external entity processing in XML parsers",
					})
					s.KB.RecordTechnique("xxe", "injection", true)
					break
				}
			}
		}
	}
}

func (s *Scanner) testCRLFInjection(ctx context.Context, target config.Target, endpoints []knowledge.Endpoint, params []knowledge.Parameter, result *PhaseResult) {
	log.Printf("[Injection] Testing CRLF Injection")

	crlfPayloads := []string{
		"%0d%0aSet-Cookie:%20evil=injected",
		"%0d%0aLocation:%20https://evil.com",
		"\r\nSet-Cookie: evil=injected",
	}

	for _, ep := range endpoints {
		for _, param := range params {
			for _, payload := range crlfPayloads {
				url := buildURL(ep.URL, param.Name, payload)
				resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
					Method:  ep.Method,
					URL:     url,
					Headers: map[string]string{},
				})
				if err != nil {
					continue
				}

				// Check if our injected header appeared
				cookie := getHeader(resp.Headers, "Set-Cookie")
				if strings.Contains(cookie, "evil=injected") {
					result.Findings = append(result.Findings, Finding{
						Type:        "crlf-injection",
						Severity:    "medium",
						Title:       "CRLF Injection / Header Injection",
						Description: "CRLF characters in input allow injecting HTTP headers",
						URL:         ep.URL,
						Parameter:   param.Name,
						Payload:     payload,
						Evidence:    fmt.Sprintf("Injected cookie found: %s", cookie),
						Remediation: "Encode CRLF characters in user input before including in HTTP responses",
					})
				}
			}
		}
	}
}

// testSSRF tests for Server-Side Request Forgery
func (s *Scanner) testSSRF(ctx context.Context, target config.Target, endpoints []knowledge.Endpoint, params []knowledge.Parameter, result *PhaseResult) {
	log.Printf("[Injection] Testing SSRF")

	ssrfPayloads := GetSSRFPayloads()

	// SSRF indicators in response
	ssrfIndicators := []string{
		"root:", "bin/bash", "ami-id", "instance-id",
		"reservation-id", "security-credentials",
		"projectId", "name",
		"meta-data", "user-data",
		"<ListAllMyBucketsResult", "<Bucket>",
		"imap", "220 ", "230 ", "251 ",
		"redis", "-ERR",
	}

	for _, ep := range endpoints {
		for _, param := range params {
			// Only test URL-like parameters
			urlParams := []string{"url", "redirect", "path", "link", "site", "goto", "dest", "destination", "return", "next", "image", "img", "src", "callback", "feed", "proxy", "uri", "api", "query"}
			isURLParam := false
			for _, up := range urlParams {
				if strings.EqualFold(param.Name, up) {
					isURLParam = true
					break
				}
			}
			if !isURLParam {
				continue
			}

			for _, payload := range ssrfPayloads {
				select {
				case <-ctx.Done():
					return
				default:
				}

				url := buildURL(ep.URL, param.Name, payload)
				resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
					Method:  ep.Method,
					URL:     url,
					Headers: map[string]string{},
				})
				if err != nil {
					continue
				}

				body := strings.ToLower(resp.Body)
				for _, indicator := range ssrfIndicators {
					if indicator != "" && strings.Contains(body, strings.ToLower(indicator)) {
						result.Findings = append(result.Findings, Finding{
							Type:        "ssrf",
							Severity:    "critical",
							Title:       fmt.Sprintf("Server-Side Request Forgery in %s", param.Name),
							Description: fmt.Sprintf("SSRF via parameter %s allows accessing internal resources", param.Name),
							URL:         ep.URL,
							Parameter:   param.Name,
							Payload:     payload,
							Evidence:    fmt.Sprintf("SSRF indicator: %s", indicator),
							Remediation: "Validate and whitelist URLs. Block requests to internal/private IPs.",
						})
						s.KB.RecordTechnique("ssrf", "injection", true)
						break
					}
				}

				// Check for time-based SSRF (connection to internal service)
				if strings.Contains(payload, "6379") || strings.Contains(payload, "25") {
					if resp.Duration > 2*time.Second {
						result.Findings = append(result.Findings, Finding{
							Type:        "ssrf-time",
							Severity:    "high",
							Title:       fmt.Sprintf("Potential SSRF (time-based) in %s", param.Name),
							Description: fmt.Sprintf("Response delay suggests internal service connection via %s", param.Name),
							URL:         ep.URL,
							Parameter:   param.Name,
							Payload:     payload,
							Evidence:    fmt.Sprintf("Response time: %v", resp.Duration),
							Remediation: "Block requests to internal services and private IP ranges",
						})
					}
				}
			}
		}
	}
}

// testPrototypePollution tests for prototype pollution via query params and JSON body
func (s *Scanner) testPrototypePollution(ctx context.Context, target config.Target, endpoints []knowledge.Endpoint, params []knowledge.Parameter, result *PhaseResult) {
	log.Printf("[Injection] Testing Prototype Pollution")

	ppPayloads := GetPrototypePollutionURLPayloads()

	for _, ep := range endpoints {
		for _, ppPayload := range ppPayloads {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Test via query parameters
			params := make(map[string]string)
			for k, v := range ppPayload {
				params[k] = v
			}

			resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
				Method:  "GET",
				URL:     ep.URL,
				Params:  params,
				Headers: map[string]string{},
			})
			if err != nil {
				continue
			}

			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "polluted") || strings.Contains(body, "isadmin") {
				result.Findings = append(result.Findings, Finding{
					Type:        "prototype-pollution",
					Severity:    "high",
					Title:       "Prototype Pollution via Query Parameters",
					Description: "Object prototype can be polluted via query parameters",
					URL:         ep.URL,
					Payload:     fmt.Sprintf("%v", ppPayload),
					Evidence:    "Polluted property reflected in response",
					Remediation: "Sanitize object keys. Use Object.create(null) or Map instead of plain objects",
				})
				s.KB.RecordTechnique("prototype-pollution", "injection", true)
			}
		}

		// Test via JSON body on POST/PUT/PATCH endpoints
		for _, jsonPayload := range GetPrototypePollutionPayloads() {
			bodyBytes, _ := json.Marshal(jsonPayload)

			for _, method := range []string{"POST", "PUT", "PATCH"} {
				resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
					Method:  method,
					URL:     ep.URL,
					Headers: map[string]string{"Content-Type": "application/json"},
					Body:    string(bodyBytes),
				})
				if err != nil {
					continue
				}

				respBody := strings.ToLower(resp.Body)
				if strings.Contains(respBody, "polluted") || strings.Contains(respBody, "isadmin") {
					result.Findings = append(result.Findings, Finding{
						Type:        "prototype-pollution",
						Severity:    "high",
						Title:       fmt.Sprintf("Prototype Pollution via %s JSON Body", method),
						Description: "Object prototype can be polluted via JSON request body",
						URL:         ep.URL,
						Payload:     string(bodyBytes),
						Evidence:    "Polluted property reflected in response",
						Remediation: "Sanitize object keys before merging. Use Object.create(null)",
					})
					s.KB.RecordTechnique("prototype-pollution", "injection", true)
				}
			}
		}
	}
}

// testHostHeaderInjection tests for host header attack
func (s *Scanner) testHostHeaderInjection(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Injection] Testing Host Header Injection")

	hostPayloads := GetHostHeaderPayloads()

	for _, hostPayload := range hostPayloads {
		select {
		case <-ctx.Done():
			return
		default:
		}

		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method: "GET",
			URL:    target.URL,
			Headers: map[string]string{
				"Host":       hostPayload,
				"User-Agent": s.HTTPClient.UserAgent,
			},
		})
		if err != nil {
			continue
		}

		body := strings.ToLower(resp.Body)
		// Check if the injected host is reflected or affects the response
		if strings.Contains(body, strings.ToLower(hostPayload)) ||
			strings.Contains(body, "evil.com") ||
			strings.Contains(body, "attacker.com") {
			result.Findings = append(result.Findings, Finding{
				Type:        "host-header-injection",
				Severity:    "high",
				Title:       "Host Header Injection",
				Description: "The server reflects or uses the Host header without validation",
				URL:         target.URL,
				Payload:     hostPayload,
				Evidence:    fmt.Sprintf("Host value reflected: %s", hostPayload),
				Remediation: "Validate the Host header against a whitelist of expected values",
			})
			s.KB.RecordTechnique("host-header-injection", "injection", true)
		}

		// Check for password reset poisoning via Host header
		loginURLs := []string{"/forgot-password", "/reset-password", "/api/auth/forgot"}
		for _, path := range loginURLs {
			resetURL := strings.TrimRight(target.URL, "/") + path
			resetResp, err := s.HTTPClient.MakeRequest(HTTPRequest{
				Method: "POST",
				URL:    resetURL,
				Headers: map[string]string{
					"Host":          hostPayload,
					"Content-Type":  "application/json",
					"User-Agent":    s.HTTPClient.UserAgent,
				},
				Body: `{"email":"test@example.com"}`,
			})
			if err != nil {
				continue
			}
			resetBody := strings.ToLower(resetResp.Body)
			if strings.Contains(resetBody, "evil.com") || strings.Contains(resetBody, hostPayload) {
				result.Findings = append(result.Findings, Finding{
					Type:        "host-header-injection",
					Severity:    "critical",
					Title:       "Password Reset Poisoning via Host Header",
					Description: "The password reset link uses the Host header value, allowing phishing attacks",
					URL:         resetURL,
					Payload:     hostPayload,
					Evidence:    "Host header reflected in password reset flow",
					Remediation: "Use a hardcoded base URL for password reset links",
				})
			}
		}
	}
}

// testHTTPMethodTampering tests X-HTTP-Method-Override and similar headers
func (s *Scanner) testHTTPMethodTampering(ctx context.Context, target config.Target, endpoints []knowledge.Endpoint, result *PhaseResult) {
	log.Printf("[Injection] Testing HTTP Method Tampering")

	overrideHeaders := GetHTTPMethodOverridePayloads()

	// Test on admin-protected paths
	protectedPaths := []string{"/admin", "/admin/users", "/admin/settings", "/api/admin", "/api/v1/admin"}

	for _, path := range protectedPaths {
		url := strings.TrimRight(target.URL, "/") + path

		for _, headers := range overrideHeaders {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// First, try normal request to check if protected
			normalResp, err := s.HTTPClient.MakeRequest(HTTPRequest{
				Method:  "GET",
				URL:     url,
				Headers: map[string]string{},
			})
			if err != nil {
				continue
			}

			// If normally blocked (401/403), try with override headers
			if normalResp.StatusCode == 401 || normalResp.StatusCode == 403 {
				reqHeaders := make(map[string]string)
				for k, v := range headers {
					reqHeaders[k] = v
				}

				overrideResp, err := s.HTTPClient.MakeRequest(HTTPRequest{
					Method:  "POST",
				URL:     url,
					Headers: reqHeaders,
				})
				if err != nil {
					continue
				}

				if overrideResp.StatusCode == 200 {
					result.Findings = append(result.Findings, Finding{
						Type:        "method-tampering",
						Severity:    "high",
						Title:       fmt.Sprintf("HTTP Method Tampering via %s", headers),
						Description: "Protected endpoint bypassed using HTTP method override headers",
						URL:         url,
						Payload:     fmt.Sprintf("%v", headers),
						Evidence:    fmt.Sprintf("Normal: HTTP %d, Override: HTTP %d", normalResp.StatusCode, overrideResp.StatusCode),
						Remediation: "Do not trust X-HTTP-Method-Override or similar headers",
					})
					s.KB.RecordTechnique("method-tampering", "injection", true)
				}
			}
		}
	}
}

// testMultiMethodInjection tests injection payloads with POST, PUT, PATCH, DELETE
func (s *Scanner) testMultiMethodInjection(ctx context.Context, target config.Target, endpoints []knowledge.Endpoint, params []knowledge.Parameter, result *PhaseResult) {
	log.Printf("[Injection] Testing multi-method injection (POST, PUT, PATCH)")

	methods := []string{"POST", "PUT", "PATCH"}
	bodyParams := []string{"username", "email", "name", "comment", "message", "title", "description", "content", "data", "query", "search", "input"}

	// Use a subset of SQLi and XSS payloads for multi-method testing
	multiSQLi := []string{"' OR '1'='1", "' OR 1=1--", "' AND SLEEP(5)--"}
	multiXSS := []string{"<script>alert(1)</script>", "<img src=x onerror=alert(1)>"}

	for _, ep := range endpoints {
		for _, method := range methods {
			for _, param := range bodyParams {
				// Test SQLi in body
				for _, payload := range multiSQLi {
					select {
					case <-ctx.Done():
						return
					default:
					}

					// JSON body
					jsonBody := fmt.Sprintf(`{"%s":"%s"}`, param, payload)
					resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
						Method:  method,
						URL:     ep.URL,
						Headers: map[string]string{"Content-Type": "application/json"},
						Body:    jsonBody,
					})
					if err != nil {
						continue
					}

					// Check SQL errors
					body := strings.ToLower(resp.Body)
					errorPatterns := GetSQLErrorPatterns()
					for _, pattern := range errorPatterns {
						if strings.Contains(body, strings.ToLower(pattern)) {
							result.Findings = append(result.Findings, Finding{
								Type:        "sqli-body",
								Severity:    "high",
								Title:       fmt.Sprintf("SQL Injection in %s Body (%s) via %s", method, param, ep.URL),
								Description: fmt.Sprintf("SQL injection via JSON body parameter %s with %s method", param, method),
								URL:         ep.URL,
								Parameter:   param,
								Payload:     payload,
								Evidence:    fmt.Sprintf("SQL error: %s", pattern),
								Remediation: "Use parameterized queries for all input sources including JSON body",
							})
							s.KB.RecordTechnique("sqli-body", "injection", true)
							break
						}
					}

					// Form-urlencoded body
					formBody := fmt.Sprintf("%s=%s", param, payload)
					resp2, err := s.HTTPClient.MakeRequest(HTTPRequest{
						Method:  method,
						URL:     ep.URL,
						Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
						Body:    formBody,
					})
					if err != nil {
						continue
					}

					body2 := strings.ToLower(resp2.Body)
					for _, pattern := range errorPatterns {
						if strings.Contains(body2, strings.ToLower(pattern)) {
							result.Findings = append(result.Findings, Finding{
								Type:        "sqli-body",
								Severity:    "high",
								Title:       fmt.Sprintf("SQL Injection in %s Form Body (%s)", method, param),
								Description: fmt.Sprintf("SQL injection via form body parameter %s with %s method", param, method),
								URL:         ep.URL,
								Parameter:   param,
								Payload:     payload,
								Evidence:    fmt.Sprintf("SQL error: %s", pattern),
								Remediation: "Use parameterized queries for all input sources",
							})
							break
						}
					}
				}

				// Test XSS in body
				for _, payload := range multiXSS {
					jsonBody := fmt.Sprintf(`{"%s":"%s"}`, param, payload)
					resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
						Method:  method,
						URL:     ep.URL,
						Headers: map[string]string{"Content-Type": "application/json"},
						Body:    jsonBody,
					})
					if err != nil {
						continue
					}

					if strings.Contains(resp.Body, payload) {
						result.Findings = append(result.Findings, Finding{
							Type:        "xss-body",
							Severity:    "high",
							Title:       fmt.Sprintf("Stored/Reflected XSS in %s Body (%s)", method, param),
							Description: fmt.Sprintf("XSS via JSON body parameter %s with %s method", param, method),
							URL:         ep.URL,
							Parameter:   param,
							Payload:     payload,
							Evidence:    "Payload reflected in response body",
							Remediation: "Encode all user input before rendering, regardless of HTTP method",
						})
						s.KB.RecordTechnique("xss-body", "injection", true)
					}
				}
			}
		}
	}
}

func buildURL(baseURL, param, value string) string {
	sep := "?"
	if strings.Contains(baseURL, "?") {
		sep = "&"
	}
	return baseURL + sep + param + "=" + value
}
