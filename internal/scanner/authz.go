package scanner

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"red-team-agent/internal/config"
)

// RunAuthz - Phase 4: Authorization Testing
func (s *Scanner) RunAuthz(ctx context.Context, target config.Target) *PhaseResult {
	start := time.Now()
	result := &PhaseResult{Phase: "Authorization"}

	log.Printf("[Authz] Starting authorization testing for %s", target.URL)

	// Privilege escalation tests
	s.testPrivilegeEscalation(ctx, target, result)

	// IDOR tests
	s.testIDOR(ctx, target, result)

	// Missing function-level access control
	s.testMissingAccessControl(ctx, target, result)

	// API authorization bypass
	s.testAPIAuthzBypass(ctx, target, result)

	result.Duration = time.Since(start)
	log.Printf("[Authz] Completed: %d findings", len(result.Findings))
	return result
}

var adminPaths = []string{
	"/admin", "/admin/users", "/admin/settings", "/admin/config",
	"/admin/dashboard", "/admin/api", "/api/admin",
	"/api/v1/admin", "/manage", "/management",
	"/api/users/all", "/api/users/admin",
}

func (s *Scanner) testPrivilegeEscalation(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Authz] Testing privilege escalation")

	for _, path := range adminPaths {
		url := strings.TrimRight(target.URL, "/") + path

		// Try accessing as unauthenticated user
		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method:  "GET",
			URL:     url,
			Headers: map[string]string{},
		})
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			result.Findings = append(result.Findings, Finding{
				Type:        "privilege-escalation",
				Severity:    "high",
				Title:       fmt.Sprintf("Unauthenticated Access to Admin Path: %s", path),
				Description: fmt.Sprintf("Admin endpoint %s is accessible without authentication", path),
				URL:         url,
				Evidence:    fmt.Sprintf("HTTP %d - accessible without credentials", resp.StatusCode),
				Remediation: "Implement proper authentication and authorization checks on admin endpoints",
			})
			s.KB.RecordTechnique("privilege-escalation", "authz", true)
		} else {
			s.KB.RecordTechnique("privilege-escalation", "authz", false)
		}
	}
}

func (s *Scanner) testIDOR(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Authz] Testing IDOR")

	// Test sequential/predictable IDs
	idorEndpoints := []struct {
		path   string
		param  string
	}{
		{"/api/users/1", "id"},
		{"/api/users/2", "id"},
		{"/api/v1/users/1", "id"},
		{"/api/profile/1", "id"},
		{"/api/orders/1", "id"},
		{"/api/documents/1", "id"},
		{"/user/1", "id"},
		{"/profile?id=1", "id"},
		{"/api/users/me", "none"},
	}

	for _, ep := range idorEndpoints {
		url := strings.TrimRight(target.URL, "/") + ep.path

		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method:  "GET",
			URL:     url,
			Headers: map[string]string{},
		})
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			// Check if response contains user data
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "email") || strings.Contains(body, "name") || strings.Contains(body, "password") {
				result.Findings = append(result.Findings, Finding{
					Type:        "idor",
					Severity:    "high",
					Title:       fmt.Sprintf("IDOR: Unauthorized Data Access at %s", ep.path),
					Description: fmt.Sprintf("User data accessible without authorization at %s", ep.path),
					URL:         url,
					Parameter:   ep.param,
					Payload:     ep.path,
					Evidence:    "User data returned without authorization",
					Remediation: "Implement proper authorization checks - verify the requesting user owns the requested resource",
				})
				s.KB.RecordTechnique("idor", "authz", true)
			}
		}
		s.KB.RecordTechnique("idor", "authz", false)
	}

	// Try known IDs from knowledge base
	for _, ep := range s.KB.Endpoints {
		if strings.Contains(ep.URL, "user") || strings.Contains(ep.URL, "profile") {
			for i := 1; i <= 5; i++ {
				testURL := strings.Replace(ep.URL, "me", fmt.Sprintf("%d", i), 1)
				resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
					Method: "GET",
					URL:    testURL,
				})
				if err == nil && resp.StatusCode == 200 {
					result.Findings = append(result.Findings, Finding{
						Type:        "idor",
						Severity:    "high",
						Title:       fmt.Sprintf("IDOR via Sequential ID at %s", testURL),
						Description: "Sequential user IDs allow accessing other users' data",
						URL:         testURL,
						Parameter:   "id",
						Payload:     fmt.Sprintf("%d", i),
						Evidence:    fmt.Sprintf("HTTP 200 for ID %d", i),
						Remediation: "Use UUIDs instead of sequential IDs and verify resource ownership",
					})
				}
			}
		}
	}
}

func (s *Scanner) testMissingAccessControl(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Authz] Testing missing function-level access control")

	// Try different HTTP methods on sensitive endpoints
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	sensitivePaths := []string{"/api/users", "/api/config", "/api/settings", "/api/admin"}

	for _, path := range sensitivePaths {
		for _, method := range methods {
			url := strings.TrimRight(target.URL, "/") + path
			resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
				Method:  method,
				URL:     url,
				Headers: map[string]string{},
			})
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 && method != "GET" {
				result.Findings = append(result.Findings, Finding{
					Type:        "missing-access-control",
					Severity:    "high",
					Title:       fmt.Sprintf("Unrestricted %s on %s", method, path),
					Description: fmt.Sprintf("HTTP %s method is allowed without authentication on %s", method, path),
					URL:         url,
					Payload:     method,
					Evidence:    fmt.Sprintf("HTTP %d for %s %s", resp.StatusCode, method, path),
					Remediation: "Implement proper authorization checks for all HTTP methods",
				})
			}
		}
	}
}

func (s *Scanner) testAPIAuthzBypass(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Authz] Testing API authorization bypass")

	bypassTechniques := []struct {
		name    string
		headers map[string]string
	}{
		{"X-Forwarded-For", map[string]string{"X-Forwarded-For": "127.0.0.1"}},
		{"X-Original-URL", map[string]string{"X-Original-URL": "/admin"}},
		{"X-Rewrite-URL", map[string]string{"X-Rewrite-URL": "/admin"}},
		{"X-Custom-IP-Authorization", map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"}},
		{"X-Real-IP", map[string]string{"X-Real-IP": "127.0.0.1"}},
		{"Content-Type JSON", map[string]string{"Content-Type": "application/json"}},
		{"Method Override GET", map[string]string{"X-HTTP-Method-Override": "GET"}},
	}

	for _, path := range adminPaths {
		url := strings.TrimRight(target.URL, "/") + path
		for _, technique := range bypassTechniques {
			headers := make(map[string]string)
			for k, v := range technique.headers {
				headers[k] = v
			}

			resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
				Method:  "GET",
				URL:     url,
				Headers: headers,
			})
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				result.Findings = append(result.Findings, Finding{
					Type:        "authz-bypass",
					Severity:    "high",
					Title:       fmt.Sprintf("Authorization Bypass via %s", technique.name),
					Description: fmt.Sprintf("Admin endpoint accessible using header: %s", technique.name),
					URL:         url,
					Payload:     fmt.Sprintf("%v", technique.headers),
					Evidence:    fmt.Sprintf("HTTP %d with bypass header", resp.StatusCode),
					Remediation: "Do not trust client-supplied headers for authorization decisions",
				})
				s.KB.RecordTechnique("authz-bypass-"+technique.name, "authz", true)
			} else {
				s.KB.RecordTechnique("authz-bypass-"+technique.name, "authz", false)
			}
		}
	}
}
