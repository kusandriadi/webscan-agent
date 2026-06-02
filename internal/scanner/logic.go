package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"red-team-agent/internal/config"
	"red-team-agent/internal/knowledge"
)

// RunLogic — Phase 6: Logic & Business Flow testing
func (s *Scanner) RunLogic(ctx context.Context, target config.Target) *PhaseResult {
	start := time.Now()
	result := &PhaseResult{Phase: "Logic"}

	baseURL := strings.TrimRight(target.URL, "/")

	// Rate limit bypass
	result.Findings = append(result.Findings, s.testRateLimitBypassLogic(ctx, baseURL)...)
	// Parameter tampering
	result.Findings = append(result.Findings, s.testParamTamperingLogic(ctx, baseURL)...)
	// Force browsing
	result.Findings = append(result.Findings, s.testForceBrowsingLogic(ctx, baseURL)...)
	// Race conditions
	s.testRaceCondition(ctx, target, result)
	// IDOR in API endpoints
	s.testIDORInAPI(ctx, target, result)
	// HTTP method bypass
	s.testHTTPMethodBypass(ctx, target, result)
	// Mass assignment
	s.testMassAssignment(ctx, target, result)

	result.Duration = time.Since(start)
	log.Printf("[Logic] Complete: %d findings", len(result.Findings))
	return result
}

func (s *Scanner) testRateLimitBypassLogic(ctx context.Context, baseURL string) []Finding {
	var findings []Finding
	endpoint := baseURL + "/login"

	successCount := 0
	for i := 0; i < 20; i++ {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method: "POST",
			URL:    endpoint,
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
				"User-Agent":   s.HTTPClient.UserAgent,
			},
			Body: "username=test&password=wrong",
		})
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			successCount++
		}
		time.Sleep(50 * time.Millisecond)
	}

	if successCount >= 15 {
		findings = append(findings, Finding{
			Type:        "rate-limit",
			Severity:    "medium",
			Title:       "Missing Rate Limiting on Login",
			Description: "Login endpoint accepts rapid successive requests without rate limiting.",
			URL:         endpoint,
			Remediation: "Implement rate limiting (e.g., 5 attempts per minute per IP).",
		})
	}
	return findings
}

func (s *Scanner) testParamTamperingLogic(ctx context.Context, baseURL string) []Finding {
	var findings []Finding
	tamperParams := []struct {
		param string
		value string
	}{
		{"price", "0.01"},
		{"role", "admin"},
		{"isAdmin", "true"},
		{"admin", "1"},
		{"debug", "true"},
		{"access_level", "99"},
	}

	for _, tp := range tamperParams {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method: "GET",
			URL:    fmt.Sprintf("%s/?%s=%s", baseURL, tp.param, tp.value),
			Headers: map[string]string{
				"User-Agent": s.HTTPClient.UserAgent,
			},
		})
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 {
			findings = append(findings, Finding{
				Type:        "param-tamper",
				Severity:    "low",
				Title:       fmt.Sprintf("Parameter Tampering: %s=%s", tp.param, tp.value),
				Description: fmt.Sprintf("Server accepted parameter %s with value %s without validation.", tp.param, tp.value),
				URL:         fmt.Sprintf("%s/?%s=%s", baseURL, tp.param, tp.value),
				Parameter:   tp.param,
				Payload:     tp.value,
				Remediation: "Validate and sanitize all user-supplied parameters server-side.",
			})
		}
	}
	return findings
}

func (s *Scanner) testForceBrowsingLogic(ctx context.Context, baseURL string) []Finding {
	var findings []Finding
	paths := []string{
		"/admin/delete-user", "/admin/config", "/admin/export",
		"/api/internal", "/api/debug", "/api/config",
		"/management", "/console", "/actuator/shutdown",
	}

	for _, path := range paths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

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
				Type:        "force-browse",
				Severity:    "medium",
				Title:       "Force Browsing: " + path,
				Description: "Endpoint accessible via direct URL access.",
				URL:         url,
				Remediation: "Restrict access to internal endpoints.",
			})
		}
	}
	return findings
}

// testRaceCondition sends concurrent requests to find race conditions
func (s *Scanner) testRaceCondition(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Logic] Testing Race Conditions")

	baseURL := strings.TrimRight(target.URL, "/")
	raceTests := GetRaceConditionPayloads()

	// Also generate from discovered endpoints
	for _, ep := range s.KB.Endpoints {
		if ep.Method == "POST" || ep.Method == "PUT" || ep.Method == "PATCH" {
			// Only add if not already covered
			raceTests = append(raceTests, RaceConditionTest{
				Endpoint:    strings.TrimPrefix(ep.URL, baseURL),
				Method:      ep.Method,
				Body:        `{}`,
				Concurrency: 15,
				Name:        fmt.Sprintf("Race on %s %s", ep.Method, ep.URL),
			})
		}
	}

	for _, test := range raceTests {
		select {
		case <-ctx.Done():
			return
		default:
		}

		url := baseURL + test.Endpoint

		// First check if endpoint exists
		checkResp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method:  test.Method,
			URL:     url,
			Headers: map[string]string{"Content-Type": "application/json", "User-Agent": s.HTTPClient.UserAgent},
			Body:    test.Body,
		})
		if err != nil || (checkResp.StatusCode != 200 && checkResp.StatusCode != 201 && checkResp.StatusCode != 400) {
			continue
		}

		// Send concurrent requests
		var wg sync.WaitGroup
		results := make(chan *HTTPResponse, test.Concurrency)
		errors := make(chan error, test.Concurrency)

		for i := 0; i < test.Concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
					Method:  test.Method,
					URL:     url,
					Headers: map[string]string{"Content-Type": "application/json", "User-Agent": s.HTTPClient.UserAgent},
					Body:    test.Body,
				})
				if err != nil {
					errors <- err
					return
				}
				results <- resp
			}()
		}
		wg.Wait()
		close(results)
		close(errors)

		// Analyze results
		successCount := 0
		for resp := range results {
			if resp.StatusCode == 200 || resp.StatusCode == 201 {
				successCount++
			}
		}

		// If more than 1 success, potential race condition
		if successCount > 1 {
			result.Findings = append(result.Findings, Finding{
				Type:        "race-condition",
				Severity:    "high",
				Title:       fmt.Sprintf("Race Condition: %s", test.Name),
				Description: fmt.Sprintf("Endpoint %s processed %d/%d concurrent requests successfully. Only 1 should succeed.", url, successCount, test.Concurrency),
				URL:         url,
				Payload:     test.Body,
				Evidence:    fmt.Sprintf("%d successes out of %d concurrent requests", successCount, test.Concurrency),
				Remediation: "Implement proper locking mechanisms and idempotency checks for state-changing operations",
			})
			s.KB.RecordTechnique("race-condition", "logic", true)
		} else {
			s.KB.RecordTechnique("race-condition", "logic", false)
		}
	}
}

// testIDORInAPI tests IDOR with different IDs on API endpoints
func (s *Scanner) testIDORInAPI(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Logic] Testing IDOR in API endpoints")

	baseURL := strings.TrimRight(target.URL, "/")

	// ID patterns to test
	idorPatterns := []struct {
		path   string
		method string
	}{
		// Users
		{"/api/users/{id}", "GET"},
		{"/api/v1/users/{id}", "GET"},
		{"/api/v1/users/{id}/profile", "GET"},
		{"/api/v1/users/{id}/settings", "GET"},
		{"/api/v1/users/{id}/posts", "GET"},
		// Orders/transactions
		{"/api/orders/{id}", "GET"},
		{"/api/v1/orders/{id}", "GET"},
		{"/api/v1/transactions/{id}", "GET"},
		// Documents/files
		{"/api/documents/{id}", "GET"},
		{"/api/v1/files/{id}", "GET"},
		{"/api/v1/uploads/{id}", "GET"},
		// Messages
		{"/api/messages/{id}", "GET"},
		{"/api/v1/messages/{id}", "GET"},
		// Admin actions
		{"/api/users/{id}", "PUT"},
		{"/api/users/{id}", "DELETE"},
		{"/api/v1/users/{id}", "PUT"},
		{"/api/v1/users/{id}", "DELETE"},
	}

	ids := []string{"1", "2", "3", "999", "0", "-1"}
	baselineResponses := make(map[string]int) // path -> status code for baseline

	for _, pattern := range idorPatterns {
		for _, id := range ids {
			select {
			case <-ctx.Done():
				return
			default:
			}

			path := strings.ReplaceAll(pattern.path, "{id}", id)
			url := baseURL + path

			resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
				Method:  pattern.method,
				URL:     url,
				Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
			})
			if err != nil {
				continue
			}

			// Store baseline (first ID response)
			if _, exists := baselineResponses[pattern.path]; !exists {
				baselineResponses[pattern.path] = resp.StatusCode
			}

			// If we get a 200 for sequential IDs, flag IDOR
			if resp.StatusCode == 200 {
				body := strings.ToLower(resp.Body)
				hasUserData := strings.Contains(body, "email") ||
					strings.Contains(body, "name") ||
					strings.Contains(body, "username") ||
					strings.Contains(body, "phone") ||
					strings.Contains(body, "address") ||
					strings.Contains(body, "password") ||
					strings.Contains(body, "token") ||
					strings.Contains(body, "order") ||
					strings.Contains(body, "amount") ||
					strings.Contains(body, "message")

				if hasUserData {
					result.Findings = append(result.Findings, Finding{
						Type:        "idor-api",
						Severity:    "high",
						Title:       fmt.Sprintf("IDOR in API: %s %s", pattern.method, path),
						Description: fmt.Sprintf("User/resource data accessible at %s without authorization check (ID: %s)", path, id),
						URL:         url,
						Parameter:   "id",
						Payload:     id,
						Evidence:    fmt.Sprintf("HTTP %d returned user data for ID %s", resp.StatusCode, id),
						Remediation: "Implement proper authorization: verify requesting user owns the resource",
					})
					s.KB.RecordTechnique("idor-api", "logic", true)
				}

				// Record as discovered endpoint
				result.Endpoints = append(result.Endpoints, knowledge.Endpoint{
					URL:           url,
					Method:        pattern.method,
					DiscoveredAt:  time.Now(),
					DiscoveredBy:  "idor-testing",
				})
			}
		}
	}
}

// testHTTPMethodBypass tries accessing protected endpoints with different methods
func (s *Scanner) testHTTPMethodBypass(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Logic] Testing HTTP method bypass")

	baseURL := strings.TrimRight(target.URL, "/")
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

	protectedPaths := []string{
		"/admin", "/admin/users", "/admin/settings",
		"/api/admin", "/api/v1/admin",
		"/dashboard", "/profile", "/settings",
		"/api/users/me", "/api/v1/users/me",
		"/api/users/1", "/api/v1/users/1",
	}

	for _, path := range protectedPaths {
		url := baseURL + path
		var blockedMethods []string
		var acceptedMethods []string
		responses := make(map[string]int)

		for _, method := range methods {
			select {
			case <-ctx.Done():
				return
			default:
			}

			resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
				Method:  method,
				URL:     url,
				Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
			})
			if err != nil {
				continue
			}
			responses[method] = resp.StatusCode

			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				blockedMethods = append(blockedMethods, method)
			} else if resp.StatusCode == 200 || resp.StatusCode == 201 {
				acceptedMethods = append(acceptedMethods, method)
			}
		}

		// If some methods are blocked but others accepted → bypass
		if len(blockedMethods) > 0 && len(acceptedMethods) > 0 {
			result.Findings = append(result.Findings, Finding{
				Type:        "method-bypass",
				Severity:    "high",
				Title:       fmt.Sprintf("HTTP Method Bypass at %s", path),
				Description: fmt.Sprintf("Access control is method-dependent. Blocked: %v, Accepted: %v", blockedMethods, acceptedMethods),
				URL:         url,
				Evidence:    fmt.Sprintf("Method responses: %v", responses),
				Remediation: "Apply consistent authorization checks regardless of HTTP method",
			})
			s.KB.RecordTechnique("method-bypass", "logic", true)
		}
	}
}

// testMassAssignment tries adding extra JSON fields in POST/PUT requests
func (s *Scanner) testMassAssignment(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Logic] Testing Mass Assignment")

	baseURL := strings.TrimRight(target.URL, "/")

	// Target endpoints for mass assignment
	maEndpoints := []struct {
		path   string
		method string
		body   string
	}{
		{"/api/users", "POST", `{"username":"testuser","email":"test@test.com"}`},
		{"/api/v1/users", "POST", `{"username":"testuser","email":"test@test.com"}`},
		{"/api/register", "POST", `{"username":"testuser","email":"test@test.com","password":"Test1234!"}`},
		{"/api/v1/register", "POST", `{"username":"testuser","email":"test@test.com","password":"Test1234!"}`},
		{"/api/profile", "PUT", `{"name":"Test User"}`},
		{"/api/v1/profile", "PUT", `{"name":"Test User"}`},
		{"/api/users/1", "PUT", `{"name":"Test User"}`},
		{"/api/v1/users/1", "PUT", `{"name":"Test User"}`},
	}

	maPayloads := GetMassAssignmentPayloads()

	for _, ep := range maEndpoints {
		for _, maPayload := range maPayloads {
			select {
			case <-ctx.Done():
				return
			default:
			}

			url := baseURL + ep.path

			// Merge extra fields into the base body
			var baseBody map[string]interface{}
			if err := json.Unmarshal([]byte(ep.body), &baseBody); err != nil {
				continue
			}

			// Add mass assignment fields
			for k, v := range maPayload {
				if extra, ok := v.(map[string]interface{}); ok {
					for ek, ev := range extra {
						baseBody[k+"_"+ek] = ev
						// Also try flat injection
						baseBody[ek] = ev
					}
				}
			}

			mergedBody, _ := json.Marshal(baseBody)

			// First, send normal request to get baseline
			normalResp, err := s.HTTPClient.MakeRequest(HTTPRequest{
				Method:  ep.method,
				URL:     url,
				Headers: map[string]string{"Content-Type": "application/json", "User-Agent": s.HTTPClient.UserAgent},
				Body:    ep.body,
			})
			if err != nil {
				continue
			}

			// Send request with extra fields
			maResp, err := s.HTTPClient.MakeRequest(HTTPRequest{
				Method:  ep.method,
				URL:     url,
				Headers: map[string]string{"Content-Type": "application/json", "User-Agent": s.HTTPClient.UserAgent},
				Body:    string(mergedBody),
			})
			if err != nil {
				continue
			}

			// Compare responses
			maBody := strings.ToLower(maResp.Body)
			if maResp.StatusCode == 200 || maResp.StatusCode == 201 {
				// Check if extra fields were accepted
				if strings.Contains(maBody, "admin") || strings.Contains(maBody, "role") ||
					strings.Contains(maBody, "premium") || strings.Contains(maBody, "verified") {
					if normalResp.StatusCode != 200 && normalResp.StatusCode != 201 {
						// Only the mass assignment request succeeded
						result.Findings = append(result.Findings, Finding{
							Type:        "mass-assignment",
							Severity:    "high",
							Title:       fmt.Sprintf("Mass Assignment at %s", ep.path),
							Description: "Extra JSON fields in request body are processed by the server, allowing privilege escalation",
							URL:         url,
							Payload:     string(mergedBody),
							Evidence:    fmt.Sprintf("Normal: HTTP %d, With extra fields: HTTP %d", normalResp.StatusCode, maResp.StatusCode),
							Remediation: "Whitelist allowed fields in the API layer. Use DTOs to explicitly define accepted fields",
						})
						s.KB.RecordTechnique("mass-assignment", "logic", true)
					}
				}
			}
		}
	}
}
