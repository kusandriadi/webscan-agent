package scanner

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"red-team-agent/internal/config"
	"red-team-agent/internal/knowledge"
)

// RunDiscovery - Phase 2: Discovery
func (s *Scanner) RunDiscovery(ctx context.Context, target config.Target) *PhaseResult {
	start := time.Now()
	result := &PhaseResult{Phase: "Discovery"}

	log.Printf("[Discovery] Starting for %s", target.URL)

	// Directory/file brute force
	s.bruteForcePaths(ctx, target, result)

	// API endpoint discovery
	s.discoverAPIEndpoints(ctx, target, result)

	// Deep REST API endpoint discovery
	s.discoverDeepAPIEndpoints(ctx, target, result)

	// Parameter discovery
	s.discoverParameters(ctx, target, result)

	// Source code comments analysis
	s.analyzeComments(ctx, target, result)

	// HTTP method fuzzing on discovered endpoints
	s.testHTTPMethods(ctx, target, result)

	// JavaScript analysis for API endpoints
	s.analyzeJSForEndpoints(ctx, target, result)

	// Form detection and parameter discovery
	s.discoverForms(ctx, target, result)

	// GraphQL introspection
	s.testGraphQLIntrospection(ctx, target, result)

	result.Duration = time.Since(start)
	log.Printf("[Discovery] Completed for %s: %d findings, %d endpoints", target.URL, len(result.Findings), len(result.Endpoints))
	return result
}

var commonPaths = []string{
	// Admin
	"/admin", "/admin/login", "/administrator", "/admin/dashboard",
	"/wp-admin", "/phpmyadmin", "/adminer",
	// Config/backup
	"/.env", "/config.json", "/config.yml", "/config.yaml",
	"/backup.sql", "/dump.sql", "/database.sql",
	"/.git/config", "/.svn/entries", "/.hg/store",
	// API docs
	"/swagger.json", "/swagger-ui.html", "/api-docs",
	"/graphql", "/graphiql",
	"/openapi.json", "/api/swagger.json",
	// Debug
	"/debug", "/trace", "/metrics", "/healthz",
	"/.well-known/security.txt",
	// Upload
	"/upload", "/uploads", "/files",
	// Auth
	"/login", "/register", "/forgot-password", "/reset-password",
	"/api/auth/login", "/api/auth/register",
	// User
	"/profile", "/settings", "/dashboard", "/account",
	"/api/users", "/api/v1/users",
	// Common files
	"/robots.txt", "/sitemap.xml", "/crossdomain.xml",
	"/.htaccess", "/web.config", "/package.json",
	"/composer.json", "/Gemfile",
}

var apiPatterns = []string{
	"/api", "/api/v1", "/api/v2", "/api/v3",
	"/api/users", "/api/admin", "/api/config",
	"/rest", "/rest/api", "/graphql",
	"/v1", "/v2",
}

func (s *Scanner) bruteForcePaths(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Discovery] Brute forcing %d common paths", len(commonPaths))

	for _, path := range commonPaths {
		select {
		case <-ctx.Done():
			return
		default:
		}

		url := strings.TrimRight(target.URL, "/") + path
		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method:  "GET",
			URL:     url,
			Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
		})
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			ep := knowledge.Endpoint{
				URL:           url,
				Method:        "GET",
				DiscoveredAt:  time.Now(),
				DiscoveredBy:  "brute-force",
			}
			result.Endpoints = append(result.Endpoints, ep)

			// Check for sensitive files
			sensitivePaths := map[string]string{
				"/.env":           "high",
				"/.git/config":    "critical",
				"/config.json":    "high",
				"/backup.sql":     "critical",
				"/dump.sql":       "critical",
				"/phpmyadmin":     "high",
				"/adminer":        "high",
				"/swagger.json":   "medium",
				"/api-docs":       "medium",
			}
			if severity, ok := sensitivePaths[path]; ok {
				result.Findings = append(result.Findings, Finding{
					Type:        "sensitive-file",
					Severity:    severity,
					Title:       fmt.Sprintf("Sensitive File/Path Exposed: %s", path),
					Description: fmt.Sprintf("The sensitive path %s is publicly accessible", path),
					URL:         url,
					Evidence:    fmt.Sprintf("HTTP %d - file accessible", resp.StatusCode),
					Remediation: "Restrict access to sensitive files and directories",
				})
			}
		}
	}
}

func (s *Scanner) discoverAPIEndpoints(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Discovery] Discovering API endpoints")

	for _, pattern := range apiPatterns {
		url := strings.TrimRight(target.URL, "/") + pattern
		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method:  "GET",
			URL:     url,
			Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
		})
		if err != nil {
			continue
		}

		if resp.StatusCode != 404 {
			ep := knowledge.Endpoint{
				URL:           url,
				Method:        "GET",
				DiscoveredAt:  time.Now(),
				DiscoveredBy:  "api-discovery",
			}
			result.Endpoints = append(result.Endpoints, ep)

			// Check for API documentation
			if strings.Contains(resp.Body, "swagger") || strings.Contains(resp.Body, "openapi") {
				result.Findings = append(result.Findings, Finding{
					Type:        "api-docs",
					Severity:    "medium",
					Title:       "API Documentation Exposed",
					Description: "API documentation is publicly accessible, revealing API structure",
					URL:         url,
					Evidence:    "Swagger/OpenAPI documentation detected",
					Remediation: "Restrict access to API documentation in production",
				})
			}
		}
	}
}

func (s *Scanner) discoverParameters(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Discovery] Discovering parameters from known endpoints")

	// Check common query parameters on discovered endpoints
	commonParams := []string{
		"id", "page", "search", "q", "query", "user", "username",
		"file", "path", "url", "redirect", "return", "next",
		"callback", "format", "type", "sort", "order", "limit", "offset",
	}

	// Test on the base URL
	for _, param := range commonParams {
		p := knowledge.Parameter{
			Name: param,
			URL:  target.URL,
			Type: "query",
		}
		result.Parameters = append(result.Parameters, p)
	}
}

func (s *Scanner) analyzeComments(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Discovery] Analyzing source code comments")

	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
		Method:  "GET",
		URL:     target.URL,
		Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
	})
	if err != nil || resp.StatusCode != 200 {
		return
	}

	// Look for HTML comments
	body := resp.Body
	commentStart := strings.Index(body, "<!--")
	for commentStart != -1 {
		commentEnd := strings.Index(body[commentStart:], "-->")
		if commentEnd == -1 {
			break
		}
		comment := body[commentStart : commentStart+commentEnd+3]

		// Check for interesting comments
		interesting := []string{"password", "secret", "api", "key", "token", "admin", "debug", "todo", "fixme", "hack", "temp"}
		for _, keyword := range interesting {
			if strings.Contains(strings.ToLower(comment), keyword) {
				result.Findings = append(result.Findings, Finding{
					Type:        "info-disclosure",
					Severity:    "low",
					Title:       fmt.Sprintf("Interesting Comment: '%s'", keyword),
					Description: fmt.Sprintf("HTML comment contains potentially sensitive keyword: %s", keyword),
					URL:         target.URL,
					Evidence:    truncate(comment, 200),
					Remediation: "Remove sensitive comments from production code",
				})
				break
			}
		}

		body = body[commentStart+commentEnd+3:]
		commentStart = strings.Index(body, "<!--")
	}
}

// testHTTPMethods tests GET, POST, PUT, DELETE, PATCH, OPTIONS on every discovered endpoint
func (s *Scanner) testHTTPMethods(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Discovery] Testing HTTP methods on discovered endpoints")

	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
	endpoints := s.KB.Endpoints

	// Also test on the base URL and common paths
	testPaths := []string{""}
	if len(endpoints) == 0 {
		testPaths = append(testPaths, "/api", "/api/v1", "/users", "/admin")
	} else {
		for _, ep := range endpoints {
			path := strings.TrimPrefix(ep.URL, target.URL)
			if path != "" && path != "/" {
				testPaths = append(testPaths, path)
			}
		}
	}

	for _, path := range testPaths {
		url := strings.TrimRight(target.URL, "/") + path
		var allowedMethods []string

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

			// Record endpoint for non-404/405 responses
			if resp.StatusCode != 404 && resp.StatusCode != 405 && resp.StatusCode != 501 {
				allowedMethods = append(allowedMethods, method)
				ep := knowledge.Endpoint{
					URL:           url,
					Method:        method,
					DiscoveredAt:  time.Now(),
					DiscoveredBy:  "method-fuzzing",
				}
				result.Endpoints = append(result.Endpoints, ep)
			}

			// Check OPTIONS for Allow header
			if method == "OPTIONS" {
				if allow := getHeader(resp.Headers, "Allow"); allow != "" {
					result.Findings = append(result.Findings, Finding{
						Type:        "http-methods",
						Severity:    "info",
						Title:       fmt.Sprintf("HTTP Methods Allowed: %s", path),
						Description: fmt.Sprintf("Allow header reveals: %s", allow),
						URL:         url,
						Evidence:    fmt.Sprintf("Allow: %s", allow),
						Remediation: "Restrict HTTP methods to only those needed by the application",
					})
				}
			}
		}

		if len(allowedMethods) > 3 {
			result.Findings = append(result.Findings, Finding{
				Type:        "http-methods",
				Severity:    "low",
				Title:       fmt.Sprintf("Many HTTP Methods Accepted: %s", path),
				Description: fmt.Sprintf("Endpoint accepts %d methods: %s", len(allowedMethods), strings.Join(allowedMethods, ", ")),
				URL:         url,
				Evidence:    fmt.Sprintf("Methods: %s", strings.Join(allowedMethods, ", ")),
				Remediation: "Restrict HTTP methods to only those needed",
			})
		}

		// Record technique
		if len(allowedMethods) > 1 {
			s.KB.RecordTechnique("http-method-fuzzing", "discovery", true)
		}
	}
}

// discoverDeepAPIEndpoints tests comprehensive REST API patterns
func (s *Scanner) discoverDeepAPIEndpoints(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Discovery] Deep REST API endpoint discovery")

	patterns := GetAPIEndpointPatterns()
	baseURL := strings.TrimRight(target.URL, "/")

	for _, pattern := range patterns {
		select {
		case <-ctx.Done():
			return
		default:
		}

		url := baseURL + pattern
		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method:  "GET",
			URL:     url,
			Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
		})
		if err != nil {
			continue
		}

		if resp.StatusCode != 404 && resp.StatusCode != 502 && resp.StatusCode != 503 {
			ep := knowledge.Endpoint{
				URL:           url,
				Method:        "GET",
				DiscoveredAt:  time.Now(),
				DiscoveredBy:  "deep-api-discovery",
			}
			result.Endpoints = append(result.Endpoints, ep)

			// Check for API documentation
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "swagger") || strings.Contains(body, "openapi") {
				result.Findings = append(result.Findings, Finding{
					Type:        "api-docs",
					Severity:    "medium",
					Title:       fmt.Sprintf("API Documentation Exposed at %s", pattern),
					Description: "API documentation is publicly accessible",
					URL:         url,
					Evidence:    "Swagger/OpenAPI documentation detected",
					Remediation: "Restrict access to API documentation in production",
				})
			}

			// Check for JSON API responses
			ct := getHeader(resp.Headers, "Content-Type")
			if strings.Contains(ct, "application/json") && resp.StatusCode == 200 {
				s.KB.RecordTechnique("api-endpoint-found", "discovery", true)
			}
		}
	}
}

// analyzeJSForEndpoints extracts API endpoints from JavaScript
func (s *Scanner) analyzeJSForEndpoints(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Discovery] Analyzing JavaScript for API endpoints")

	baseURL := strings.TrimRight(target.URL, "/")

	// First, fetch the main page to find JS files
	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
		Method:  "GET",
		URL:     target.URL,
		Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
	})
	if err != nil || resp.StatusCode != 200 {
		return
	}

	// Extract script src paths from HTML
	scriptRegex := regexp.MustCompile(`<script[^>]+src="([^"]+)"`)
	matches := scriptRegex.FindAllStringSubmatch(resp.Body, -1)

	jsURLs := make(map[string]bool)
	for _, match := range matches {
		src := match[1]
		if strings.HasPrefix(src, "//") {
			src = "https:" + src
		} else if strings.HasPrefix(src, "/") {
			src = baseURL + src
		} else if !strings.HasPrefix(src, "http") {
			src = baseURL + "/" + src
		}
		jsURLs[src] = true
	}

	// Also check inline script tags for API endpoints
	inlineRegex := regexp.MustCompile(`<script[^>]*>([\s\S]*?)</script>`)
	inlineMatches := inlineRegex.FindAllStringSubmatch(resp.Body, -1)
	for _, m := range inlineMatches {
		s.extractEndpointsFromJS(m[1], baseURL, result)
	}

	// Fetch and analyze each JS file
	for jsURL := range jsURLs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		jsResp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method:  "GET",
			URL:     jsURL,
			Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
		})
		if err != nil || jsResp.StatusCode != 200 {
			continue
		}

		s.extractEndpointsFromJS(jsResp.Body, baseURL, result)

		// Check for sensitive strings in JS
		jsBody := strings.ToLower(jsResp.Body)
		sensitivePatterns := []struct {
			pattern string
			name    string
		}{
			{"api_key", "API Key"},
			{"api_secret", "API Secret"},
			{"authorization:", "Auth Header"},
			{"bearer ", "Bearer Token"},
			{"password", "Password"},
			{"secret_key", "Secret Key"},
			{"private_key", "Private Key"},
			{"aws_secret", "AWS Secret"},
		}
		for _, sp := range sensitivePatterns {
			if strings.Contains(jsBody, sp.pattern) {
				result.Findings = append(result.Findings, Finding{
					Type:        "info-disclosure",
					Severity:    "medium",
					Title:       fmt.Sprintf("Sensitive String in JavaScript: %s", sp.name),
					Description: fmt.Sprintf("Found %s reference in %s", sp.name, jsURL),
					URL:         jsURL,
					Evidence:    sp.pattern + " found in JS file",
					Remediation: "Remove sensitive data from client-side JavaScript",
				})
			}
		}
	}
}

// extractEndpointsFromJS finds API endpoints in JS code
func (s *Scanner) extractEndpointsFromJS(jsContent, baseURL string, result *PhaseResult) {
	// Patterns for fetch(), axios, XMLHttpRequest, and string URLs
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)fetch\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)axios\.[a-z]+\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)\.(?:get|post|put|delete|patch)\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)["'](/[a-z][a-z0-9/_-]*(?:/[a-z0-9/_-]+)*)["']`),
		regexp.MustCompile(`(?i)url:\s*["']([^"']+api[^"']*)["']`),
		regexp.MustCompile(`(?i)baseURL:\s*["']([^"']+)["']`),
	}

	seen := make(map[string]bool)
	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(jsContent, -1)
		for _, match := range matches {
			endpoint := match[1]
			if endpoint == "" || strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
				if strings.HasPrefix(endpoint, baseURL) {
					endpoint = strings.TrimPrefix(endpoint, baseURL)
				} else if strings.HasPrefix(endpoint, "http") {
					continue
				}
			}
			if !strings.HasPrefix(endpoint, "/") || len(endpoint) < 3 {
				continue
			}
			if seen[endpoint] {
				continue
			}
			seen[endpoint] = true

			url := baseURL + endpoint
		ep := knowledge.Endpoint{
				URL:           url,
				Method:        "GET",
				DiscoveredAt:  time.Now(),
				DiscoveredBy:  "js-analysis",
			}
			result.Endpoints = append(result.Endpoints, ep)
		}
	}
}

// discoverForms parses HTML pages for forms and extracts input parameters
func (s *Scanner) discoverForms(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Discovery] Discovering forms and parameters")

	// Fetch main page
	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
		Method:  "GET",
		URL:     target.URL,
		Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
	})
	if err != nil || resp.StatusCode != 200 {
		return
	}

	// Parse HTML forms
	formRegex := regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	forms := formRegex.FindAllStringSubmatch(resp.Body, -1)

	for i, formMatch := range forms {
		formHTML := formMatch[1]

		// Extract form action
		actionRegex := regexp.MustCompile(`action=["']?([^"'\s>]+)`)
		actionMatches := actionRegex.FindAllStringSubmatch(formMatch[0], 1)
		action := "/"
		if len(actionMatches) > 0 {
			action = actionMatches[0][1]
		}

		// Extract form method
		methodRegex := regexp.MustCompile(`method=["']?([^"'\s>]+)`)
		methodMatches := methodRegex.FindAllStringSubmatch(formMatch[0], 1)
		method := "GET"
		if len(methodMatches) > 0 {
			method = strings.ToUpper(methodMatches[0][1])
		}

		// Extract input fields
		inputRegex := regexp.MustCompile(`<input[^>]+name=["']?([^"'\s>]+)`)
		inputMatches := inputRegex.FindAllStringSubmatch(formHTML, -1)

		textareaRegex := regexp.MustCompile(`<textarea[^>]+name=["']?([^"'\s>]+)`)
		textareaMatches := textareaRegex.FindAllStringSubmatch(formHTML, -1)

		selectRegex := regexp.MustCompile(`<select[^>]+name=["']?([^"'\s>]+)`)
		selectMatches := selectRegex.FindAllStringSubmatch(formHTML, -1)

		formURL := target.URL
		if action != "" && action != "#" {
			if strings.HasPrefix(action, "/") {
				formURL = strings.TrimRight(target.URL, "/") + action
			} else if strings.HasPrefix(action, "http") {
				formURL = action
			}
		}

		// Record the form endpoint
		ep := knowledge.Endpoint{
			URL:           formURL,
			Method:        method,
			DiscoveredAt:  time.Now(),
			DiscoveredBy:  "form-discovery",
		}
		result.Endpoints = append(result.Endpoints, ep)

		// Record all input parameters
		allInputs := append(append(inputMatches, textareaMatches...), selectMatches...)
		for _, input := range allInputs {
			paramName := input[1]
			p := knowledge.Parameter{
				Name: paramName,
				URL:  formURL,
				Method: method,
				Type: "form",
			}
			result.Parameters = append(result.Parameters, p)
		}

		// Check for missing CSRF token
		hasCSRF := false
		for _, input := range allInputs {
			name := strings.ToLower(input[1])
			if strings.Contains(name, "csrf") || strings.Contains(name, "token") || strings.Contains(name, "_token") {
				hasCSRF = true
				break
			}
		}
		if method == "POST" && !hasCSRF {
			result.Findings = append(result.Findings, Finding{
				Type:        "csrf-missing",
				Severity:    "medium",
				Title:       fmt.Sprintf("Form #%d Missing CSRF Token", i+1),
				Description: fmt.Sprintf("POST form at %s has no CSRF token field", action),
				URL:         formURL,
				Evidence:    "No csrf/token/_token input field found in form",
				Remediation: "Add CSRF tokens to all state-changing forms",
			})
		}

		log.Printf("[Discovery] Found form #%d: %s %s with %d inputs", i+1, method, action, len(allInputs))
	}
}

// testGraphQLIntrospection tests for GraphQL endpoints and introspection
func (s *Scanner) testGraphQLIntrospection(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Discovery] Testing GraphQL introspection")

	baseURL := strings.TrimRight(target.URL, "/")
	graphqlPaths := []string{"/graphql", "/graphiql", "/api/graphql", "/query", "/v1/graphql"}

	for _, path := range graphqlPaths {
		select {
		case <-ctx.Done():
			return
		default:
		}

		url := baseURL + path

		// Try introspection query
		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method:  "POST",
			URL:     url,
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    GetGraphQLIntrospectionQuery(),
		})
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			body := strings.ToLower(resp.Body)
			if strings.Contains(body, "__schema") || strings.Contains(body, "querytype") || strings.Contains(body, "mutationtype") {
				result.Findings = append(result.Findings, Finding{
					Type:        "graphql-introspection",
					Severity:    "medium",
					Title:       "GraphQL Introspection Enabled",
					Description: fmt.Sprintf("GraphQL introspection is enabled at %s, exposing the full API schema", url),
					URL:         url,
					Evidence:    truncate(resp.Body, 500),
					Remediation: "Disable introspection in production GraphQL deployments",
				})

				ep := knowledge.Endpoint{
					URL:           url,
					Method:        "POST",
					DiscoveredAt:  time.Now(),
					DiscoveredBy:  "graphql-discovery",
				}
				result.Endpoints = append(result.Endpoints, ep)
				s.KB.RecordTechnique("graphql-introspection", "discovery", true)
			}
		}
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
