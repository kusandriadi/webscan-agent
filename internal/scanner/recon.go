package scanner

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"red-team-agent/internal/config"
	"red-team-agent/internal/knowledge"
)

// RunRecon - Phase 1: Reconnaissance
func (s *Scanner) RunRecon(ctx context.Context, target config.Target) *PhaseResult {
	start := time.Now()
	result := &PhaseResult{Phase: "Reconnaissance"}

	log.Printf("[Recon] Starting reconnaissance for %s", target.URL)

	// HTTP fingerprinting
	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
		Method:  "GET",
		URL:     target.URL,
		Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
	})
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("HTTP request failed: %v", err))
		result.Duration = time.Since(start)
		return result
	}

	s.CheckSlowResponse(resp)

	// Analyze response headers for tech stack
	s.analyzeHeaders(resp, target)

	// Check robots.txt
	s.checkRobotsTxt(ctx, target, result)

	// Check sitemap.xml
	s.checkSitemapXML(ctx, target, result)

	// SSL/TLS check
	s.checkTLS(target, result)

	// JS file analysis
	s.analyzeJSFiles(ctx, target, result)

	// Response behavior analysis
	s.analyzeResponseBehavior(ctx, target, result)

	result.Duration = time.Since(start)
	log.Printf("[Recon] Completed for %s: %d findings, %d endpoints", target.URL, len(result.Findings), len(result.Endpoints))
	return result
}

func (s *Scanner) analyzeHeaders(resp *HTTPResponse, target config.Target) {
	// Server header
	if server := getHeader(resp.Headers, "Server"); server != "" {
		s.KB.Profile.ServerType = server
		s.KB.Profile.AddTech(server, "", "Server header")
		log.Printf("[Recon] Server: %s", server)
	}

	// X-Powered-By
	if xpb := getHeader(resp.Headers, "X-Powered-By"); xpb != "" {
		s.KB.Profile.AddTech(xpb, "", "X-Powered-By header")
		log.Printf("[Recon] Powered-By: %s", xpb)
	}

	// Framework detection from cookies
	for _, cookie := range flattenHeaders(resp.Headers) {
		if strings.Contains(strings.ToLower(cookie), "session") {
			s.KB.Profile.AuthMechanism = "cookie-session"
		}
		if strings.Contains(strings.ToLower(cookie), "csrf") {
			s.KB.Profile.AddTech("CSRF Protection", "", "cookie")
		}
		if strings.Contains(strings.ToLower(cookie), "laravel") {
			s.KB.Profile.Framework = "Laravel"
			s.KB.Profile.AddTech("Laravel", "", "cookie")
		}
		if strings.Contains(strings.ToLower(cookie), "phpsessid") {
			s.KB.Profile.AddTech("PHP", "", "cookie")
		}
		if strings.Contains(strings.ToLower(cookie), "jsessionid") {
			s.KB.Profile.AddTech("Java/Tomcat", "", "cookie")
		}
		if strings.Contains(strings.ToLower(cookie), "asp.net_sessionid") {
			s.KB.Profile.AddTech("ASP.NET", "", "cookie")
		}
		if strings.Contains(strings.ToLower(cookie), "rack.session") {
			s.KB.Profile.Framework = "Ruby on Rails"
			s.KB.Profile.AddTech("Ruby on Rails", "", "cookie")
		}
	}
}

func (s *Scanner) checkRobotsTxt(ctx context.Context, target config.Target, result *PhaseResult) {
	robotsURL := strings.TrimRight(target.URL, "/") + "/robots.txt"
	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
		Method: "GET",
		URL:    robotsURL,
	})
	if err != nil || resp.StatusCode != 200 {
		return
	}

	lines := strings.Split(resp.Body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Disallow:") || strings.HasPrefix(line, "Allow:") {
			path := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			if path != "" && path != "/" {
				ep := knowledge.Endpoint{
					URL:           target.URL + path,
					Method:        "GET",
					DiscoveredAt:  time.Now(),
					DiscoveredBy:  "robots.txt",
				}
				result.Endpoints = append(result.Endpoints, ep)
			}
		}
	}
	log.Printf("[Recon] robots.txt: found %d paths", len(result.Endpoints))
}

func (s *Scanner) checkSitemapXML(ctx context.Context, target config.Target, result *PhaseResult) {
	sitemapURL := strings.TrimRight(target.URL, "/") + "/sitemap.xml"
	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
		Method: "GET",
		URL:    sitemapURL,
	})
	if err != nil || resp.StatusCode != 200 {
		return
	}

	// Simple XML parsing - extract URLs
	urls := extractXMLURLs(resp.Body)
	for _, u := range urls {
		ep := knowledge.Endpoint{
			URL:           u,
			Method:        "GET",
			DiscoveredAt:  time.Now(),
			DiscoveredBy:  "sitemap.xml",
		}
		result.Endpoints = append(result.Endpoints, ep)
	}
	log.Printf("[Recon] sitemap.xml: found %d URLs", len(urls))
}

func (s *Scanner) checkTLS(target config.Target, result *PhaseResult) {
	if !strings.HasPrefix(target.URL, "https://") {
		result.Findings = append(result.Findings, Finding{
			Type:        "info-disclosure",
			Severity:    "medium",
			Title:       "No TLS/HTTPS",
			Description: "Target is not using HTTPS - all communication is unencrypted",
			URL:         target.URL,
			Remediation: "Enable TLS/HTTPS for all communications",
		})
		return
	}
	// In production: actual TLS certificate check, cipher suite analysis, etc.
	s.KB.Profile.TLSInfo = "HTTPS enabled"
}

func (s *Scanner) analyzeJSFiles(ctx context.Context, target config.Target, result *PhaseResult) {
	// In production: fetch HTML page, parse script tags, analyze JS content
	// for API keys, endpoints, secrets
	commonJSPaths := []string{"/static/js/app.js", "/js/main.js", "/assets/app.js", "/static/main.js"}
	for _, path := range commonJSPaths {
		jsURL := strings.TrimRight(target.URL, "/") + path
		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{Method: "GET", URL: jsURL})
		if err == nil && resp.StatusCode == 200 {
			// Check for secrets patterns
			checks := []struct {
				pattern string
				name    string
			}{
				{"api_key", "API Key"},
				{"secret", "Secret"},
				{"password", "Password"},
				{"token", "Token"},
				{"authorization", "Authorization"},
			}
			for _, check := range checks {
				if strings.Contains(strings.ToLower(resp.Body), check.pattern) {
					result.Findings = append(result.Findings, Finding{
						Type:        "info-disclosure",
						Severity:    "medium",
						Title:       fmt.Sprintf("Potential %s in JavaScript", check.name),
						Description: fmt.Sprintf("Found potential %s reference in %s", check.name, jsURL),
						URL:         jsURL,
						Evidence:    check.pattern + " found in JS file",
						Remediation: "Remove sensitive data from client-side JavaScript",
					})
				}
			}
		}
	}
}

func (s *Scanner) analyzeResponseBehavior(ctx context.Context, target config.Target, result *PhaseResult) {
	// Test 404 response
	nonExistURL := strings.TrimRight(target.URL, "/") + "/this-page-should-not-exist-404-test-abc123"
	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{Method: "GET", URL: nonExistURL})
	if err == nil {
		// Check if error page reveals tech stack
		body := strings.ToLower(resp.Body)
		leaks := []struct {
			pattern string
			tech    string
		}{
			{"stack trace", "Stack Trace"},
			{"exception", "Exception Details"},
			{"debug", "Debug Mode"},
			{"traceback", "Python Traceback"},
			{"apache", "Apache"},
			{"nginx", "Nginx"},
			{"iis", "IIS"},
		}
		for _, leak := range leaks {
			if strings.Contains(body, leak.pattern) {
				result.Findings = append(result.Findings, Finding{
					Type:        "info-disclosure",
					Severity:    "low",
					Title:       fmt.Sprintf("Information Disclosure in Error Page (%s)", leak.tech),
					Description: fmt.Sprintf("Error page reveals %s information", leak.tech),
					URL:         nonExistURL,
					Evidence:    leak.pattern + " found in error page",
					Remediation: "Use custom error pages that don't reveal server details",
				})
			}
		}
	}
}

// Helper functions
func getHeader(headers map[string][]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func flattenHeaders(headers map[string][]string) []string {
	var result []string
	for k := range headers {
		result = append(result, k)
	}
	return result
}

func extractXMLURLs(xml string) []string {
	var urls []string
	for _, line := range strings.Split(xml, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "<loc>") && strings.HasSuffix(line, "</loc>") {
			url := strings.TrimPrefix(line, "<loc>")
			url = strings.TrimSuffix(url, "</loc>")
			url = strings.TrimSpace(url)
			if url != "" {
				urls = append(urls, url)
			}
		}
	}
	return urls
}
