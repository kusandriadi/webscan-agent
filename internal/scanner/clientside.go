package scanner

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"red-team-agent/internal/config"
)

// RunClientSide — Phase 7: Client-Side security testing
func (s *Scanner) RunClientSide(ctx context.Context, target config.Target) *PhaseResult {
	start := time.Now()
	result := &PhaseResult{Phase: "Client-Side"}

	baseURL := strings.TrimRight(target.URL, "/")

	// CORS check
	result.Findings = append(result.Findings, s.testCORSClient(baseURL)...)
	// Clickjacking check
	result.Findings = append(result.Findings, s.testClickjackingClient(baseURL)...)
	// Open redirect
	result.Findings = append(result.Findings, s.testOpenRedirectClient(baseURL)...)
	// CSP analysis
	result.Findings = append(result.Findings, s.testCSPClient(baseURL)...)
	// Client-side prototype pollution
	s.testClientSidePrototypePollution(ctx, target, result)
	// postMessage security
	s.testPostMessage(ctx, target, result)
	// DOM Clobbering
	s.testDOMClobbering(ctx, target, result)

	result.Duration = time.Since(start)
	log.Printf("[Client-Side] Complete: %d findings", len(result.Findings))
	return result
}

func (s *Scanner) testCORSClient(baseURL string) []Finding {
	var findings []Finding
	originTests := []string{
		"https://evil.com",
		"http://localhost",
		"https://attacker.example.com",
	}

	for _, origin := range originTests {
		resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
			Method: "OPTIONS",
			URL:    baseURL,
			Headers: map[string]string{
				"Origin":                       origin,
				"Access-Control-Request-Method": "GET",
				"User-Agent":                   s.HTTPClient.UserAgent,
			},
		})
		if err != nil {
			continue
		}

		acao := getHeader(resp.Headers, "Access-Control-Allow-Origin")
		acac := getHeader(resp.Headers, "Access-Control-Allow-Credentials")

		if acao == "*" || acao == origin {
			severity := "medium"
			desc := fmt.Sprintf("CORS allows origin: %s", origin)
			if acac == "true" {
				severity = "high"
				desc += " with credentials"
			}
			findings = append(findings, Finding{
				Type:        "cors",
				Severity:    severity,
				Title:       "CORS Misconfiguration",
				Description: desc,
				URL:         baseURL,
				Evidence:    fmt.Sprintf("ACAO: %s, ACAC: %s", acao, acac),
				Remediation: "Restrict CORS to trusted origins only. Never use '*' with credentials.",
			})
		}
	}
	return findings
}

func (s *Scanner) testClickjackingClient(baseURL string) []Finding {
	var findings []Finding
	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
		Method:  "GET",
		URL:     baseURL,
		Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
	})
	if err != nil {
		return findings
	}

	xfo := getHeader(resp.Headers, "X-Frame-Options")
	csp := getHeader(resp.Headers, "Content-Security-Policy")

	if xfo == "" && !strings.Contains(csp, "frame-ancestors") {
		findings = append(findings, Finding{
			Type:        "clickjacking",
			Severity:    "medium",
			Title:       "Clickjacking Vulnerability",
			Description: "No X-Frame-Options or CSP frame-ancestors header. Page can be embedded in an iframe.",
			URL:         baseURL,
			Evidence:    fmt.Sprintf("X-Frame-Options: %q, CSP: %q", xfo, csp),
			Remediation: "Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors directive.",
		})
	}
	return findings
}

func (s *Scanner) testOpenRedirectClient(baseURL string) []Finding {
	var findings []Finding
	redirectParams := []string{"redirect", "url", "next", "return", "returnTo", "goto", "continue", "destination"}
	payloads := []string{
		"https://evil.com",
		"//evil.com",
		"/\\evil.com",
	}

	for _, param := range redirectParams {
		for _, payload := range payloads {
			url := fmt.Sprintf("%s/?%s=%s", baseURL, param, payload)
			// Disable redirect following for this test
			resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
				Method:  "GET",
				URL:     url,
				Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
			})
			if err != nil {
				continue
			}

			loc := getHeader(resp.Headers, "Location")
			if resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
				if strings.Contains(loc, "evil.com") {
					findings = append(findings, Finding{
						Type:        "open-redirect",
						Severity:    "medium",
						Title:       fmt.Sprintf("Open Redirect via '%s' parameter", param),
						Description: fmt.Sprintf("Parameter '%s' redirects to: %s", param, loc),
						URL:         url,
						Parameter:   param,
						Payload:     payload,
						Evidence:    fmt.Sprintf("Location: %s", loc),
						Remediation: "Validate and whitelist redirect destinations.",
					})
				}
			}
		}
	}
	return findings
}

func (s *Scanner) testCSPClient(baseURL string) []Finding {
	var findings []Finding
	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
		Method:  "GET",
		URL:     baseURL,
		Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
	})
	if err != nil {
		return findings
	}

	csp := getHeader(resp.Headers, "Content-Security-Policy")
	if csp == "" {
		findings = append(findings, Finding{
			Type:        "csp",
			Severity:    "low",
			Title:       "Missing Content Security Policy",
			Description: "No Content-Security-Policy header is set.",
			URL:         baseURL,
			Remediation: "Implement a strict Content Security Policy.",
		})
	} else {
		if strings.Contains(csp, "'unsafe-inline'") || strings.Contains(csp, "'unsafe-eval'") {
			findings = append(findings, Finding{
				Type:        "csp",
				Severity:    "low",
				Title:       "Weak Content Security Policy",
				Description: "CSP contains unsafe-inline or unsafe-eval directives.",
				URL:         baseURL,
				Evidence:    csp,
				Remediation: "Remove 'unsafe-inline' and 'unsafe-eval' from CSP.",
			})
		}
	}
	return findings
}

// testClientSidePrototypePollution checks for JS prototype pollution via client-side
func (s *Scanner) testClientSidePrototypePollution(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Client-Side] Testing client-side prototype pollution")

	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
		Method:  "GET",
		URL:     target.URL,
		Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
	})
	if err != nil || resp.StatusCode != 200 {
		return
	}

	body := resp.Body

	// Check for vulnerable patterns in JavaScript
	ppPatterns := []struct {
		pattern     string
		description string
	}{
		// Deep merge without hasOwnProperty check
		{`for\s*\(\s*var\s+\w+\s+in\s+\w+\s*\)\s*\{[^}]*\w+\[\w+\]\s*=\s*\w+\[\w+\]`, "Deep merge without hasOwnProperty check"},
		// _.merge, _.extend, $.extend
		{`(?:_\.merge|_\.extend|\$\.extend)\s*\(`, "Lodash/jQuery merge/extend without sanitization"},
		// Object.assign without filter
		{`Object\.assign\s*\(\s*\w+\s*,\s*\w+\s*\)`, "Object.assign without property filtering"},
		// Direct __proto__ assignment
		{`__proto__\s*[=:]`, "Direct __proto__ assignment"},
		// constructor.prototype
		{`constructor\s*\[\s*['"]prototype['"]\s*\]`, "constructor.prototype access"},
	}

	for _, pp := range ppPatterns {
		matched, _ := regexp.MatchString(pp.pattern, body)
		if matched {
			result.Findings = append(result.Findings, Finding{
				Type:        "client-prototype-pollution",
				Severity:    "medium",
				Title:       "Potential Client-Side Prototype Pollution",
				Description: fmt.Sprintf("JavaScript code contains pattern: %s", pp.description),
				URL:         target.URL,
				Evidence:    pp.pattern,
				Remediation: "Use Object.create(null) for data objects, sanitize keys before merging",
			})
			s.KB.RecordTechnique("client-pp", "client-side", true)
		}
	}
}

// testPostMessage checks for insecure postMessage handlers
func (s *Scanner) testPostMessage(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Client-Side] Testing postMessage security")

	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
		Method:  "GET",
		URL:     target.URL,
		Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
	})
	if err != nil || resp.StatusCode != 200 {
		return
	}

	body := resp.Body

	// Check for addEventListener("message", ...) without origin check
	messageListenerPattern := regexp.MustCompile(`(?i)addEventListener\s*\(\s*['"]message['"]\s*,`)
	if messageListenerPattern.MatchString(body) {
		// Check if there's an origin validation
		hasOriginCheck := strings.Contains(body, "event.origin") ||
			strings.Contains(body, "e.origin") ||
			strings.Contains(body, "msg.origin") ||
			strings.Contains(body, "message.origin")

		if !hasOriginCheck {
			result.Findings = append(result.Findings, Finding{
				Type:        "postmessage",
				Severity:    "medium",
				Title:       "Insecure postMessage Handler",
				Description: "addEventListener for 'message' events found without origin validation",
				URL:         target.URL,
				Evidence:    "message event listener without origin check",
				Remediation: "Always validate event.origin in message event handlers",
			})
			s.KB.RecordTechnique("postmessage", "client-side", true)
		} else {
			result.Findings = append(result.Findings, Finding{
				Type:        "postmessage",
				Severity:    "info",
				Title:       "postMessage Handler with Origin Check",
				Description: "addEventListener for 'message' events found with origin validation",
				URL:         target.URL,
				Evidence:    "message event listener with origin check detected",
				Remediation: "Ensure origin check is strict (=== not indexOf)",
			})
		}
	}

	// Check for window.postMessage usage
	postMessagePattern := regexp.MustCompile(`(?i)(?:window|parent|opener|top|frames)\[?\]?\.postMessage\s*\(`)
	if postMessagePattern.MatchString(body) {
		// Check if targetOrigin is '*'
		starPattern := regexp.MustCompile(`postMessage\s*\([^,]+,\s*['"]\*['"]\s*\)`)
		if starPattern.MatchString(body) {
			result.Findings = append(result.Findings, Finding{
				Type:        "postmessage-send",
				Severity:    "medium",
				Title:       "postMessage Sent with Wildcard Origin",
				Description: "postMessage is called with '*' as target origin, leaking data to any window",
				URL:         target.URL,
				Evidence:    "postMessage(..., '*') found",
				Remediation: "Specify exact target origin instead of '*' in postMessage calls",
			})
		}
	}
}

// testDOMClobbering checks for DOM clobbering vectors
func (s *Scanner) testDOMClobbering(ctx context.Context, target config.Target, result *PhaseResult) {
	log.Printf("[Client-Side] Testing DOM clobbering vectors")

	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
		Method:  "GET",
		URL:     target.URL,
		Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
	})
	if err != nil || resp.StatusCode != 200 {
		return
	}

	body := resp.Body

	// Check for DOM clobbering vulnerable patterns
	clobberPatterns := []struct {
		pattern     string
		description string
	}{
		// window.location used in decision making
		{`window\.location\s*[!=]==`, "window.location comparison (clobberable)"},
		// document.getElementById result not checked
		{`document\.(getElementById|querySelector)\s*\([^)]+\)\.\w+`, "DOM element property access without null check"},
		// Using named form elements as globals
		{`window\.(\w+)\s*[!=]==`, "window property comparison (can be clobbered by named elements)"},
		// document.cookie access
		{`document\.cookie`, "document.cookie access"},
	}

	for _, cp := range clobberPatterns {
		matched, _ := regexp.MatchString(cp.pattern, body)
		if matched {
			result.Findings = append(result.Findings, Finding{
				Type:        "dom-clobbering",
				Severity:    "low",
				Title:       "Potential DOM Clobbering Vector",
				Description: fmt.Sprintf("JavaScript code: %s", cp.description),
				URL:         target.URL,
				Evidence:    cp.pattern,
				Remediation: "Use explicit variable declarations and avoid relying on global DOM properties",
			})
			s.KB.RecordTechnique("dom-clobbering", "client-side", true)
		}
	}

	// Check for DOM-based sinks
	domSinks := []struct {
		pattern     string
		name        string
		severity    string
	}{
		{`innerHTML\s*=`, "innerHTML assignment", "medium"},
		{`outerHTML\s*=`, "outerHTML assignment", "medium"},
		{`document\.write\s*\(`, "document.write", "high"},
		{`eval\s*\(`, "eval()", "high"},
		{`setTimeout\s*\(\s*['"]`, "setTimeout with string", "medium"},
		{`setInterval\s*\(\s*['"]`, "setInterval with string", "medium"},
		{`new Function\s*\(`, "new Function()", "high"},
		{`\.insertAdjacentHTML\s*\(`, "insertAdjacentHTML", "medium"},
		{`location\s*=\s*[^=]`, "location assignment", "medium"},
		{`location\.href\s*=`, "location.href assignment", "medium"},
		{`location\.hash`, "location.hash usage", "low"},
		{`location\.search`, "location.search usage", "low"},
		{`document\.URL`, "document.URL usage", "low"},
		{`document\.documentURI`, "document.documentURI usage", "low"},
		{`document\.referrer`, "document.referrer usage", "low"},
		{`window\.name`, "window.name usage", "low"},
	}

	for _, sink := range domSinks {
		matched, _ := regexp.MatchString(sink.pattern, body)
		if matched {
			result.Findings = append(result.Findings, Finding{
				Type:        "dom-sink",
				Severity:    sink.severity,
				Title:       fmt.Sprintf("DOM Sink: %s", sink.name),
				Description: fmt.Sprintf("Potential DOM XSS sink found: %s. If source data flows here unvalidated, XSS is possible.", sink.name),
				URL:         target.URL,
				Evidence:    sink.pattern,
				Remediation: "Sanitize all data before passing to DOM manipulation functions",
			})
		}
	}
}
