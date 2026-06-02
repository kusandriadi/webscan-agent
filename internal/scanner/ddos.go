package scanner

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"red-team-agent/internal/config"
)

// RunDDoS — Phase 9: DDoS Simulation & Stress Testing
func (s *Scanner) RunDDoS(ctx context.Context, target config.Target) (result *PhaseResult) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[DDoS] Panic recovered: %v", r)
			if result == nil {
				result = &PhaseResult{Phase: "DDoS Simulation"}
			}
		}
	}()
	start := time.Now()
	result = &PhaseResult{Phase: "DDoS Simulation"}

	baseURL := strings.TrimRight(target.URL, "/")
	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("parse URL: %v", err))
		result.Duration = time.Since(start)
		return result
	}
	host := parsedURL.Host
	if !strings.Contains(host, ":") {
		if parsedURL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	// Test 1: Slowloris
	result.Findings = append(result.Findings, s.testSlowloris(ctx, host, parsedURL.Scheme)...)

	// Test 2: HTTP Flood
	result.Findings = append(result.Findings, s.testHTTPFlood(ctx, baseURL)...)

	// Test 3: Amplification Check
	result.Findings = append(result.Findings, s.testAmplification(ctx, baseURL)...)

	// Test 4: Connection Exhaustion
	result.Findings = append(result.Findings, s.testConnectionExhaustion(ctx, host, parsedURL.Scheme)...)

	// Test 5: Slow POST (R.U.D.Y.)
	result.Findings = append(result.Findings, s.testSlowPOST(ctx, baseURL)...)

	result.Duration = time.Since(start)
	log.Printf("[DDoS] Complete: %d findings", len(result.Findings))
	return result
}

// testSlowloris opens connections, sends partial headers slowly.
// If server keeps connections open for 30s → vulnerable.
func (s *Scanner) testSlowloris(ctx context.Context, host, scheme string) []Finding {
	var findings []Finding
	log.Printf("[DDoS] Testing Slowloris vulnerability")

	network := "tcp"
	if scheme == "https" {
		network = "tcp" // we'll handle TLS below
	}

	const numConns = 10
	const waitDuration = 15 * time.Second
	ctxTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var aliveCount int64

	var wg sync.WaitGroup
	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			dialer := net.Dialer{Timeout: 10 * time.Second}
			var conn net.Conn
			var err error

			if scheme == "https" {
				// For HTTPS, we just test at TCP level (TLS handshake would add overhead)
				// We still use raw TCP to test slow header delivery
				conn, err = dialer.DialContext(ctxTimeout, network, host)
			} else {
				conn, err = dialer.DialContext(ctxTimeout, network, host)
			}
			if err != nil {
				return
			}
			defer conn.Close()

			// Send partial HTTP request
			partialReq := "GET / HTTP/1.1\r\nHost: " + strings.Split(host, ":")[0] + "\r\nX-Test-A: test\r\n"
			_, err = conn.Write([]byte(partialReq))
			if err != nil {
				return
			}

			// Set deadline for the wait period
			conn.SetDeadline(time.Now().Add(waitDuration + 5*time.Second))

			// Send additional headers slowly
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()

			for sent := 0; sent < 4; sent++ {
				select {
				case <-ctxTimeout.Done():
					return
				case <-ticker.C:
					_, err := conn.Write([]byte(fmt.Sprintf("X-Keep-%d: alive\r\n", idx)))
					if err != nil {
						return // connection was closed by server — good
					}
				}
			}

			// If we got here, the connection is still alive after slow headers
			atomic.AddInt64(&aliveCount, 1)
		}(i)
	}

	wg.Wait()

	alive := atomic.LoadInt64(&aliveCount)
	if alive >= int64(numConns)/2 {
		findings = append(findings, Finding{
			Type:        "slowloris",
			Severity:    "medium",
			Title:       "Slowloris Vulnerability",
			Description: fmt.Sprintf("Server kept %d/%d connections open during slow header delivery. Vulnerable to Slowloris DoS attack.", alive, numConns),
			URL:         scheme + "://" + host,
			Evidence:    fmt.Sprintf("Connections alive after %v of slow headers: %d/%d", waitDuration, alive, numConns),
			Remediation: "Configure server to close idle connections quickly. Use reverse proxies with connection timeouts. Implement request rate limiting.",
		})
	} else {
		findings = append(findings, Finding{
			Type:        "slowloris",
			Severity:    "info",
			Title:       "Slowloris: Server Resistant",
			Description: fmt.Sprintf("Server closed idle connections. Only %d/%d remained open.", alive, numConns),
			URL:         scheme + "://" + host,
			Evidence:    fmt.Sprintf("Alive connections: %d/%d", alive, numConns),
			Remediation: "No action needed.",
		})
	}

	return findings
}

// testHTTPFlood sends 100 rapid concurrent requests and measures server degradation.
func (s *Scanner) testHTTPFlood(ctx context.Context, baseURL string) []Finding {
	var findings []Finding
	log.Printf("[DDoS] Testing HTTP Flood resilience")

	const totalRequests = 100
	const concurrency = 20

	ctxTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var (
		wg           sync.WaitGroup
		mu           sync.Mutex
		errors5xx    int
		timeouts     int
		minDuration  time.Duration = 24 * time.Hour
		maxDuration  time.Duration
		totalDuration time.Duration
		successCount int
	)

	sem := make(chan struct{}, concurrency)

	for i := 0; i < totalRequests; i++ {
		select {
		case <-ctxTimeout.Done():
			break
		default:
		}

		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
				Method:  "GET",
				URL:     baseURL + "/",
				Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
			})

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				timeouts++
				return
			}
			totalDuration += resp.Duration
			if resp.Duration < minDuration {
				minDuration = resp.Duration
			}
			if resp.Duration > maxDuration {
				maxDuration = resp.Duration
			}
			successCount++

			if resp.StatusCode >= 500 {
				errors5xx++
			}
		}()
	}
	wg.Wait()

	var avgDuration time.Duration
	if successCount > 0 {
		avgDuration = totalDuration / time.Duration(successCount)
	}

	// Add info finding with stats
	findings = append(findings, Finding{
		Type:        "http-flood-stats",
		Severity:    "info",
		Title:       "HTTP Flood Statistics",
		Description: fmt.Sprintf("Sent %d requests with %d concurrency. Success: %d, Timeouts: %d, 5xx: %d", totalRequests, concurrency, successCount, timeouts, errors5xx),
		URL:         baseURL,
		Evidence:    fmt.Sprintf("Min: %v, Max: %v, Avg: %v", minDuration.Round(time.Millisecond), maxDuration.Round(time.Millisecond), avgDuration.Round(time.Millisecond)),
		Remediation: "Monitor response times under load.",
	})

	if errors5xx > 5 || timeouts > 20 {
		findings = append(findings, Finding{
			Type:        "http-flood-degradation",
			Severity:    "high",
			Title:       "Server Degrades Under Load",
			Description: fmt.Sprintf("Under %d concurrent requests, server returned %d 5xx errors and %d timeouts.", concurrency, errors5xx, timeouts),
			URL:         baseURL,
			Evidence:    fmt.Sprintf("5xx: %d, Timeouts: %d, Success: %d/%d", errors5xx, timeouts, successCount, totalRequests),
			Remediation: "Implement rate limiting, auto-scaling, and request queuing. Review server resource limits.",
		})
	} else if errors5xx > 0 || timeouts > 5 {
		findings = append(findings, Finding{
			Type:        "http-flood-moderate",
			Severity:    "medium",
			Title:       "Server Shows Moderate Stress Under Load",
			Description: fmt.Sprintf("Under load, %d 5xx errors and %d timeouts observed.", errors5xx, timeouts),
			URL:         baseURL,
			Evidence:    fmt.Sprintf("5xx: %d, Timeouts: %d", errors5xx, timeouts),
			Remediation: "Consider implementing rate limiting and monitoring.",
		})
	}

	return findings
}

// testAmplification checks if server accepts oversized requests.
func (s *Scanner) testAmplification(ctx context.Context, baseURL string) []Finding {
	var findings []Finding
	log.Printf("[DDoS] Testing amplification/oversized requests")

	ctxTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Test 1: Large URL (8KB+ path)
	longPath := strings.Repeat("a", 8000)
	select {
	case <-ctxTimeout.Done():
		return findings
	default:
	}

	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
		Method:  "GET",
		URL:     baseURL + "/" + longPath,
		Headers: map[string]string{"User-Agent": s.HTTPClient.UserAgent},
	})
	if err == nil && resp.StatusCode < 500 {
		findings = append(findings, Finding{
			Type:        "oversized-url",
			Severity:    "low",
			Title:       "Server Accepts Oversized URL",
			Description: "Server processed a request with an 8KB URL path without rejecting it.",
			URL:         baseURL + "/" + longPath[:50] + "...",
			Evidence:    fmt.Sprintf("Status: %d", resp.StatusCode),
			Remediation: "Configure server to reject URLs longer than a reasonable limit (e.g., 2048 characters).",
		})
	}

	// Test 2: Large POST body (100KB)
	largeBody := strings.Repeat("A", 100*1024)
	select {
	case <-ctxTimeout.Done():
		return findings
	default:
	}

	resp, err = s.HTTPClient.MakeRequest(HTTPRequest{
		Method:  "POST",
		URL:     baseURL + "/",
		Headers: map[string]string{
			"User-Agent":   s.HTTPClient.UserAgent,
		},
		Body: largeBody,
	})
	if err == nil && resp.StatusCode < 500 {
		findings = append(findings, Finding{
			Type:        "oversized-body",
			Severity:    "low",
			Title:       "Server Accepts Oversized Request Body",
			Description: "Server accepted a POST with a 100KB body without rejecting it.",
			URL:         baseURL + "/",
			Evidence:    fmt.Sprintf("Status: %d for 100KB body", resp.StatusCode),
			Remediation: "Set request body size limits (e.g., max 1MB for typical APIs).",
		})
	}

	// Test 3: Large headers
	longHeader := strings.Repeat("X", 8000)
	select {
	case <-ctxTimeout.Done():
		return findings
	default:
	}

	resp, err = s.HTTPClient.MakeRequest(HTTPRequest{
		Method:  "GET",
		URL:     baseURL + "/",
		Headers: map[string]string{
			"User-Agent": s.HTTPClient.UserAgent,
			"X-Large":    longHeader,
		},
	})
	if err == nil && resp.StatusCode < 500 {
		findings = append(findings, Finding{
			Type:        "oversized-headers",
			Severity:    "low",
			Title:       "Server Accepts Oversized Headers",
			Description: "Server accepted a request with 8KB header value without rejecting it.",
			URL:         baseURL + "/",
			Evidence:    fmt.Sprintf("Status: %d", resp.StatusCode),
			Remediation: "Configure header size limits on the server.",
		})
	}

	return findings
}

// testConnectionExhaustion tries to open many concurrent connections.
func (s *Scanner) testConnectionExhaustion(ctx context.Context, host, scheme string) []Finding {
	var findings []Finding
	log.Printf("[DDoS] Testing connection exhaustion")

	const numConns = 50
	ctxTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var successCount int64
	var wg sync.WaitGroup

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := net.Dialer{Timeout: 10 * time.Second}
			conn, err := dialer.DialContext(ctxTimeout, "tcp", host)
			if err != nil {
				return
			}
			atomic.AddInt64(&successCount, 1)
			conn.Close()
		}()
		// Small stagger to avoid OS-level limits
		time.Sleep(10 * time.Millisecond)
	}

	wg.Wait()
	success := atomic.LoadInt64(&successCount)

	if success >= int64(numConns)-5 { // Allow 5 failures for network conditions
		findings = append(findings, Finding{
			Type:        "connection-exhaustion",
			Severity:    "medium",
			Title:       "No Connection Rate Limiting",
			Description: fmt.Sprintf("Successfully opened %d/%d concurrent connections without rate limiting.", success, numConns),
			URL:         scheme + "://" + host,
			Evidence:    fmt.Sprintf("Connections opened: %d/%d", success, numConns),
			Remediation: "Implement connection rate limiting (e.g., max 20 connections per second per IP). Use a WAF or reverse proxy.",
		})
	} else {
		findings = append(findings, Finding{
			Type:        "connection-exhaustion",
			Severity:    "info",
			Title:       "Connection Rate Limiting Detected",
			Description: fmt.Sprintf("Only %d/%d connections succeeded — server appears to rate-limit connections.", success, numConns),
			URL:         scheme + "://" + host,
			Evidence:    fmt.Sprintf("Successful connections: %d/%d", success, numConns),
			Remediation: "No action needed.",
		})
	}

	return findings
}

// testSlowPOST sends POST with large Content-Length but delivers body very slowly (R.U.D.Y. style).
func (s *Scanner) testSlowPOST(ctx context.Context, baseURL string) []Finding {
	var findings []Finding
	log.Printf("[DDoS] Testing Slow POST (R.U.D.Y.)")

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return findings
	}
	host := parsedURL.Host
	if !strings.Contains(host, ":") {
		if parsedURL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	const numConns = 5
	var vulnerableCount int64

	var wg sync.WaitGroup
	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			dialer := net.Dialer{Timeout: 10 * time.Second}
			conn, err := dialer.DialContext(ctxTimeout, "tcp", host)
			if err != nil {
				return
			}
			defer conn.Close()

			// Send POST headers with large Content-Length
			postHeaders := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 10000\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\n\r\n", strings.Split(host, ":")[0])
			_, err = conn.Write([]byte(postHeaders))
			if err != nil {
				return
			}

			// Send body 1 byte at a time with delays
			conn.SetDeadline(time.Now().Add(25 * time.Second))
			for j := 0; j < 10; j++ {
				select {
				case <-ctxTimeout.Done():
					return
				default:
				}

				_, err := conn.Write([]byte{byte(rand.Intn(26) + 97)}) // random lowercase letter
				if err != nil {
					return // Server closed the connection — good
				}
				time.Sleep(1 * time.Second)
			}

			// If we reached here, server waited for the body for > 10 seconds
			atomic.AddInt64(&vulnerableCount, 1)
		}()
	}

	wg.Wait()
	vuln := atomic.LoadInt64(&vulnerableCount)

	if vuln >= int64(numConns)/2 {
		findings = append(findings, Finding{
			Type:        "slow-post",
			Severity:    "medium",
			Title:       "Slow POST Vulnerability (R.U.D.Y.)",
			Description: fmt.Sprintf("Server kept %d/%d connections open while receiving POST body at 1 byte/second with Content-Length: 10000.", vuln, numConns),
			URL:         baseURL,
			Evidence:    fmt.Sprintf("Connections vulnerable: %d/%d", vuln, numConns),
			Remediation: "Set minimum data transfer rate thresholds. Timeout slow connections. Limit request body size.",
		})
	} else {
		findings = append(findings, Finding{
			Type:        "slow-post",
			Severity:    "info",
			Title:       "Slow POST: Server Resistant",
			Description: fmt.Sprintf("Server closed slow POST connections. Only %d/%d remained open.", vuln, numConns),
			URL:         baseURL,
			Evidence:    fmt.Sprintf("Vulnerable connections: %d/%d", vuln, numConns),
			Remediation: "No action needed.",
		})
	}

	return findings
}
