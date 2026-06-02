package scanner

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"red-team-agent/internal/config"
	"red-team-agent/internal/knowledge"
)

// BrowserLogin is the minimal browser capability the scanner needs to
// establish an authenticated session via a real login form. It is satisfied
// by browser.Manager and kept as an interface here to avoid importing the
// (heavy) browser/rod package into the scanner.
type BrowserLogin interface {
	FormLoginCookies(loginURL, username, password string, selectors map[string]string) (map[string]string, bool, error)
}

type PhaseResult struct {
	Phase         string                `json:"phase"`
	Duration      time.Duration         `json:"duration"`
	Findings      []Finding             `json:"findings"`
	Endpoints     []knowledge.Endpoint  `json:"endpoints"`
	Parameters    []knowledge.Parameter `json:"parameters"`
	Errors        []string              `json:"errors"`
}

type Finding struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Parameter   string `json:"parameter"`
	Payload     string `json:"payload"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
}

type ScanResult struct {
	TargetID    string                 `json:"target_id"`
	TargetName  string                 `json:"target_name"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     time.Time              `json:"end_time"`
	Duration    time.Duration          `json:"duration"`
	Iteration   int                    `json:"iteration"`
	Phases      []PhaseResult          `json:"phases"`
	VulnsFound  int                    `json:"vulns_found"`
	Status      string                 `json:"status"` // completed, failed, partial
}

// Computed fields for report generation

func (r *ScanResult) Findings() []Finding {
	var all []Finding
	for _, p := range r.Phases {
		all = append(all, p.Findings...)
	}
	return all
}

func (r *ScanResult) Endpoints() []string {
	seen := make(map[string]bool)
	var all []string
	for _, p := range r.Phases {
		for _, ep := range p.Endpoints {
			if !seen[ep.URL] {
				seen[ep.URL] = true
				all = append(all, ep.URL)
			}
		}
	}
	return all
}

func (r *ScanResult) Stats() Stats {
	s := Stats{
		Duration:         r.Duration.Seconds(),
		TotalFindings:    r.VulnsFound,
		EndpointsCrawled: len(r.Endpoints()),
	}
	for _, f := range r.Findings() {
		switch f.Severity {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		default:
			s.Info++
		}
	}
	s.TestsRun = 0
	for range r.Phases {
		s.TestsRun++
	}
	return s
}

func (r *ScanResult) TestsRun() []TestRecord {
	var all []TestRecord
	for _, p := range r.Phases {
		all = append(all, TestRecord{
			Name:       p.Phase,
			FoundVuln:  len(p.Findings) > 0,
			Note:       "",
		})
	}
	return all
}

type RaceConditionTest struct {
	Endpoint    string `json:"endpoint"`
	Method      string `json:"method"`
	Body        string `json:"body"`
	Concurrency int    `json:"concurrency"`
	Name        string `json:"name"`
}

type Stats struct {
	Critical        int     `json:"critical"`
	High            int     `json:"high"`
	Medium          int     `json:"medium"`
	Low             int     `json:"low"`
	Info            int     `json:"info"`
	TotalFindings   int     `json:"total_findings"`
	EndpointsCrawled int    `json:"endpoints_crawled"`
	TestsRun        int     `json:"tests_run"`
	Duration        float64 `json:"duration"`
}

type TestRecord struct {
	Name      string `json:"name"`
	FoundVuln bool   `json:"found_vuln"`
	Note      string `json:"note"`
}

type ScanPlan struct {
	Target       config.Target
	Phases       map[string]bool
	CustomTests  map[string][]string
	SkipTests    map[string]bool
	PayloadSets  map[string][]string
}

type Scanner struct {
	Config         *config.Config
	KB             *knowledge.KnowledgeBase
	HTTPClient     *HTTPClient
	mu             sync.Mutex
	progress       map[string]string
	SlowThreshold  time.Duration
	slowURLs       map[string]bool
	currentResult  *PhaseResult
}

type HTTPClient struct {
	UserAgent   string
	Timeout     time.Duration
	RateLimit   time.Duration
	Proxy       string
	Headers     map[string]string
	Cookies     map[string]string
	OnResponse  func(*HTTPResponse) // callback after each request
	Ctx         context.Context     // cancellation context for the current scan
	Scope       *scopeChecker       // include/exclude path enforcement
	SessionHost string              // only send session creds (Authorization/Cookies) to this host
	limiter     *rateLimiter        // global, concurrency-safe rate limiter
}

// sessionApplies reports whether session credentials should be attached to a
// request for the given host. Credentials are scoped to the target host so a
// bearer token or session cookie is never leaked to a third party (e.g. crt.sh).
func (c *HTTPClient) sessionApplies(host string) bool {
	if c.SessionHost == "" {
		return true
	}
	return strings.EqualFold(host, c.SessionHost)
}

// rateLimiter spaces out requests by a fixed interval across ALL goroutines,
// so concurrent phases (ddos, fuzz) cannot exceed the configured RPS.
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func (r *rateLimiter) wait(ctx context.Context) {
	if r == nil || r.interval <= 0 {
		return
	}
	r.mu.Lock()
	now := time.Now()
	if r.next.Before(now) {
		r.next = now
	}
	delay := r.next.Sub(now)
	r.next = r.next.Add(r.interval)
	r.mu.Unlock()

	if delay <= 0 {
		return
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	if ctx == nil {
		<-timer.C
		return
	}
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// scopeChecker enforces the target's include_paths / exclude_paths rules.
// Requests to disallowed paths are blocked before any network I/O.
type scopeChecker struct {
	include []string
	exclude []string
}

func (sc *scopeChecker) allowed(rawURL string) bool {
	if sc == nil {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return true // never block on an unparseable URL
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	for _, ex := range sc.exclude {
		if pathMatch(ex, path) {
			return false
		}
	}
	if len(sc.include) > 0 {
		for _, in := range sc.include {
			if pathMatch(in, path) {
				return true
			}
		}
		return false
	}
	return true
}

// pathMatch supports exact paths, a trailing "*" wildcard, and "*" (match all).
// An exact pattern also matches everything beneath it, so "/admin/delete"
// blocks "/admin/delete" and "/admin/delete/123".
func pathMatch(pattern, path string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "*"))
	}
	return path == pattern || strings.HasPrefix(path, strings.TrimRight(pattern, "/")+"/")
}

func NewScanner(cfg *config.Config, kb *knowledge.KnowledgeBase) *Scanner {
	timeout := 30 * time.Second
	if len(cfg.Targets) > 0 && cfg.Targets[0].Scope.Timeout != "" {
		if d, err := time.ParseDuration(cfg.Targets[0].Scope.Timeout); err == nil {
			timeout = d
		}
	}
	rateLimit := time.Second / time.Duration(5)
	if len(cfg.Targets) > 0 && cfg.Targets[0].Scope.RateLimitRPS > 0 {
		rateLimit = time.Second / time.Duration(cfg.Targets[0].Scope.RateLimitRPS)
	}

	slowThreshold := 500 * time.Millisecond
	if len(cfg.Targets) > 0 && cfg.Targets[0].Scope.SlowThresholdMs > 0 {
		slowThreshold = time.Duration(cfg.Targets[0].Scope.SlowThresholdMs) * time.Millisecond
	}

	return &Scanner{
		Config:        cfg,
		KB:            kb,
		SlowThreshold: slowThreshold,
		HTTPClient: &HTTPClient{
			UserAgent: cfg.Agent.UserAgent,
			Timeout:   timeout,
			RateLimit: rateLimit,
			Proxy:     cfg.Agent.Proxy,
			Headers:   make(map[string]string),
			Cookies:   make(map[string]string),
			Ctx:       context.Background(),
			limiter:   &rateLimiter{interval: rateLimit},
			OnResponse: func(hr *HTTPResponse) {
				// callback will be patched per-scan via setCurrentResult
			},
		},
		progress:  make(map[string]string),
		slowURLs:  make(map[string]bool),
	}
}

// SetScope applies the target's include_paths / exclude_paths so that out-of-scope
// requests (e.g. destructive admin paths) are blocked at the HTTP layer.
func (s *Scanner) SetScope(target config.Target) {
	inc := target.Scope.IncludePaths
	exc := target.Scope.ExcludePaths
	if len(inc) == 0 && len(exc) == 0 {
		s.HTTPClient.Scope = nil
		return
	}
	s.HTTPClient.Scope = &scopeChecker{include: inc, exclude: exc}
	if len(exc) > 0 {
		log.Printf("[Scanner] Scope enforced — exclude_paths: %v", exc)
	}
}

// ApplyAuth establishes an authenticated session for the whole scan based on the
// target's auth method. The resulting headers/cookies are attached to every
// subsequent request. Call this BEFORE SetScope so the login URL is never blocked.
func (s *Scanner) ApplyAuth(ctx context.Context, target config.Target, browser BrowserLogin) {
	if u, err := url.Parse(target.URL); err == nil {
		s.HTTPClient.SessionHost = u.Hostname()
	}
	switch target.Auth.Method {
	case "token":
		if target.Auth.Token != "" {
			token := target.Auth.Token
			if !strings.HasPrefix(strings.ToLower(token), "bearer ") {
				token = "Bearer " + token
			}
			s.HTTPClient.Headers["Authorization"] = token
			log.Printf("[Auth] Applied bearer token to scan session")
		}
	case "basic":
		if target.Auth.Username != "" {
			cred := base64.StdEncoding.EncodeToString([]byte(target.Auth.Username + ":" + target.Auth.Password))
			s.HTTPClient.Headers["Authorization"] = "Basic " + cred
			log.Printf("[Auth] Applied HTTP basic auth to scan session")
		}
	case "form":
		s.formLogin(ctx, target, browser)
	}
}

// formLogin authenticates against a login form and stores the resulting session
// cookies on the HTTP client. When login_selectors are configured it uses the
// headless browser (most faithful to a real login); otherwise — or if the browser
// fails — it falls back to a direct form POST and captures Set-Cookie headers.
func (s *Scanner) formLogin(ctx context.Context, target config.Target, browser BrowserLogin) {
	if target.Auth.LoginURL == "" || target.Auth.Username == "" {
		return
	}

	if browser != nil && len(target.Auth.LoginSelectors) > 0 {
		cookies, ok, err := browser.FormLoginCookies(
			target.Auth.LoginURL, target.Auth.Username, target.Auth.Password, target.Auth.LoginSelectors)
		if err == nil && len(cookies) > 0 {
			for k, v := range cookies {
				s.HTTPClient.Cookies[k] = v
			}
			log.Printf("[Auth] Browser form login established session (%d cookies, success=%v)", len(cookies), ok)
			return
		}
		log.Printf("[Auth] Browser login unavailable (%v), falling back to HTTP form POST", err)
	}

	form := url.Values{}
	form.Set("username", target.Auth.Username)
	form.Set("email", target.Auth.Username)
	form.Set("password", target.Auth.Password)

	resp, err := s.HTTPClient.MakeRequest(HTTPRequest{
		Method:  "POST",
		URL:     target.Auth.LoginURL,
		Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:    form.Encode(),
	})
	if err != nil {
		log.Printf("[Auth] Form login failed: %v", err)
		return
	}

	count := 0
	for _, sc := range resp.Headers["Set-Cookie"] {
		if name, value := parseSetCookie(sc); name != "" {
			s.HTTPClient.Cookies[name] = value
			count++
		}
	}
	if count > 0 {
		log.Printf("[Auth] HTTP form login captured %d session cookie(s)", count)
	} else {
		log.Printf("[Auth] HTTP form login returned no Set-Cookie (HTTP %d) — session may be unauthenticated", resp.StatusCode)
	}
}

// parseSetCookie extracts the name and value from a Set-Cookie header value.
func parseSetCookie(header string) (string, string) {
	first := header
	if i := strings.IndexByte(header, ';'); i >= 0 {
		first = header[:i]
	}
	first = strings.TrimSpace(first)
	eq := strings.IndexByte(first, '=')
	if eq <= 0 {
		return "", ""
	}
	return strings.TrimSpace(first[:eq]), strings.TrimSpace(first[eq+1:])
}

func (s *Scanner) Execute(ctx context.Context, plan *ScanPlan) *ScanResult {
	s.HTTPClient.Ctx = ctx // propagate cancellation to every request
	s.mu.Lock()
	s.progress[plan.Target.ID] = "running"
	s.slowURLs = make(map[string]bool) // reset slow URL dedup per scan
	s.mu.Unlock()

	result := &ScanResult{
		TargetID:   plan.Target.ID,
		TargetName: plan.Target.Name,
		StartTime:  time.Now(),
		Iteration:  s.KB.Skills.Iteration,
		Status:     "completed",
	}

	defer func() {
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		s.mu.Lock()
		s.progress[plan.Target.ID] = "completed"
		s.mu.Unlock()
	}()

	phaseOrder := []struct {
		name   string
		phase  string
		run    func(context.Context, config.Target) *PhaseResult
	}{
		{"recon", "Reconnaissance", func(ctx context.Context, t config.Target) *PhaseResult { return s.RunRecon(ctx, t) }},
		{"discovery", "Discovery", func(ctx context.Context, t config.Target) *PhaseResult { return s.RunDiscovery(ctx, t) }},
		{"auth", "Authentication", func(ctx context.Context, t config.Target) *PhaseResult { return s.RunAuth(ctx, t) }},
		{"authz", "Authorization", func(ctx context.Context, t config.Target) *PhaseResult { return s.RunAuthz(ctx, t) }},
		{"injection", "Injection", func(ctx context.Context, t config.Target) *PhaseResult { return s.RunInjection(ctx, t) }},
		{"logic", "Logic", func(ctx context.Context, t config.Target) *PhaseResult { return s.RunLogic(ctx, t) }},
		{"client_side", "Client-Side", func(ctx context.Context, t config.Target) *PhaseResult { return s.RunClientSide(ctx, t) }},
		{"infra", "Infrastructure", func(ctx context.Context, t config.Target) *PhaseResult { return s.RunInfra(ctx, t) }},
		{"ddos", "DDoS Simulation", func(ctx context.Context, t config.Target) *PhaseResult { return s.RunDDoS(ctx, t) }},
		{"fuzz", "Fuzzing Stress", func(ctx context.Context, t config.Target) *PhaseResult { return s.RunFuzz(ctx, t) }},
	}

	for _, p := range phaseOrder {
		if !plan.Phases[p.name] {
			continue
		}

		select {
		case <-ctx.Done():
			result.Status = "partial"
			return result
		default:
		}

		log.Printf("[Scanner] Running phase %s for target %s", p.phase, plan.Target.ID)
		s.mu.Lock()
		s.progress[plan.Target.ID] = fmt.Sprintf("phase:%s", p.name)
		s.mu.Unlock()

		pr := func() (r *PhaseResult) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("[Scanner] Panic recovered in phase %s: %v", p.phase, rec)
					r = &PhaseResult{Phase: p.phase, Errors: []string{fmt.Sprintf("panic: %v", rec)}}
				}
				s.setCurrentResult(nil) // clear callback after phase
			}()
			// Wire slow response tracking for this phase
			phaseResult := &PhaseResult{Phase: p.phase}
			s.setCurrentResult(phaseResult)
			result := p.run(ctx, plan.Target)
			// Merge any slow-response findings collected during the phase
			if result != nil {
				s.mu.Lock()
				for _, f := range phaseResult.Findings {
					result.Findings = append(result.Findings, f)
				}
				s.mu.Unlock()
			}
			return result
		}()
		if pr != nil {
			result.Phases = append(result.Phases, *pr)
			result.VulnsFound += len(pr.Findings)

			// Store findings in knowledge base
			for _, f := range pr.Findings {
				s.KB.AddVuln(knowledge.Vulnerability{
					Type:        f.Type,
					Severity:    f.Severity,
					Title:       f.Title,
					Description: f.Description,
					URL:         f.URL,
					Parameter:   f.Parameter,
					Payload:     f.Payload,
					Evidence:    f.Evidence,
					Remediation: f.Remediation,
					Phase:       p.name,
					Iteration:   result.Iteration,
					FoundAt:     time.Now(),
				})
			}

			// Store discovered endpoints
			for _, ep := range pr.Endpoints {
				s.KB.AddEndpoint(ep)
			}

			// Store discovered parameters
			for _, param := range pr.Parameters {
				s.KB.AddParameter(param)
			}
		}
	}

	return result
}

func (s *Scanner) GetProgress(targetID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.progress[targetID]; ok {
		return p
	}
	return "idle"
}

// CheckSlowResponse checks if an HTTP response exceeded the slow threshold
// and appends a finding to currentResult. Deduplicates per URL.
func (s *Scanner) CheckSlowResponse(resp *HTTPResponse) {
	if s.SlowThreshold <= 0 || resp == nil {
		return
	}
	if resp.Duration >= s.SlowThreshold {
		// Hold the lock across dedup AND append so concurrent phases (ddos, fuzz)
		// cannot race on the shared currentResult slice.
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.slowURLs[resp.URL] {
			return
		}
		s.slowURLs[resp.URL] = true

		result := s.currentResult
		if result == nil {
			return
		}

		result.Findings = append(result.Findings, Finding{
			Type:        "slow-response",
			Severity:    "minor",
			Title:       fmt.Sprintf("Slow Response: %s", resp.Duration.Round(time.Millisecond)),
			Description: fmt.Sprintf("%s %s responded in %v (threshold: %v)", resp.Method, resp.URL, resp.Duration.Round(time.Millisecond), s.SlowThreshold),
			URL:         resp.URL,
			Evidence:    fmt.Sprintf("Method: %s, Status: %d, Duration: %v, Threshold: %v", resp.Method, resp.StatusCode, resp.Duration.Round(time.Millisecond), s.SlowThreshold),
			Remediation: "Investigate slow endpoint. Consider caching, query optimization, or pagination.",
		})
	}
}

// setCurrentResult sets the current phase result and wires up the slow response callback.
func (s *Scanner) setCurrentResult(result *PhaseResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentResult = result
	s.HTTPClient.OnResponse = func(hr *HTTPResponse) {
		s.CheckSlowResponse(hr)
	}
}

type HTTPRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
	Params  map[string]string
}

type HTTPResponse struct {
	StatusCode int
	Headers    map[string][]string
	Body       string
	Duration   time.Duration
	Method     string
	URL        string
}

var sharedTransport = &http.Transport{
	MaxIdleConns:        20,
	MaxIdleConnsPerHost: 10,
	IdleConnTimeout:     30 * time.Second,
	DisableKeepAlives:   false,
	TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
}

// MakeRequest performs a real HTTP request with rate limiting, timeout, and cookie jar
func (c *HTTPClient) MakeRequest(req HTTPRequest) (*HTTPResponse, error) {
	// Scope enforcement — refuse out-of-scope (e.g. excluded) URLs before any I/O.
	if c.Scope != nil && !c.Scope.allowed(req.URL) {
		return nil, fmt.Errorf("request blocked: out of scope: %s", req.URL)
	}

	ctx := c.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// Rate limiting (global, concurrency-safe)
	c.limiter.wait(ctx)

	// Honor cancellation before spending a request
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Build request body
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	// Default headers
	httpReq.Header.Set("User-Agent", c.UserAgent)
	httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	httpReq.Header.Set("Accept-Language", "en-US,en;q=0.5")

	// Global session headers first (e.g. Authorization from ApplyAuth), but only
	// for the target host so credentials never leak to third parties...
	sessionOK := c.sessionApplies(httpReq.URL.Hostname())
	if sessionOK {
		for k, v := range c.Headers {
			httpReq.Header.Set(k, v)
		}
	}
	// ...then per-request headers so a specific test can override the session
	// (e.g. the auth phase sending its own Authorization for alg:none tests).
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Cookies (session-scoped to the target host)
	if sessionOK {
		for k, v := range c.Cookies {
			httpReq.AddCookie(&http.Cookie{Name: k, Value: v})
		}
	}

	// Query params
	if req.Params != nil {
		q := httpReq.URL.Query()
		for k, v := range req.Params {
			q.Set(k, v)
		}
		httpReq.URL.RawQuery = q.Encode()
	}

	// Execute with timeout
	client := &http.Client{
		Timeout:   c.Timeout,
		Transport: sharedTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	start := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read body (max 2MB)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	httpResp := &HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       string(bodyBytes),
		Duration:   time.Since(start),
		Method:     req.Method,
		URL:        req.URL,
	}

	if c.OnResponse != nil {
		c.OnResponse(httpResp)
	}

	return httpResp, nil
}
