package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"red-team-agent/internal/config"
	"red-team-agent/internal/knowledge"
)

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
			OnResponse: func(hr *HTTPResponse) {
				// callback will be patched per-scan via setCurrentResult
			},
		},
		progress:  make(map[string]string),
		slowURLs:  make(map[string]bool),
	}
}

func (s *Scanner) Execute(ctx context.Context, plan *ScanPlan) *ScanResult {
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
		s.mu.Lock()
		if s.slowURLs[resp.URL] {
			s.mu.Unlock()
			return
		}
		s.slowURLs[resp.URL] = true
		s.mu.Unlock()

		s.mu.Lock()
		result := s.currentResult
		s.mu.Unlock()
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
	// Rate limiting
	time.Sleep(c.RateLimit)

	// Build request body
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequest(req.Method, req.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	// Default headers
	httpReq.Header.Set("User-Agent", c.UserAgent)
	httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	httpReq.Header.Set("Accept-Language", "en-US,en;q=0.5")

	// Custom headers
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	for k, v := range c.Headers {
		httpReq.Header.Set(k, v)
	}

	// Cookies
	for k, v := range c.Cookies {
		httpReq.AddCookie(&http.Cookie{Name: k, Value: v})
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
