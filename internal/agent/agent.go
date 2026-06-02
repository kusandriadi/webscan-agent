package agent

import (
	"context"
	"fmt"
	"log"
	"time"

	"red-team-agent/internal/api"
	"red-team-agent/internal/browser"
	"red-team-agent/internal/config"
	"red-team-agent/internal/knowledge"
	"red-team-agent/internal/report"
	"red-team-agent/internal/scanner"
)

type Agent struct {
	Config    *config.Config
	Knowledge *knowledge.Manager
	Scanner   *scanner.Scanner
	Reporter  *report.Generator
	Browser   *browser.Manager
	API       *api.Server
	Planner   *Planner
	Scheduler *Scheduler
	dataDir   string
	history   []api.ScanResult
}

func New(cfg *config.Config, dataDir string) *Agent {
	km := knowledge.NewManager(dataDir)
	agt := &Agent{
		Config:    cfg,
		Knowledge: km,
		Planner:   NewPlanner(km),
		Reporter:  report.NewGenerator("reports"),
		Browser:   browser.NewManager(&cfg.Agent),
		dataDir:   dataDir,
		history:   make([]api.ScanResult, 0),
	}
	agt.Scheduler = NewScheduler(agt)
	return agt
}

// ExecuteScan implements api.ScanExecutor
func (a *Agent) ExecuteScan(targetID string) (summary *api.ScanResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Agent] Panic recovered in ExecuteScan: %v", r)
			err = fmt.Errorf("scan panic: %v", r)
		}
	}()

	t := a.Config.GetTarget(targetID)
	if t == nil {
		return nil, fmt.Errorf("target not found: %s", targetID)
	}

	kb, err := a.Knowledge.Load(targetID)
	if err != nil || kb == nil {
		kb = a.Knowledge.NewKB(targetID)
	}

	plan := a.Planner.CreatePlan(*t, kb)

	log.Printf("=== Starting scan iteration %d for: %s (%s) ===",
		kb.Skills.Iteration+1, t.Name, t.URL)

	s := scanner.NewScanner(a.Config, kb)
	a.Scanner = s

	result := s.Execute(context.Background(), plan)

	kb.IncrementIteration()

	findings := result.Findings()
	for _, f := range findings {
		kb.RecordTechnique(f.Type, f.Severity, true)
	}
	if len(findings) > 0 {
		kb.AddImprovement(knowledge.Improvement{
			Category:    "findings",
			Description: fmt.Sprintf("Iteration %d: Found %d vulns — escalate attack depth", kb.Skills.Iteration, len(findings)),
			Priority:    1,
		})
	}
	kb.Skills.AddNote(fmt.Sprintf("Iteration %d: %d vulns, %d endpoints, %d params.",
		kb.Skills.Iteration, len(findings), len(kb.Endpoints), len(kb.Parameters)))

	kb.Save()

	dateStr := time.Now().Format("2006-01-02")
	pdfName := fmt.Sprintf("redteam_%s_%s.pdf", targetID, dateStr)
	pdfPath, err := a.Reporter.Generate(result, *t, kb, pdfName)
	if err != nil {
		log.Printf("Report generation failed: %v", err)
		pdfPath = ""
	} else {
		log.Printf("Report generated: %s", pdfPath)
	}

	summary = &api.ScanResult{
		TargetID:   targetID,
		TargetName: t.Name,
		Date:       time.Now().Format("Jan 02, 2006"),
		Findings:   len(findings),
		PDFPath:    pdfPath,
		Iteration:  kb.Skills.Iteration,
		Duration:   fmt.Sprintf("%.1fs", result.Duration.Seconds()),
	}
	a.history = append(a.history, *summary)

	log.Printf("=== Scan complete: %d findings in %s ===", len(findings), summary.Duration)
	return summary, nil
}

// GetHistory implements api.ScanExecutor
func (a *Agent) GetHistory() []api.ScanResult {
	return a.history
}

// GetScanner implements api.ScanExecutor
func (a *Agent) GetScanner() *scanner.Scanner {
	return a.Scanner
}

func (a *Agent) Run(ctx context.Context) error {
	srv := api.New(a.Config, a.Knowledge, nil, a.Reporter, a)
	a.API = srv

	go func() {
		if err := srv.Start(); err != nil {
			log.Printf("Dashboard error: %v", err)
		}
	}()

	// Start cron/interval scheduler
	a.Scheduler.Start(ctx)

	log.Println("Agent started. Dashboard + Scheduler running.")

	// Block until context cancelled
	<-ctx.Done()
	a.Scheduler.StopAll()
	a.Browser.Close()
	return ctx.Err()
}
