package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"red-team-agent/internal/config"
	"red-team-agent/internal/knowledge"
	"red-team-agent/internal/report"
	"red-team-agent/internal/scanner"

	"github.com/gorilla/mux"
)

// ScanExecutor is implemented by agent.Agent
type ScanExecutor interface {
	ExecuteScan(targetID string) (*ScanResult, error)
	GetHistory() []ScanResult
	GetScanner() *scanner.Scanner
}

type ScanResult struct {
	TargetID   string `json:"target_id"`
	TargetName string `json:"target_name"`
	Date       string `json:"date"`
	Findings   int    `json:"findings_count"`
	PDFPath    string `json:"pdf_path"`
	Iteration  int    `json:"iteration"`
	Duration   string `json:"duration"`
}

type Server struct {
	Config    *config.Config
	Knowledge *knowledge.Manager
	Scanner   *scanner.Scanner
	Reporter  *report.Generator
	Executor  ScanExecutor
	router    *mux.Router
}

func New(cfg *config.Config, km *knowledge.Manager, sc *scanner.Scanner, rep *report.Generator, executor ScanExecutor) *Server {
	s := &Server{
		Config:    cfg,
		Knowledge: km,
		Scanner:   sc,
		Reporter:  rep,
		Executor:  executor,
		router:    mux.NewRouter(),
	}
	s.routes()
	return s
}

func (s *Server) Start() error {
	addr := s.Config.DashboardAddr()
	log.Printf("[API] Starting dashboard on http://%s", addr)

	srv := &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	return srv.ListenAndServe()
}

func (s *Server) routes() {
	staticDir := "web/static"
	if _, err := os.Stat(staticDir); err == nil {
		fs := http.FileServer(http.Dir(staticDir))
		s.router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))
	}

	s.router.HandleFunc("/", s.page("dashboard")).Methods("GET")
	s.router.HandleFunc("/scan", s.page("scan")).Methods("GET")
	s.router.HandleFunc("/config", s.page("config")).Methods("GET")
	s.router.HandleFunc("/reports", s.page("reports")).Methods("GET")
	s.router.HandleFunc("/skills", s.page("skills")).Methods("GET")

	api := s.router.PathPrefix("/api").Subrouter()
	api.HandleFunc("/config", s.handleGetConfig).Methods("GET")
	api.HandleFunc("/config", s.handleSaveConfig).Methods("PUT")
	api.HandleFunc("/targets", s.handleListTargets).Methods("GET")
	api.HandleFunc("/targets", s.handleCreateTarget).Methods("POST")
	api.HandleFunc("/targets/{id}", s.handleUpdateTarget).Methods("PUT")
	api.HandleFunc("/targets/{id}", s.handleDeleteTarget).Methods("DELETE")
	api.HandleFunc("/scan/start", s.handleStartScan).Methods("POST")
	api.HandleFunc("/scan/progress", s.handleScanProgress).Methods("GET")
	api.HandleFunc("/scan/history", s.handleScanHistory).Methods("GET")
	api.HandleFunc("/reports", s.handleListReports).Methods("GET")
	api.HandleFunc("/reports/download/{filename}", s.handleDownloadReport).Methods("GET")
	api.HandleFunc("/reports/view/{filename}", s.handleViewReport).Methods("GET")
	api.HandleFunc("/skills", s.handleListSkills).Methods("GET")
	api.HandleFunc("/skills/{id}", s.handleGetSkills).Methods("GET")
	api.HandleFunc("/skills/{id}/reset", s.handleResetSkills).Methods("POST")
	api.HandleFunc("/schedule", s.handleGetSchedule).Methods("GET")
}

func (s *Server) page(name string) http.HandlerFunc {
	tmplFile := fmt.Sprintf("web/templates/%s.html", name)
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(tmplFile)
		if err != nil {
			http.Error(w, "Template not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write(data)
	}
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	data, _ := s.Config.ToJSON()
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (s *Server) handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	var cfg config.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	cfg.SetFilePath(s.Config.FilePath())
	s.Config = &cfg
	s.Config.Save()
	jsonOK(w, map[string]string{"status": "ok"})
}

func (s *Server) handleListTargets(w http.ResponseWriter, r *http.Request) {
	data, _ := json.Marshal(s.Config.Targets)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (s *Server) handleCreateTarget(w http.ResponseWriter, r *http.Request) {
	var t config.Target
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	if t.ID == "" {
		t.ID = fmt.Sprintf("target_%d", time.Now().Unix())
	}
	s.Config.AddTarget(t)
	s.Config.Save()
	jsonOK(w, map[string]string{"status": "created", "id": t.ID})
}

func (s *Server) handleUpdateTarget(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var t config.Target
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		jsonError(w, err.Error(), 400)
		return
	}
	t.ID = id
	if err := s.Config.UpdateTarget(id, t); err != nil {
		jsonError(w, err.Error(), 404)
		return
	}
	s.Config.Save()
	jsonOK(w, map[string]string{"status": "updated"})
}

func (s *Server) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := s.Config.DeleteTarget(id); err != nil {
		jsonError(w, err.Error(), 404)
		return
	}
	s.Config.Save()
	jsonOK(w, map[string]string{"status": "deleted"})
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TargetID string `json:"target_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "target_id required", 400)
		return
	}

	go func() {
		_, err := s.Executor.ExecuteScan(req.TargetID)
		if err != nil {
			log.Printf("[API] Scan error: %v", err)
		}
	}()

	jsonOK(w, map[string]string{"status": "started", "target_id": req.TargetID})
}

func (s *Server) handleScanProgress(w http.ResponseWriter, r *http.Request) {
	progress := map[string]interface{}{
		"running":       s.Executor.GetScanner() != nil,
		"current_scan":  nil,
		"progress":      map[string]string{},
	}
	sc := s.Executor.GetScanner()
	if sc != nil {
		targets := s.Config.GetEnabledTargets()
		if len(targets) > 0 {
			progress["progress"] = map[string]string{
				"status": sc.GetProgress(targets[0].ID),
			}
		}
	}
	data, _ := json.Marshal(progress)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (s *Server) handleScanHistory(w http.ResponseWriter, r *http.Request) {
	data, _ := json.Marshal(s.Executor.GetHistory())
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (s *Server) handleListReports(w http.ResponseWriter, r *http.Request) {
	var reports []map[string]interface{}
	filepath.Walk("reports", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		name := info.Name()
		if strings.HasSuffix(name, ".pdf") || strings.HasSuffix(name, ".json") {
			reports = append(reports, map[string]interface{}{
				"filename": name,
				"size":     info.Size(),
				"created":  info.ModTime().Format(time.RFC3339),
			})
		}
		return nil
	})
	if reports == nil {
		reports = []map[string]interface{}{}
	}
	data, _ := json.Marshal(reports)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (s *Server) handleDownloadReport(w http.ResponseWriter, r *http.Request) {
	filename := mux.Vars(r)["filename"]
	path := filepath.Join("reports", filename)
	if _, err := os.Stat(path); err != nil {
		http.Error(w, "Not found", 404)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	http.ServeFile(w, r, path)
}

func (s *Server) handleViewReport(w http.ResponseWriter, r *http.Request) {
	filename := mux.Vars(r)["filename"]
	path := filepath.Join("reports", filename)
	if strings.HasSuffix(filename, ".json") {
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, "Not found", 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}
	http.ServeFile(w, r, path)
}

func (s *Server) handleListSkills(w http.ResponseWriter, r *http.Request) {
	var result []map[string]interface{}
	for _, t := range s.Config.Targets {
		kb, _ := s.Knowledge.Load(t.ID)
		if kb == nil {
			continue
		}
		result = append(result, map[string]interface{}{
			"target_id":         t.ID,
			"target_name":       t.Name,
			"iterations":        kb.Skills.Iteration,
			"known_endpoints":   len(kb.Endpoints),
			"known_parameters":  len(kb.Parameters),
			"past_findings":     len(kb.VulnHistory),
			"improvement_notes": kb.Skills.ImprovementNotes,
			"last_test_date":    kb.Skills.LastIterationAt.Format(time.RFC3339),
		})
	}
	if result == nil {
		result = []map[string]interface{}{}
	}
	data, _ := json.Marshal(result)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (s *Server) handleGetSkills(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	kb, err := s.Knowledge.Load(id)
	if err != nil || kb == nil {
		jsonError(w, "Not found", 404)
		return
	}
	data, _ := json.Marshal(kb)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (s *Server) handleResetSkills(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	kb, _ := s.Knowledge.Load(id)
	if kb != nil {
		kb.Skills.Reset()
		kb.Save()
	}
	jsonOK(w, map[string]string{"status": "reset"})
}

func jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) handleGetSchedule(w http.ResponseWriter, r *http.Request) {
	var schedules []map[string]interface{}
	for _, t := range s.Config.Targets {
		entry := map[string]interface{}{
			"target_id":   t.ID,
			"target_name": t.Name,
			"enabled":     t.Enabled,
			"interval":    t.Schedule.Interval,
			"cron":        t.Schedule.Cron,
		}
		next := ""
		if t.Schedule.Cron != "" {
			if nt, err := nextCronTime(t.Schedule.Cron); err == nil {
				next = nt.Format(time.RFC3339)
			}
		} else if t.Schedule.Interval != "" {
			kb, _ := s.Knowledge.Load(t.ID)
			if kb != nil && !kb.Skills.LastIterationAt.IsZero() {
				if dur, err := time.ParseDuration(t.Schedule.Interval); err == nil {
					next = kb.Skills.LastIterationAt.Add(dur).Format(time.RFC3339)
				}
			}
		}
		entry["next_scan"] = next
		schedules = append(schedules, entry)
	}
	if schedules == nil {
		schedules = []map[string]interface{}{}
	}
	data, _ := json.Marshal(schedules)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// Simple cron next-time calculator (same as agent/scheduler.go)
func nextCronTime(expr string) (time.Time, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return time.Time{}, fmt.Errorf("need 5 fields")
	}
	now := time.Now().Add(time.Minute).Truncate(time.Minute)
	deadline := now.AddDate(1, 0, 0)
	for t := now; t.Before(deadline); t = t.Add(time.Minute) {
		if cronMatch(fields, t) {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("no match")
}

func cronMatch(fields []string, t time.Time) bool {
	return cronField(fields[0], t.Minute()) && cronField(fields[1], t.Hour()) && cronField(fields[2], t.Day()) && cronField(fields[3], int(t.Month())) && cronField(fields[4], int(t.Weekday()))
}

func cronField(f string, v int) bool {
	for _, p := range strings.Split(f, ",") {
		if p == "*" { return true }
		if strings.HasPrefix(p, "*/") {
			step, _ := strconv.Atoi(p[2:])
			if step > 0 && v%step == 0 { return true }
		}
		if strings.Contains(p, "-") {
			parts := strings.SplitN(p, "-", 2)
			s, e1 := strconv.Atoi(parts[0])
			e, e2 := strconv.Atoi(parts[1])
			if e1 == nil && e2 == nil && v >= s && v <= e { return true }
		}
		n, err := strconv.Atoi(p)
		if err == nil && n == v { return true }
	}
	return false
}
