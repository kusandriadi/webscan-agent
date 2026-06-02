package knowledge

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type TechInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"` // where we detected it
}

type Profile struct {
	Technologies []TechInfo `json:"technologies"`
	ServerType   string     `json:"server_type"`
	AuthMechanism string    `json:"auth_mechanism"`
	Framework    string     `json:"framework"`
	TLSInfo      string     `json:"tls_info"`
	LastUpdated  time.Time  `json:"last_updated"`
}

type Endpoint struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Params      []string          `json:"params"`
	Headers     map[string]string `json:"headers"`
	Auth        bool              `json:"auth_required"`
	DiscoveredAt time.Time        `json:"discovered_at"`
	DiscoveredBy string           `json:"discovered_by"`
}

type Parameter struct {
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	Method    string   `json:"method"`
	Type      string   `json:"type"` // query, form, header, cookie
	Values    []string `json:"values"`
	Tested    bool     `json:"tested"`
}

type Vulnerability struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Severity     string    `json:"severity"`
	Title        string    `json:"title"`
	Description  string    `json:"description"`
	URL          string    `json:"url"`
	Parameter    string    `json:"parameter"`
	Payload      string    `json:"payload"`
	Evidence     string    `json:"evidence"`
	Remediation  string    `json:"remediation"`
	Phase        string    `json:"phase"`
	Iteration    int       `json:"iteration"`
	FoundAt      time.Time `json:"found_at"`
	Confirmed    bool      `json:"confirmed"`
}

type PayloadRecord struct {
	Payload   string    `json:"payload"`
	Type      string    `json:"type"`
	Endpoint  string    `json:"endpoint"`
	Result    string    `json:"result"` // hit, miss, error
	Timestamp time.Time `json:"timestamp"`
}

type Technique struct {
	Name      string  `json:"name"`
	Category  string  `json:"category"`
	Attempts  int     `json:"attempts"`
	Successes int     `json:"successes"`
	LastUsed  time.Time `json:"last_used"`
}

func (t *Technique) SuccessRate() float64 {
	if t.Attempts == 0 {
		return 0
	}
	return float64(t.Successes) / float64(t.Attempts) * 100
}

func (t *Technique) Failed() bool {
	return t.Attempts >= 3 && t.Successes == 0
}

type Skills struct {
	Iteration        int       `json:"iteration"`
	TotalVulnsFound  int       `json:"total_vulns_found"`
	ImprovementNotes []string  `json:"improvement_notes"`
	LastIterationAt  time.Time `json:"last_iteration_at"`
}

type Improvement struct {
	ID          string    `json:"id"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Priority    int       `json:"priority"`
	Completed   bool      `json:"completed"`
	CreatedAt   time.Time `json:"created_at"`
}

type KnowledgeBase struct {
	TargetID     string
	Profile      Profile          `json:"profile"`
	Endpoints    []Endpoint       `json:"endpoints"`
	Parameters   []Parameter      `json:"parameters"`
	VulnHistory  []Vulnerability  `json:"vuln_history"`
	PayloadsUsed []PayloadRecord  `json:"payloads_used"`
	Techniques   []Technique      `json:"techniques"`
	Skills       Skills           `json:"skills"`
	Improvements []Improvement    `json:"improvements"`

	mu      sync.RWMutex
	dataDir string
}

type Manager struct {
	baseDir string
	mu      sync.RWMutex
	caches  map[string]*KnowledgeBase
}

func NewManager(dataDir string) *Manager {
	return &Manager{
		baseDir: dataDir,
		caches:  make(map[string]*KnowledgeBase),
	}
}

func (m *Manager) targetDir(targetID string) string {
	return filepath.Join(m.baseDir, targetID)
}

func (m *Manager) Load(targetID string) (*KnowledgeBase, error) {
	m.mu.RLock()
	if kb, ok := m.caches[targetID]; ok {
		m.mu.RUnlock()
		return kb, nil
	}
	m.mu.RUnlock()

	dir := m.targetDir(targetID)
	os.MkdirAll(dir, 0755)

	kb := &KnowledgeBase{
		TargetID: targetID,
		dataDir:  dir,
	}

	files := map[string]interface{}{
		"profile.json":      &kb.Profile,
		"endpoints.json":    &kb.Endpoints,
		"parameters.json":   &kb.Parameters,
		"vuln_history.json": &kb.VulnHistory,
		"payloads_used.json": &kb.PayloadsUsed,
		"techniques.json":   &kb.Techniques,
		"skills.json":       &kb.Skills,
		"improvements.json": &kb.Improvements,
	}

	for name, v := range files {
		p := filepath.Join(dir, name)
		data, err := os.ReadFile(p)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("read %s: %w", name, err)
			}
			continue
		}
		if err := json.Unmarshal(data, v); err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
	}

	m.mu.Lock()
	m.caches[targetID] = kb
	m.mu.Unlock()

	return kb, nil
}

func (kb *KnowledgeBase) Save() error {
	kb.mu.Lock()
	defer kb.mu.Unlock()

	files := map[string]interface{}{
		"profile.json":       kb.Profile,
		"endpoints.json":     kb.Endpoints,
		"parameters.json":    kb.Parameters,
		"vuln_history.json":  kb.VulnHistory,
		"payloads_used.json": kb.PayloadsUsed,
		"techniques.json":    kb.Techniques,
		"skills.json":        kb.Skills,
		"improvements.json":  kb.Improvements,
	}

	for name, v := range files {
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal %s: %w", name, err)
		}
		p := filepath.Join(kb.dataDir, name)
		if err := os.WriteFile(p, data, 0644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

func (kb *KnowledgeBase) AddEndpoint(ep Endpoint) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	for _, existing := range kb.Endpoints {
		if existing.URL == ep.URL && existing.Method == ep.Method {
			return
		}
	}
	kb.Endpoints = append(kb.Endpoints, ep)
}

func (kb *KnowledgeBase) AddParameter(p Parameter) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	for _, existing := range kb.Parameters {
		if existing.Name == p.Name && existing.URL == p.URL {
			return
		}
	}
	kb.Parameters = append(kb.Parameters, p)
}

func (kb *KnowledgeBase) AddVuln(v Vulnerability) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	kb.VulnHistory = append(kb.VulnHistory, v)
	kb.Skills.TotalVulnsFound = len(kb.VulnHistory)
}

func (kb *KnowledgeBase) AddPayloadRecord(p PayloadRecord) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	kb.PayloadsUsed = append(kb.PayloadsUsed, p)
}

func (kb *KnowledgeBase) RecordTechnique(name, category string, success bool) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	for i := range kb.Techniques {
		if kb.Techniques[i].Name == name && kb.Techniques[i].Category == category {
			kb.Techniques[i].Attempts++
			if success {
				kb.Techniques[i].Successes++
			}
			kb.Techniques[i].LastUsed = time.Now()
			return
		}
	}
	t := Technique{
		Name:      name,
		Category:  category,
		Attempts:  1,
		Successes: 0,
		LastUsed:  time.Now(),
	}
	if success {
		t.Successes = 1
	}
	kb.Techniques = append(kb.Techniques, t)
}

func (kb *KnowledgeBase) HasTech(name string) bool {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	for _, t := range kb.Profile.Technologies {
		if t.Name == name {
			return true
		}
	}
	return false
}

func (kb *KnowledgeBase) NewEndpointsSince(iteration int) []Endpoint {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	var result []Endpoint
	for _, ep := range kb.Endpoints {
		if ep.DiscoveredAt.After(kb.Skills.LastIterationAt) {
			result = append(result, ep)
		}
	}
	return result
}

func (kb *KnowledgeBase) FailedTechniques() []Technique {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	var failed []Technique
	for _, t := range kb.Techniques {
		if t.Failed() {
			failed = append(failed, t)
		}
	}
	return failed
}

func (kb *KnowledgeBase) WasPayloadUsed(payload, endpoint string) bool {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	for _, p := range kb.PayloadsUsed {
		if p.Payload == payload && p.Endpoint == endpoint {
			return true
		}
	}
	return false
}

func (kb *KnowledgeBase) IncrementIteration() {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	kb.Skills.Iteration++
	kb.Skills.LastIterationAt = time.Now()
}

func (kb *KnowledgeBase) AddImprovement(imp Improvement) {
	kb.mu.Lock()
	defer kb.mu.Unlock()
	kb.Improvements = append(kb.Improvements, imp)
}

func (kb *KnowledgeBase) ToJSON() ([]byte, error) {
	kb.mu.RLock()
	defer kb.mu.RUnlock()
	return json.MarshalIndent(kb, "", "  ")
}

func (m *Manager) NewKB(targetID string) *KnowledgeBase {
	return &KnowledgeBase{
		TargetID:   targetID,
		dataDir:    m.baseDir,
		Endpoints:  []Endpoint{},
		Parameters: []Parameter{},
		VulnHistory: []Vulnerability{},
		PayloadsUsed: []PayloadRecord{},
		Techniques: []Technique{},
		Skills:     *NewSkills(),
		Improvements: []Improvement{},
	}
}
