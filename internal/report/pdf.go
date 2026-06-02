package report

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"red-team-agent/internal/config"
	"red-team-agent/internal/knowledge"
	"red-team-agent/internal/scanner"

	"github.com/jung-kurt/gofpdf"
)

type Generator struct {
	outputDir string
}

func NewGenerator(outputDir string) *Generator {
	return &Generator{outputDir: outputDir}
}

func (g *Generator) Generate(result *scanner.ScanResult, target config.Target, kb *knowledge.KnowledgeBase, filename string) (string, error) {
	os.MkdirAll(g.outputDir, 0755)

	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 20)

	// Cover Page
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 32)
	pdf.SetTextColor(180, 0, 0)
	pdf.Ln(60)
	pdf.CellFormat(0, 15, "SECURITY ASSESSMENT REPORT", "", 0, "C", false, 0, "")
	pdf.Ln(12)
	pdf.SetFont("Helvetica", "", 16)
	pdf.SetTextColor(100, 100, 100)
	pdf.CellFormat(0, 10, "Red Team Agent v2.0 — Automated Testing", "", 0, "C", false, 0, "")
	pdf.Ln(30)

	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(0, 0, 0)
	info := []struct{ label, value string }{
		{"Target", target.Name},
		{"URL", target.URL},
		{"Date", time.Now().Format("Jan 02, 2006")},
		{"Iteration", fmt.Sprintf("#%d", kb.Skills.Iteration)},
	}
	for _, item := range info {
		pdf.CellFormat(50, 8, item.label+":", "", 0, "R", false, 0, "")
		pdf.CellFormat(0, 8, "  "+item.value, "", 1, "L", false, 0, "")
	}

	pdf.Ln(30)
	pdf.SetFillColor(180, 0, 0)
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(0, 12, "  CONFIDENTIAL — FOR AUTHORIZED PERSONNEL ONLY", "", 1, "C", true, 0, "")

	// Executive Summary
	pdf.AddPage()
	pdf.SetTextColor(180, 0, 0)
	pdf.SetFont("Helvetica", "B", 18)
	pdf.CellFormat(0, 10, "Executive Summary", "", 1, "L", false, 0, "")
	redLine(pdf)
	pdf.Ln(5)

	// Severity stats boxes
	severities := []struct {
		label string
		count int
		r, g, b int
	}{
		{"CRITICAL", result.Stats().Critical, 180, 0, 0},
		{"HIGH", result.Stats().High, 230, 126, 34},
		{"MEDIUM", result.Stats().Medium, 241, 196, 15},
		{"LOW", result.Stats().Low, 52, 152, 219},
		{"INFO", result.Stats().Info, 149, 165, 166},
	}

	boxW := 32.0
	boxH := 20.0
 startX := 10.0
	for i, s := range severities {
		x := startX + float64(i)*(boxW+2)
		pdf.SetFillColor(s.r, s.g, s.b)
		pdf.Rect(x, pdf.GetY(), boxW, boxH, "F")
		pdf.SetXY(x, pdf.GetY()+2)
		pdf.SetFont("Helvetica", "B", 18)
		pdf.SetTextColor(255, 255, 255)
		pdf.CellFormat(boxW, 8, fmt.Sprintf("%d", s.count), "", 0, "C", false, 0, "")
		pdf.SetXY(x, pdf.GetY()+8)
		pdf.SetFont("Helvetica", "", 8)
		pdf.CellFormat(boxW, 6, s.label, "", 0, "C", false, 0, "")
	}
	pdf.SetY(pdf.GetY() + boxH + 5)

	pdf.SetTextColor(0, 0, 0)
	pdf.SetFont("Helvetica", "", 10)
	meta := []struct{ label, value string }{
		{"Scan Duration", fmt.Sprintf("%.1f seconds", result.Stats().Duration)},
		{"Endpoints Crawled", fmt.Sprintf("%d", result.Stats().EndpointsCrawled)},
		{"Tests Executed", fmt.Sprintf("%d", result.Stats().TestsRun)},
		{"Total Findings", fmt.Sprintf("%d", result.Stats().TotalFindings)},
	}
	for _, m := range meta {
		pdf.CellFormat(60, 6, m.label+":", "", 0, "L", false, 0, "")
		pdf.CellFormat(0, 6, m.value, "", 1, "L", false, 0, "")
	}

	// Learning notes
	if len(kb.Skills.ImprovementNotes) > 0 {
		pdf.Ln(5)
		pdf.SetFont("Helvetica", "B", 11)
		pdf.CellFormat(0, 6, "Learning Notes:", "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		for _, note := range kb.Skills.ImprovementNotes {
			pdf.CellFormat(5, 5, "", "", 0, "", false, 0, "")
			pdf.CellFormat(0, 5, "- "+note, "", 1, "L", false, 0, "")
		}
	}

	// Detailed Findings
	pdf.AddPage()
	pdf.SetTextColor(180, 0, 0)
	pdf.SetFont("Helvetica", "B", 18)
	pdf.CellFormat(0, 10, "Detailed Findings", "", 1, "L", false, 0, "")
	redLine(pdf)
	pdf.Ln(5)

	if len(result.Findings()) == 0 {
		pdf.SetFont("Helvetica", "", 11)
		pdf.SetTextColor(100, 100, 100)
		pdf.CellFormat(0, 10, "No findings were identified during this assessment.", "", 1, "L", false, 0, "")
	}

	for i, f := range result.Findings() {
		if pdf.GetY() > 250 {
			pdf.AddPage()
		}

		// Severity color mapping
		var r, g, b int
		switch f.Severity {
		case "critical":
			r, g, b = 180, 0, 0
		case "high":
			r, g, b = 230, 126, 34
		case "medium":
			r, g, b = 241, 196, 15
		case "low":
			r, g, b = 52, 152, 219
		default:
			r, g, b = 149, 165, 166
		}

		// Badge
		badgeText := strings.ToUpper(f.Severity)
		pdf.SetFillColor(r, g, b)
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont("Helvetica", "B", 8)
		badgeW := pdf.GetStringWidth(badgeText) + 6
		pdf.CellFormat(badgeW, 5, badgeText, "", 0, "C", true, 0, "")

		// Title
		pdf.SetTextColor(0, 0, 0)
		pdf.SetFont("Helvetica", "B", 11)
		pdf.CellFormat(0, 5, "  "+fmt.Sprintf("%d. %s", i+1, f.Title), "", 1, "L", false, 0, "")
		pdf.Ln(2)

		// Details
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(60, 60, 60)
		details := []struct{ label, value string }{
			{"Type", f.Type},
			{"URL", truncate(f.URL, 80)},
			{"Parameter", f.Parameter},
		}
		for _, d := range details {
			if d.value != "" {
				pdf.CellFormat(25, 5, d.label+":", "", 0, "L", false, 0, "")
				pdf.CellFormat(0, 5, d.value, "", 1, "L", false, 0, "")
			}
		}

		// Description
		pdf.SetTextColor(30, 30, 30)
		pdf.MultiCell(0, 5, f.Description, "", "L", false)

		// Evidence
		if f.Evidence != "" {
			pdf.Ln(1)
			pdf.SetFont("Helvetica", "B", 8)
			pdf.CellFormat(0, 5, "Evidence:", "", 1, "L", false, 0, "")
			pdf.SetFont("Courier", "", 7)
			pdf.SetFillColor(245, 245, 245)
			evText := truncate(f.Evidence, 300)
			pdf.MultiCell(0, 4, evText, "", "L", true)
		}

		// Remediation
		if f.Remediation != "" {
			pdf.Ln(1)
			pdf.SetFont("Helvetica", "", 9)
			pdf.SetTextColor(34, 139, 34)
			pdf.MultiCell(0, 5, "Remediation: "+f.Remediation, "", "L", false)
		}

		pdf.Ln(3)
		pdf.SetDrawColor(200, 200, 200)
		pdf.Line(10, pdf.GetY(), 200, pdf.GetY())
		pdf.Ln(3)
	}

	// Discovered Endpoints
	if len(result.Endpoints()) > 0 {
		pdf.AddPage()
		pdf.SetTextColor(180, 0, 0)
		pdf.SetFont("Helvetica", "B", 18)
		pdf.CellFormat(0, 10, fmt.Sprintf("Discovered Endpoints (%d)", len(result.Endpoints())), "", 1, "L", false, 0, "")
		redLine(pdf)
		pdf.Ln(3)

		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(0, 0, 0)
		for i, ep := range result.Endpoints() {
			if pdf.GetY() > 275 {
				pdf.AddPage()
			}
			pdf.CellFormat(10, 4, fmt.Sprintf("%d.", i+1), "", 0, "R", false, 0, "")
			pdf.CellFormat(0, 4, "  "+ep, "", 1, "L", false, 0, "")
		}
	}

	// Tests Executed
	if len(result.TestsRun()) > 0 {
		pdf.AddPage()
		pdf.SetTextColor(180, 0, 0)
		pdf.SetFont("Helvetica", "B", 18)
		pdf.CellFormat(0, 10, "Tests Executed", "", 1, "L", false, 0, "")
		redLine(pdf)
		pdf.Ln(3)

		pdf.SetFont("Helvetica", "B", 9)
		pdf.CellFormat(80, 6, "Test", "", 0, "L", false, 0, "")
		pdf.CellFormat(30, 6, "Result", "", 0, "L", false, 0, "")
		pdf.CellFormat(0, 6, "Notes", "", 1, "L", false, 0, "")
		pdf.Line(10, pdf.GetY(), 200, pdf.GetY())
		pdf.Ln(2)

		pdf.SetFont("Helvetica", "", 8)
		for _, t := range result.TestsRun() {
			status := "Clean"
			if t.FoundVuln {
				status = "VULN FOUND"
				pdf.SetTextColor(180, 0, 0)
			} else {
				pdf.SetTextColor(34, 139, 34)
			}
			pdf.CellFormat(80, 5, t.Name, "", 0, "L", false, 0, "")
			pdf.CellFormat(30, 5, status, "", 0, "L", false, 0, "")
			pdf.SetTextColor(100, 100, 100)
			pdf.CellFormat(0, 5, t.Note, "", 1, "L", false, 0, "")
		}
	}

	// Footer
	pdf.SetTextColor(150, 150, 150)
	pdf.SetFont("Helvetica", "", 7)
	pdf.Ln(10)
	pdf.CellFormat(0, 4, fmt.Sprintf("Generated by Red Team Agent v2.0 | Date: %s | Iteration: #%d", time.Now().Format("Jan 02, 2006"), kb.Skills.Iteration), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 4, "This assessment does not guarantee the absence of vulnerabilities.", "", 1, "C", false, 0, "")

	path := filepath.Join(g.outputDir, filename)
	if err := pdf.OutputFileAndClose(path); err != nil {
		return "", fmt.Errorf("write PDF: %w", err)
	}

	log.Printf("[Report] Generated: %s", path)
	return path, nil
}

func redLine(pdf *gofpdf.Fpdf) {
	y := pdf.GetY()
	pdf.SetDrawColor(180, 0, 0)
	pdf.SetLineWidth(0.8)
	pdf.Line(10, y, 200, y)
	pdf.SetLineWidth(0.2)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
