package agent

type ScanSummary struct {
	TargetID   string `json:"target_id"`
	TargetName string `json:"target_name"`
	Date       string `json:"date"`
	Findings   int    `json:"findings_count"`
	PDFPath    string `json:"pdf_path"`
	Iteration  int    `json:"iteration"`
	Duration   string `json:"duration"`
}
