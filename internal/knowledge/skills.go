package knowledge

import "time"

// Skills engine - learning from results

func NewSkills() *Skills {
	return &Skills{
		Iteration:        0,
		ImprovementNotes: []string{},
		LastIterationAt:  time.Now(),
	}
}

func (s *Skills) AddNote(note string) {
	s.ImprovementNotes = append(s.ImprovementNotes, note)
}

func (s *Skills) Reset() {
	s.Iteration = 0
	s.TotalVulnsFound = 0
	s.ImprovementNotes = []string{}
	s.LastIterationAt = time.Now()
}
