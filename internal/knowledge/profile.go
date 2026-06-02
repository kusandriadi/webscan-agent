package knowledge

// Profile helper methods
import "time"

func NewProfile() *Profile {
	return &Profile{
		Technologies: []TechInfo{},
		LastUpdated:  time.Now(),
	}
}

func (p *Profile) AddTech(name, version, source string) {
	for _, t := range p.Technologies {
		if t.Name == name {
			return
		}
	}
	p.Technologies = append(p.Technologies, TechInfo{
		Name: name, Version: version, Source: source,
	})
	p.LastUpdated = time.Now()
}
