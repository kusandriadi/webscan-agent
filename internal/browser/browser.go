package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"red-team-agent/internal/config"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

type Manager struct {
	config  *config.AgentConfig
	browser *rod.Browser
	ctx     context.Context
	cancel  context.CancelFunc
}

func NewManager(cfg *config.AgentConfig) *Manager {
	return &Manager{config: cfg}
}

func (m *Manager) EnsureBrowser(ctx context.Context) error {
	if m.browser != nil {
		return nil
	}

	m.ctx, m.cancel = context.WithCancel(ctx)

	headless := true
	if m.config != nil {
		headless = m.config.Headless
	}

	l := launcher.New().Headless(headless)
	if m.config != nil && m.config.Proxy != "" {
		l = l.Proxy(m.config.Proxy)
	}

	url, err := l.Launch()
	if err != nil {
		return fmt.Errorf("launch browser: %w", err)
	}

	b := rod.New().ControlURL(url)
	if err := b.Connect(); err != nil {
		return fmt.Errorf("connect browser: %w", err)
	}

	m.browser = b
	log.Println("[Browser] Headless browser launched")
	return nil
}

func (m *Manager) Close() {
	if m.browser != nil {
		m.browser.Close()
		m.browser = nil
	}
	if m.cancel != nil {
		m.cancel()
	}
}

func (m *Manager) NewPage() (*rod.Page, error) {
	if m.browser == nil {
		return nil, fmt.Errorf("browser not initialized")
	}
	return m.browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
}

func (m *Manager) Navigate(page *rod.Page, targetURL string) (*PageResult, error) {
	start := time.Now()
	result := &PageResult{URL: targetURL}

	err := rod.Try(func() {
		page.Timeout(30 * time.Second).MustNavigate(targetURL).MustWaitStable()
	})
	elapsed := time.Since(start)
	result.Elapsed = elapsed

	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	result.Status = 200
	result.Body, _ = page.HTML()
	info, _ := page.Info()
	if info != nil {
		result.Title = info.Title
	}
	return result, nil
}

func (m *Manager) NavigateSimple(targetURL string) (*PageResult, error) {
	if err := m.EnsureBrowser(context.Background()); err != nil {
		return nil, err
	}
	page, err := m.NewPage()
	if err != nil {
		return nil, err
	}
	defer page.Close()
	return m.Navigate(page, targetURL)
}

func (m *Manager) FormLogin(loginURL, username, password, usernameSel, passwordSel, submitSel string) (bool, error) {
	if err := m.EnsureBrowser(context.Background()); err != nil {
		return false, err
	}
	page, err := m.NewPage()
	if err != nil {
		return false, err
	}
	defer page.Close()

	page.Timeout(30 * time.Second).MustNavigate(loginURL).MustWaitStable()

	if usernameSel == "" {
		usernameSel = "input[name='username'], input[type='email']"
	}
	if passwordSel == "" {
		passwordSel = "input[name='password'], input[type='password']"
	}
	if submitSel == "" {
		submitSel = "button[type='submit'], input[type='submit']"
	}

	page.MustElement(usernameSel).MustInput(username)
	page.MustElement(passwordSel).MustInput(password)
	page.MustElement(submitSel).MustClick()
	page.MustWaitStable()

	info, _ := page.Info()
	title := ""
	if info != nil {
		title = info.Title
	}
	currentURL := ""
	if info != nil {
		currentURL = info.URL
	}

	loggedIn := !strings.Contains(currentURL, "login") && !strings.Contains(strings.ToLower(title), "login")
	log.Printf("[Browser] Login attempt → %v", loggedIn)
	return loggedIn, nil
}

func (m *Manager) GetLinks(targetURL string) ([]string, error) {
	if err := m.EnsureBrowser(context.Background()); err != nil {
		return nil, err
	}
	page, err := m.NewPage()
	if err != nil {
		return nil, err
	}
	defer page.Close()

	page.Timeout(30 * time.Second).MustNavigate(targetURL).MustWaitStable()

	els, err := page.Elements("a[href]")
	if err != nil {
		return nil, err
	}

	var result []string
	for _, el := range els {
		href, err := el.Property("href")
		if err != nil {
			continue
		}
		s := href.String()
		if strings.HasPrefix(s, "http") {
			result = append(result, s)
		}
	}
	return result, nil
}

func (m *Manager) GetForms(targetURL string) ([]FormInfo, error) {
	if err := m.EnsureBrowser(context.Background()); err != nil {
		return nil, err
	}
	page, err := m.NewPage()
	if err != nil {
		return nil, err
	}
	defer page.Close()

	page.Timeout(30 * time.Second).MustNavigate(targetURL).MustWaitStable()

	eval, err := page.Eval(`JSON.stringify(Array.from(document.forms).map(f => ({
		action: f.action, method: f.method, id: f.id,
		inputs: Array.from(f.elements).map(e => ({name: e.name, type: e.type, id: e.id}))
	})))`)
	if err != nil {
		return nil, err
	}

	var forms []FormInfo
	data := []byte(eval.Value.String())
	if len(data) > 2 {
		json.Unmarshal(data, &forms)
	}
	return forms, nil
}

func (m *Manager) Screenshot(targetURL string) ([]byte, error) {
	if err := m.EnsureBrowser(context.Background()); err != nil {
		return nil, err
	}
	page, err := m.NewPage()
	if err != nil {
		return nil, err
	}
	defer page.Close()

	page.Timeout(30 * time.Second).MustNavigate(targetURL).MustWaitStable()
	return page.Screenshot(false, nil)
}

func (m *Manager) ExtractJS(targetURL string) ([]string, error) {
	if err := m.EnsureBrowser(context.Background()); err != nil {
		return nil, err
	}
	page, err := m.NewPage()
	if err != nil {
		return nil, err
	}
	defer page.Close()

	page.Timeout(30 * time.Second).MustNavigate(targetURL).MustWaitStable()

	els, err := page.Elements("script")
	if err != nil {
		return nil, err
	}

	var result []string
	for _, el := range els {
		text, err := el.Text()
		if err != nil {
			continue
		}
		if strings.TrimSpace(text) != "" {
			if len(text) > 2000 {
				text = text[:2000]
			}
			result = append(result, text)
		}
	}
	return result, nil
}

type PageResult struct {
	URL     string        `json:"url"`
	Status  int           `json:"status"`
	Title   string        `json:"title"`
	Body    string        `json:"body"`
	Elapsed time.Duration `json:"elapsed"`
	Error   string        `json:"error,omitempty"`
	Headers http.Header   `json:"headers,omitempty"`
}

type FormInfo struct {
	Action string     `json:"action"`
	Method string     `json:"method"`
	ID     string     `json:"id"`
	Inputs []FormInput `json:"inputs"`
}

type FormInput struct {
	Name string `json:"name"`
	Type string `json:"type"`
	ID   string `json:"id"`
}
