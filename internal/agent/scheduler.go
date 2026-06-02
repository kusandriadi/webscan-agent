package agent

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"red-team-agent/internal/config"
)

// Scheduler manages automatic scan execution per target.
// Supports both interval-based and cron-based scheduling.
type Scheduler struct {
	agent   *Agent
	mu      sync.Mutex
	cancels map[string]context.CancelFunc // per-target cancel
}

func NewScheduler(agent *Agent) *Scheduler {
	return &Scheduler{
		agent:   agent,
		cancels: make(map[string]context.CancelFunc),
	}
}

// Start launches scheduler routines for all enabled targets.
func (s *Scheduler) Start(ctx context.Context) {
	s.syncTargets(ctx)

	// Re-sync every 30s to pick up config changes
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.syncTargets(ctx)
			}
		}
	}()
}

// syncTargets starts/stops per-target schedulers based on current config.
func (s *Scheduler) syncTargets(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg := s.agent.Config
	active := make(map[string]bool)

	for _, t := range cfg.GetEnabledTargets() {
		active[t.ID] = true
		sched := t.Schedule

		// Skip if no schedule configured
		if sched.Interval == "" && sched.Cron == "" {
			continue
		}

		// Already running?
		if _, ok := s.cancels[t.ID]; ok {
			continue
		}

		// Start new scheduler for this target
		tCtx, cancel := context.WithCancel(ctx)
		s.cancels[t.ID] = cancel

		go s.runTargetSchedule(tCtx, t)
		log.Printf("[Scheduler] Started schedule for target %s (interval=%s cron=%s)",
			t.ID, sched.Interval, sched.Cron)
	}

	// Stop schedulers for removed/disabled targets
	for id, cancel := range s.cancels {
		if !active[id] {
			cancel()
			delete(s.cancels, id)
			log.Printf("[Scheduler] Stopped schedule for removed target %s", id)
		}
	}
}

// StopAll cancels all running schedulers.
func (s *Scheduler) StopAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, cancel := range s.cancels {
		cancel()
		delete(s.cancels, id)
		log.Printf("[Scheduler] Stopped schedule for target %s", id)
	}
}

func (s *Scheduler) runTargetSchedule(ctx context.Context, target config.Target) {
	sched := target.Schedule

	if sched.Cron != "" {
		s.runCronSchedule(ctx, target, sched.Cron)
	} else if sched.Interval != "" {
		s.runIntervalSchedule(ctx, target, sched.Interval)
	}
}

// ─── Interval-based scheduling ───

func (s *Scheduler) runIntervalSchedule(ctx context.Context, target config.Target, intervalStr string) {
	dur, err := time.ParseDuration(intervalStr)
	if err != nil {
		log.Printf("[Scheduler] Invalid interval '%s' for %s: %v", intervalStr, target.ID, err)
		return
	}

	// Wait for first interval before first scan
	timer := time.NewTimer(dur)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			// Re-read target config (hot-reload)
			t := s.agent.Config.GetTarget(target.ID)
			if t == nil || !t.Enabled {
				return
			}

			log.Printf("[Scheduler] Interval triggered for %s (%s)", target.Name, intervalStr)
			result, err := s.agent.ExecuteScan(target.ID)
			if err != nil {
				log.Printf("[Scheduler] Scan failed for %s: %v", target.ID, err)
			} else {
				log.Printf("[Scheduler] Scan complete for %s: %d findings", target.ID, result.Findings)
			}

			// Reset timer for next interval
			timer.Reset(dur)
		}
	}
}

// ─── Cron-based scheduling ───

func (s *Scheduler) runCronSchedule(ctx context.Context, target config.Target, cronExpr string) {
	for {
		next, err := nextCronTime(cronExpr)
		if err != nil {
			log.Printf("[Scheduler] Invalid cron '%s' for %s: %v", cronExpr, target.ID, err)
			return
		}

		wait := time.Until(next)
		log.Printf("[Scheduler] Next scan for %s at %s (in %s)", target.Name, next.Format("2006-01-02 15:04:05"), wait.Round(time.Second))

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
			t := s.agent.Config.GetTarget(target.ID)
			if t == nil || !t.Enabled {
				return
			}

			log.Printf("[Scheduler] Cron triggered for %s (%s)", target.Name, cronExpr)
			result, err := s.agent.ExecuteScan(target.ID)
			if err != nil {
				log.Printf("[Scheduler] Scan failed for %s: %v", target.ID, err)
			} else {
				log.Printf("[Scheduler] Scan complete for %s: %d findings", target.ID, result.Findings)
			}
		}
	}
}

// ─── Cron Expression Parser ───
// Supports: "* * * * *" (min hour day month dow)
// Examples:
//   "0 2 * * *"       → every day at 02:00
//   "30 */4 * * *"    → every 4 hours at :30
//   "0 9 * * 1-5"     → weekdays at 09:00
//   "0 0 1 * *"       → first of every month at 00:00

func nextCronTime(expr string) (time.Time, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return time.Time{}, fmt.Errorf("cron expression must have 5 fields (min hour day month dow), got %d", len(fields))
	}

	now := time.Now().Add(time.Minute).Truncate(time.Minute)
	// Search forward for next match (max 1 year ahead)
	deadline := now.AddDate(1, 0, 0)

	for t := now; t.Before(deadline); t = t.Add(time.Minute) {
		if matchesCron(fields, t) {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("no matching time found within 1 year for: %s", expr)
}

func matchesCron(fields []string, t time.Time) bool {
	return matchField(fields[0], t.Minute(), 0, 59) &&
		matchField(fields[1], t.Hour(), 0, 23) &&
		matchField(fields[2], t.Day(), 1, 31) &&
		matchField(fields[3], int(t.Month()), 1, 12) &&
		matchField(fields[4], int(t.Weekday()), 0, 6)
}

func matchField(field string, value, min, max int) bool {
	// Handle multiple parts separated by comma
	for _, part := range strings.Split(field, ",") {
		if matchPart(part, value, min, max) {
			return true
		}
	}
	return false
}

func matchPart(part string, value, min, max int) bool {
	// Wildcard
	if part == "*" {
		return true
	}

	// Step: */N
	if strings.HasPrefix(part, "*/") {
		step, err := strconv.Atoi(part[2:])
		if err != nil || step == 0 {
			return false
		}
		return value%step == 0
	}

	// Range: N-M
	if strings.Contains(part, "-") {
		parts := strings.SplitN(part, "-", 2)
		start, err1 := strconv.Atoi(parts[0])
		end, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return false
		}
		return value >= start && value <= end
	}

	// Exact value
	n, err := strconv.Atoi(part)
	if err != nil {
		return false
	}
	return n == value
}
