package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"red-team-agent/internal/agent"
	"red-team-agent/internal/config"
)

func main() {
	configPath := flag.String("config", "config.json", "Path to config file")
	dataDir := flag.String("data", "data", "Path to knowledge base directory")
	port := flag.Int("port", 5555, "Dashboard port")
	host := flag.String("host", "0.0.0.0", "Dashboard host")
	flag.Parse()

	fmt.Println(`
  ╔══════════════════════════════════════════════╗
  ║        🔴 RED TEAM AGENT v2.0 (Go)          ║
  ║   Automated Web Security Testing Platform    ║
  ╠══════════════════════════════════════════════╣`)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if *port != 5555 {
		cfg.Dashboard.Port = *port
	}
	if *host != "0.0.0.0" {
		cfg.Dashboard.Host = *host
	}

	fmt.Printf("  ║  Dashboard: http://%s:%-28d║\n", cfg.Dashboard.Host, cfg.Dashboard.Port)
	fmt.Printf("  ║  Config:    %-32s║\n", *configPath)
	fmt.Printf("  ║  Data:      %-32s║\n", *dataDir)
	fmt.Println("  ╚══════════════════════════════════════════════╝")
	fmt.Println()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received signal: %v, shutting down...", sig)
		cancel()
	}()

	agt := agent.New(cfg, *dataDir)
	if err := agt.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("Agent error: %v", err)
	}

	log.Println("Red Team Agent stopped.")
}
