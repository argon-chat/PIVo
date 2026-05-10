package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/pivo-agent/pivo/internal/config"
	"github.com/pivo-agent/pivo/internal/pairing"
	"github.com/pivo-agent/pivo/internal/server"
	"github.com/pivo-agent/pivo/internal/yubikey"
)

func main() {
	unpair := flag.String("unpair", "", "Remove a paired origin")
	listOrigins := flag.Bool("list-origins", false, "List all paired origins")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("[PIVo] failed to load config: %v", err)
	}

	// CLI subcommands
	if *listOrigins {
		origins := cfg.Origins()
		if len(origins) == 0 {
			fmt.Println("No paired origins.")
		} else {
			fmt.Println("Paired origins:")
			for _, o := range origins {
				fmt.Printf("  %s\n", o)
			}
		}
		return
	}

	if *unpair != "" {
		if cfg.RemoveOrigin(*unpair) {
			_ = cfg.Save()
			fmt.Printf("Origin %s removed.\n", *unpair)
		} else {
			fmt.Printf("Origin %s not found.\n", *unpair)
		}
		return
	}

	// --- Server mode ---
	pairingMgr := pairing.New(cfg)
	ykMgr := yubikey.NewManager()
	defer ykMgr.Close()

	srv := server.New(config.Ports, ykMgr, pairingMgr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		log.Println("[PIVo] shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5e9)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if err := srv.Start(); err != nil && ctx.Err() == nil {
		log.Fatalf("[PIVo] server error: %v", err)
	}
}
