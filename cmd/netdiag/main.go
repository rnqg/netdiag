package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"netdiag/internal/cli"
	"netdiag/internal/fix"
)

func main() {
	if len(os.Args) == 4 && os.Args[1] == "_restore-watch" {
		if err := fix.Guard(context.Background(), os.Args[2], os.Args[3]); err != nil {
			os.Exit(1)
		}
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if len(os.Args) == 4 && os.Args[1] == "_apply" {
		if err := fix.ApplyWorker(ctx, os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "_recover" {
		if err := fix.RecoverWorker(ctx, os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	for _, path := range fix.Recoveries() {
		fmt.Fprintln(os.Stderr, "Есть незавершённое восстановление настроек:", path)
	}
	os.Exit(cli.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, cli.Interactive()))
}
