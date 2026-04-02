package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"tlsident/pkg/server"
)

func main() {
	listenAddress := flag.String("listen", ":8443", "address to listen on")
	outputDirectory := flag.String("outdir", "", "directory to persist capture snapshots as sequential .tlsident.json files")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service, err := server.New(server.Config{
		ListenAddress: *listenAddress,
		OutputDir:     *outputDirectory,
		Logger:        logger,
	})
	if err != nil {
		logger.Error("failed to create server", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := service.ListenAndServe(ctx); err != nil {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}
