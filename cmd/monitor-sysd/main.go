package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/swarit-pandey/monitor-sysd/pkg/core"
)

func main() {
	log.Println("Starting eBPF monitor...")
	eventReader, err := core.NewEventReader()
	if err != nil {
		log.Fatalf("Failed to create event reader: %v", err)
	}
	defer eventReader.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)

	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Println("Event reader context cancelled, stopping...")
				return
			default:
				event, err := eventReader.Read()
				if err != nil {
					if err == syscall.ECANCELED || err == os.ErrClosed {
						log.Println("Ring buffer reader closed")
						return
					}
					errCh <- fmt.Errorf("error reading event: %w", err)
					return
				}

				log.Printf("Event: %+v\n", event)
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case <-sigCh:
		log.Println("\nInterrupt received, shutting down...")
	case err := <-errCh:
		log.Printf("Error from event reader: %v, shutting down...", err)
	}

	cancel()
	time.Sleep(100 * time.Millisecond)
	log.Println("Shutdown complete.")
}
