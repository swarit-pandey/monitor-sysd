package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/swarit-pandey/monitor-sysd/pkg/core"
)

func main() {
	fmt.Println("Starting eBPF system monitor...")

	// Check if running as root (required for eBPF)
	if os.Geteuid() != 0 {
		fmt.Println("This program must be run as root (sudo).")
		os.Exit(1)
	}

	// Create a new monitor
	monitor, err := core.NewMonitor()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating monitor: %v\n", err)
		os.Exit(1)
	}
	defer monitor.Close()

	// Create a context with timeout (optional)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// You can either use the long-running mode with signal handling:
	err = monitor.RunMonitorWithSignalHandling(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running monitor: %v\n", err)
		os.Exit(1)
	}

	/*
		// Alternative: manually control the monitor lifecycle
		if err := monitor.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting monitor: %v\n", err)
			os.Exit(1)
		}

		// Run for 30 seconds
		fmt.Println("Monitoring system activity for 30 seconds...")
		time.Sleep(30 * time.Second)

		// Print final metrics before exiting
		monitor.PrintMetrics()
	*/

	fmt.Println("Monitoring complete.")
}
