// RDP Screenshotter - Capture screenshots from RDP servers
// Copyright (C) 2024 RDP Screenshotter Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/x-stp/rdp-screenshotter-go/pkg/rdp"
)

func main() {
	var (
		targetFile = flag.String("targets", "target.txt", "File containing RDP targets (one per line)")
		timeout    = flag.Duration("timeout", 10*time.Second, "Connection timeout")
		username   = flag.String("username", "", "Username for RDP cookie (optional)")
		outputDir  = flag.String("output", "screenshots", "Output directory for screenshots")
	)
	flag.Parse()

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Read targets from file
	targets, err := readTargets(*targetFile)
	if err != nil {
		log.Fatalf("Failed to read targets: %v", err)
	}

	if len(targets) == 0 {
		log.Fatal("No targets found in file")
	}

	fmt.Printf("Found %d targets\n", len(targets))

	// Process each target
	for i, target := range targets {
		fmt.Printf("\n[%d/%d] Processing %s...\n", i+1, len(targets), target)

		// Create client options
		opts := &rdp.ClientOptions{
			Timeout:  *timeout,
			Username: *username,
		}

		// Try to capture screenshot
		if err := captureScreenshot(target, opts, *outputDir); err != nil {
			fmt.Printf("Failed to capture screenshot from %s: %v\n", target, err)
		} else {
			fmt.Printf("Successfully captured screenshot from %s\n", target)
		}
	}
}

func readTargets(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			// Add default port if not specified
			if !strings.Contains(line, ":") {
				line += ":3389"
			}
			targets = append(targets, line)
		}
	}

	return targets, scanner.Err()
}

func captureScreenshot(target string, opts *rdp.ClientOptions, outputDir string) error {
	// Create RDP client
	client, err := rdp.NewClient(target, opts)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	defer client.Close()

	// Capture screenshot
	imageData, err := client.Screenshot()
	if err != nil {
		return fmt.Errorf("failed to capture screenshot: %w", err)
	}

	// Save screenshot
	filename := fmt.Sprintf("%s/%s.png", outputDir, sanitizeFilename(target))
	if err := saveScreenshot(filename, imageData); err != nil {
		return fmt.Errorf("failed to save screenshot: %w", err)
	}

	fmt.Printf("Screenshot saved to %s\n", filename)
	return nil
}

func sanitizeFilename(s string) string {
	// Replace characters that are invalid in filenames
	replacer := strings.NewReplacer(
		":", "_",
		"/", "_",
		"\\", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
	)
	return replacer.Replace(s)
}

func saveScreenshot(filename string, data []byte) error {
	// For now, we'll just save the raw data
	// can't RDP be more like MIME :-/
	return os.WriteFile(filename, data, 0644)
}
