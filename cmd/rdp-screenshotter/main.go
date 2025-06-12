// RDP Screenshotter Go - Capture screenshots from RDP servers
// Copyright (C) 2025 - Pepijn van der Stap, pepijn@neosecurity.nl
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
	"sync"
	"time"

	"github.com/x-stp/rdp-screenshotter-go/pkg/rdp"
)

func main() {
	var (
		targetFile = flag.String("targets", "target.txt", "File containing RDP targets (one per line)")
		timeout    = flag.Duration("timeout", 10*time.Second, "Connection timeout")
		username   = flag.String("username", "", "Username for RDP cookie (optional)")
		password   = flag.String("password", "", "Password for NLA authentication (optional)")
		domain     = flag.String("domain", "", "Domain for NLA authentication (optional)")
		outputDir  = flag.String("output", "screenshots", "Output directory for screenshots")
		workers    = flag.Int("workers", 5, "Number of concurrent workers")
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
	fmt.Printf("Using %d concurrent workers\n", *workers)

	// Create channels for work distribution
	targetChan := make(chan targetWork, len(targets))
	resultChan := make(chan targetResult, len(targets))

	// Create wait group for workers
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(i+1, targetChan, resultChan, &wg, *timeout, *username, *password, *domain, *outputDir)
	}

	// Send work to channel
	for i, target := range targets {
		targetChan <- targetWork{
			index:  i + 1,
			total:  len(targets),
			target: target,
		}
	}
	close(targetChan)

	// Start result collector
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	successCount := 0
	failCount := 0
	for result := range resultChan {
		if result.success {
			successCount++
			fmt.Printf("[%d/%d] ✓ %s - Screenshot saved to %s\n",
				result.work.index, result.work.total, result.work.target, result.filename)
		} else {
			failCount++
			fmt.Printf("[%d/%d] ✗ %s - %v\n",
				result.work.index, result.work.total, result.work.target, result.err)
		}
	}

	fmt.Printf("\nCompleted: %d successful, %d failed\n", successCount, failCount)
}

type targetWork struct {
	index  int
	total  int
	target string
}

type targetResult struct {
	work     targetWork
	success  bool
	filename string
	err      error
}

func worker(id int, targets <-chan targetWork, results chan<- targetResult, wg *sync.WaitGroup,
	timeout time.Duration, username string, password string, domain string, outputDir string) {
	defer wg.Done()

	for work := range targets {
		// Create client options
		opts := &rdp.ClientOptions{
			Timeout:  timeout,
			Username: username,
			Password: password,
			Domain:   domain,
		}

		// Try to capture screenshot
		filename, err := captureScreenshot(work.target, opts, outputDir)

		results <- targetResult{
			work:     work,
			success:  err == nil,
			filename: filename,
			err:      err,
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

func captureScreenshot(target string, opts *rdp.ClientOptions, outputDir string) (string, error) {
	// Create RDP client
	client, err := rdp.NewClient(target, opts)
	if err != nil {
		return "", fmt.Errorf("failed to create client: %w", err)
	}
	defer client.Close()

	// Capture screenshot
	imageData, err := client.Screenshot()
	if err != nil {
		return "", fmt.Errorf("failed to capture screenshot: %w", err)
	}

	// Save screenshot
	filename := fmt.Sprintf("%s/%s.png", outputDir, sanitizeFilename(target))
	if err := saveScreenshot(filename, imageData); err != nil {
		return "", fmt.Errorf("failed to save screenshot: %w", err)
	}

	return filename, nil
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
