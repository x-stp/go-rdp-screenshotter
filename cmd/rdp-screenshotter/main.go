















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

	
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	
	targets, err := readTargets(*targetFile)
	if err != nil {
		log.Fatalf("Failed to read targets: %v", err)
	}

	if len(targets) == 0 {
		log.Fatal("No targets found in file")
	}

	fmt.Printf("Found %d targets\n", len(targets))
	fmt.Printf("Using %d concurrent workers\n", *workers)

	
	targetChan := make(chan targetWork, len(targets))
	resultChan := make(chan targetResult, len(targets))

	
	var wg sync.WaitGroup

	
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(i+1, targetChan, resultChan, &wg, *timeout, *username, *password, *domain, *outputDir)
	}

	
	for i, target := range targets {
		targetChan <- targetWork{
			index:  i + 1,
			total:  len(targets),
			target: target,
		}
	}
	close(targetChan)

	
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	
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
		
		opts := &rdp.ClientOptions{
			Timeout:  timeout,
			Username: username,
			Password: password,
			Domain:   domain,
			EnableAutoDetect: true,  
			EnableHeartbeat: true,   
		}

		
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
		
		if line != "" && !strings.HasPrefix(line, "#") {
			
			if !strings.Contains(line, ":") {
				line += ":3389"
			}
			targets = append(targets, line)
		}
	}

	return targets, scanner.Err()
}

func captureScreenshot(target string, opts *rdp.ClientOptions, outputDir string) (string, error) {
	
	client, err := rdp.NewClient(target, opts)
	if err != nil {
		return "", fmt.Errorf("failed to create client: %w", err)
	}
	defer client.Close()

	
	imageData, err := client.Screenshot()
	if err != nil {
		return "", fmt.Errorf("failed to capture screenshot: %w", err)
	}

	
	filename := fmt.Sprintf("%s/%s.png", outputDir, sanitizeFilename(target))
	if err := saveScreenshot(filename, imageData); err != nil {
		return "", fmt.Errorf("failed to save screenshot: %w", err)
	}

	return filename, nil
}

func sanitizeFilename(s string) string {
	
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
	
	
	return os.WriteFile(filename, data, 0644)
}
