package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

type Result struct {
	URL           string `json:"url"`
	Status        int    `json:"status"`
	ContentLength int    `json:"length"`
}

func main() {
	targetURL := flag.String("u", "", "Target URL with FUZZ placeholder")
	wordlistPath := flag.String("w", "", "Path to wordlist")
	threads := flag.Int("t", 50, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "Timeout in seconds")
	flag.Parse()

	if *targetURL == "" || *wordlistPath == "" {
		fmt.Println(`{"error": "Missing target or wordlist"}`)
		os.Exit(1)
	}

	if !strings.Contains(*targetURL, "FUZZ") {
		fmt.Println(`{"error": "Target URL must contain FUZZ placeholder"}`)
		os.Exit(1)
	}

	// Read wordlist
	file, err := os.Open(*wordlistPath)
	if err != nil {
		fmt.Printf(`{"error": "Failed to open wordlist: %v"}`+"\n", err)
		os.Exit(1)
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		w := strings.TrimSpace(scanner.Text())
		if w != "" {
			words = append(words, w)
		}
	}

	// Configure fasthttp client
	client := &fasthttp.Client{
		NoDefaultUserAgentHeader: true,
		MaxConnsPerHost:          *threads,
		ReadTimeout:              time.Duration(*timeout) * time.Second,
		WriteTimeout:             time.Duration(*timeout) * time.Second,
	}

	// Setup workers
	jobs := make(chan string, len(words))
	results := make(chan Result, len(words))
	var wg sync.WaitGroup

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range jobs {
				testURL := strings.ReplaceAll(*targetURL, "FUZZ", payload)
				
				req := fasthttp.AcquireRequest()
				res := fasthttp.AcquireResponse()
				
				req.SetRequestURI(testURL)
				req.Header.SetMethod("GET")
				req.Header.Set("User-Agent", "FalseAlarm-Go-Engine/1.0")

				err := client.Do(req, res)
				if err == nil {
					status := res.StatusCode()
					// Simple filter: 200, 301, 302, 401, 403, 500
					if status != 404 && status != 400 {
						results <- Result{
							URL:           testURL,
							Status:        status,
							ContentLength: len(res.Body()),
						}
					}
				}
				
				fasthttp.ReleaseRequest(req)
				fasthttp.ReleaseResponse(res)
			}
		}()
	}

	// Send jobs
	for _, w := range words {
		jobs <- w
	}
	close(jobs)

	// Wait for completion in a goroutine to close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var finalResults []Result
	for r := range results {
		finalResults = append(finalResults, r)
	}

	// Output as JSON for Python to consume
	out, _ := json.Marshal(finalResults)
	fmt.Println(string(out))
}
