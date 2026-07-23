package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valyala/fasthttp"
)

type Result struct {
	URL           string `json:"url"`
	Status        int    `json:"status"`
	ContentLength int    `json:"length"`
}

func randomString(n int) string {
	bytes := make([]byte, n/2+1)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)[:n]
}

func main() {
	targetURL := flag.String("u", "", "Target URL with FUZZ placeholder")
	wordlistPath := flag.String("w", "", "Path to wordlist")
	threads := flag.Int("t", 50, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "Timeout in seconds")
	flag.Parse()

	if *targetURL == "" || *wordlistPath == "" {
		errObj, _ := json.Marshal(map[string]string{"error": "Missing target or wordlist"})
		fmt.Println(string(errObj))
		os.Exit(1)
	}

	if !strings.Contains(*targetURL, "FUZZ") {
		errObj, _ := json.Marshal(map[string]string{"error": "Target URL must contain FUZZ placeholder"})
		fmt.Println(string(errObj))
		os.Exit(1)
	}

	// Open wordlist
	file, err := os.Open(*wordlistPath)
	if err != nil {
		errObj, _ := json.Marshal(map[string]string{"error": fmt.Sprintf("Failed to open wordlist: %v", err)})
		fmt.Println(string(errObj))
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

	// 1. Baseline Calibration for Catch-All 200/302 Detection
	randPayload := "falsealarm_rand_" + randomString(10)
	baselineURL := strings.ReplaceAll(*targetURL, "FUZZ", randPayload)

	reqBase := fasthttp.AcquireRequest()
	resBase := fasthttp.AcquireResponse()
	reqBase.SetRequestURI(baselineURL)
	reqBase.Header.SetMethod("GET")
	reqBase.Header.Set("User-Agent", "FalseAlarm-Go-Engine/1.0")

	baselineStatus := 0
	baselineLen := 0
	hasBaseline := false

	if err := client.Do(reqBase, resBase); err == nil {
		baselineStatus = resBase.StatusCode()
		baselineLen = len(resBase.Body())
		if baselineStatus == 200 || baselineStatus == 301 || baselineStatus == 302 {
			hasBaseline = true
		}
	}
	fasthttp.ReleaseRequest(reqBase)
	fasthttp.ReleaseResponse(resBase)

	// Setup workers and channels
	jobs := make(chan string, *threads*2)
	var wg sync.WaitGroup
	var activeBackoff int32 // atomic flag for 429 rate limit backoff

	// Start worker goroutines
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for payload := range jobs {
				// Handle 429 backoff sleep if triggered by another worker
				if atomic.LoadInt32(&activeBackoff) > 0 {
					time.Sleep(1 * time.Second)
				}

				testURL := strings.ReplaceAll(*targetURL, "FUZZ", url.PathEscape(payload))

				req := fasthttp.AcquireRequest()
				res := fasthttp.AcquireResponse()
				req.SetRequestURI(testURL)
				req.Header.SetMethod("GET")
				req.Header.Set("User-Agent", "FalseAlarm-Go-Engine/1.0")

				err := client.Do(req, res)
				if err == nil {
					status := res.StatusCode()
					bodyLen := len(res.Body())

					// Handle 429 Rate Limiting
					if status == 429 {
						atomic.StoreInt32(&activeBackoff, 1)
						time.Sleep(2 * time.Second)
						atomic.StoreInt32(&activeBackoff, 0)
					} else if status != 404 && status != 400 && status != 0 {
						// Baseline catch-all comparison
						isFP := false
						if hasBaseline && status == baselineStatus {
							diff := math.Abs(float64(bodyLen - baselineLen))
							if diff < 50 { // If length matches baseline within 50 bytes tolerance
								isFP = true
							}
						}

						if !isFP {
							r := Result{
								URL:           testURL,
								Status:        status,
								ContentLength: bodyLen,
							}
							// NDJSON Streaming Output to stdout immediately
							out, _ := json.Marshal(r)
							fmt.Println(string(out))
						}
					}
				}

				fasthttp.ReleaseRequest(req)
				fasthttp.ReleaseResponse(res)
			}
		}()
	}

	// Feed jobs
	for _, w := range words {
		jobs <- w
	}
	close(jobs)

	// Wait for all workers to finish
	wg.Wait()
}
