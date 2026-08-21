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
	"github.com/valyala/fasthttp/fasthttpproxy"
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

func emitError(msg string) {
	errObj, _ := json.Marshal(map[string]string{"error": msg})
	fmt.Println(string(errObj))
}

func main() {
	targetURL := flag.String("u", "", "Target URL with FUZZ placeholder")
	wordlistPath := flag.String("w", "", "Path to wordlist")
	threads := flag.Int("t", 50, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "Timeout in seconds")
	proxy := flag.String("proxy", "", "Proxy URL (http://host:port or socks5://host:port)")
	rate := flag.Int("rate", 0, "Max requests per second (0 = unlimited)")
	userAgent := flag.String("ua", "FalseAlarm-Go-Engine/1.0", "User-Agent header value")
	flag.Parse()

	if *targetURL == "" || *wordlistPath == "" {
		emitError("Missing target or wordlist")
		os.Exit(1)
	}

	if !strings.Contains(*targetURL, "FUZZ") {
		emitError("Target URL must contain FUZZ placeholder")
		os.Exit(1)
	}

	// Open wordlist
	file, err := os.Open(*wordlistPath)
	if err != nil {
		emitError(fmt.Sprintf("Failed to open wordlist: %v", err))
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

	// Route traffic through the proxy so the Go engine honours the same
	// OPSEC posture (Tor / proxy chains) as the Python orchestrator.
	if *proxy != "" {
		if strings.HasPrefix(*proxy, "socks") {
			client.Dial = fasthttpproxy.FasthttpSocksDialer(*proxy)
		} else {
			addr := *proxy
			addr = strings.TrimPrefix(addr, "http://")
			addr = strings.TrimPrefix(addr, "https://")
			client.Dial = fasthttpproxy.FasthttpHTTPDialer(addr)
		}
	}

	// Global rate limiter shared by all workers (token every 1/rate seconds).
	var limiter <-chan time.Time
	if *rate > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(*rate))
		defer ticker.Stop()
		limiter = ticker.C
	}

	doRequest := func(u string) (int, int, error) {
		req := fasthttp.AcquireRequest()
		res := fasthttp.AcquireResponse()
		defer fasthttp.ReleaseRequest(req)
		defer fasthttp.ReleaseResponse(res)
		req.SetRequestURI(u)
		req.Header.SetMethod("GET")
		req.Header.Set("User-Agent", *userAgent)
		if err := client.Do(req, res); err != nil {
			return 0, 0, err
		}
		return res.StatusCode(), len(res.Body()), nil
	}

	// 1. Baseline Calibration for Catch-All 200/302 Detection
	randPayload := "falsealarm_rand_" + randomString(10)
	baselineURL := strings.ReplaceAll(*targetURL, "FUZZ", randPayload)

	baselineStatus := 0
	baselineLen := 0
	hasBaseline := false

	if status, bodyLen, err := doRequest(baselineURL); err == nil {
		baselineStatus = status
		baselineLen = bodyLen
		if baselineStatus != 0 && baselineStatus != 404 {
			hasBaseline = true
		}
	}

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
				// Honour global rate limit if configured.
				if limiter != nil {
					<-limiter
				}
				// Handle 429 backoff sleep if triggered by another worker
				if atomic.LoadInt32(&activeBackoff) > 0 {
					time.Sleep(1 * time.Second)
				}

				testURL := strings.ReplaceAll(*targetURL, "FUZZ", url.PathEscape(payload))

				status, bodyLen, err := doRequest(testURL)
				if err == nil {
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
							tolerance := math.Max(50, float64(baselineLen)*0.03)
							if diff <= tolerance {
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
