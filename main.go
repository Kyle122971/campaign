package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/time/rate"
)

// --- HARDCODED CREDENTIALS ---
const (
	MyWallet      = "0xCf2126b7e17b53D600323a7E37Be49AD15BcaF94"
	CDP_KEY_ID    = "13421f57-691e-439d-8b87-dc976ea5042a"
	CDP_SECRET    = "eOiSYPC0ROZcYGy/4dQXsN9eNMcfNc6Kk9aytYT3LYlbrAYvdO5FtokhB0qptWuOY8y5RzLqinN3gjst0ZIzlQ=="
	USDC_BASE     = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

	FacilitatorVerify = "https://facilitator.payai.network/verify"
	BazaarDiscovery   = "https://api.cdp.coinbase.com"
	MoltbookAPI       = "https://www.moltbook.com/api/v1/posts/trending"

	NetworkCAIP2   = "eip155:8453"
	PriceUSDC      = 200000 
	TargetPokeRate = 1450
	WorkerCount    = 2000
	PokeCooldown   = 15 * time.Minute
)

var (
	successCount    atomic.Int64
	seenURLs        sync.Map
	verifiedURLs    sync.Map
	verifiedTargets []string
	vtMu            sync.Mutex

	engineClient = &http.Client{
		Timeout: 800 * time.Millisecond,
		Transport: &http.Transport{
			MaxIdleConns:        10000,
			MaxIdleConnsPerHost: 5000,
			IdleConnTimeout:     10 * time.Second,
		},
	}
)

func init() {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
		rLimit.Cur = 100000; rLimit.Max = 100000
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	}
}

func main() {
	jobQueue := make(chan string, 1000000)
	limiter := rate.NewLimiter(rate.Limit(TargetPokeRate), 100)

	// Scraper Loop
	go func() {
		for {
			scrapeAndFeed(jobQueue)
			time.Sleep(15 * time.Minute)
		}
	}()

	// Worker Pool
	for i := 0; i < WorkerCount; i++ {
		go func() {
			for target := range jobQueue {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				limiter.Wait(ctx)
				pokeWithCooldown(ctx, target)
				cancel()
			}
		}()
	}

	http.HandleFunc("/alert", revenueHandler)
	fmt.Printf("[LATTICE] Engine Online | Base | Port :4021\n")
	http.ListenAndServe(":4021", nil)
}

// --- EIP-3009 SIGNER ---
func buildExactPaymentPayload(target, payTo string) string {
	nonceBytes := make([]byte, 32)
	rand.Read(nonceBytes)
	nonce := "0x" + hex.EncodeToString(nonceBytes)
	now := time.Now().Unix()
	validAfter, validBefore := now-300, now+3600

	domainSeparator := crypto.Keccak256Hash(
		crypto.Keccak256([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")),
		crypto.Keccak256([]byte("USD Coin")),
		crypto.Keccak256([]byte("2")),
		math.U256Bytes(big.NewInt(8453)),
		common.HexToAddress(USDC_BASE).Bytes(),
	)

	structHash := crypto.Keccak256Hash(
		crypto.Keccak256([]byte("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")),
		common.LeftPadBytes(common.HexToAddress(MyWallet).Bytes(), 32),
		common.LeftPadBytes(common.HexToAddress(payTo).Bytes(), 32),
		math.U256Bytes(big.NewInt(PriceUSDC)),
		math.U256Bytes(big.NewInt(validAfter)),
		math.U256Bytes(big.NewInt(validBefore)),
		common.HexToHash(nonce).Bytes(),
	)

	digest := crypto.Keccak256Hash([]byte("\x19\x01"), domainSeparator.Bytes(), structHash.Bytes())
	priv, _ := loadKey()
	sig, _ := crypto.Sign(digest.Bytes(), priv)
	if sig[64] < 27 { sig[64] += 27 }

	payload := map[string]interface{}{
		"scheme": "exact",
		"payload": map[string]interface{}{
			"signature": "0x" + hex.EncodeToString(sig),
			"authorization": map[string]interface{}{
				"from": MyWallet, "to": payTo, "value": fmt.Sprintf("%d", PriceUSDC),
				"validAfter": fmt.Sprintf("%d", validAfter), "validBefore": fmt.Sprintf("%d", validBefore), "nonce": nonce,
			},
		},
	}
	b, _ := json.Marshal(payload)
	return base64.StdEncoding.EncodeToString(b)
}

// --- REVENUE HANDLER ---
func revenueHandler(w http.ResponseWriter, r *http.Request) {
	sig := r.Header.Get("PAYMENT-SIGNATURE")
	if sig == "" {
		cfg := map[string]interface{}{
			"accepts": []map[string]interface{}{{"scheme": "exact", "price": PriceUSDC, "network": NetworkCAIP2, "payTo": MyWallet}},
			"description": "K.A.B 18-Row Lattice Signal (3x6x3)",
		}
		b, _ := json.Marshal(cfg)
		w.Header().Set("PAYMENT-REQUIRED", base64.StdEncoding.EncodeToString(b))
		w.WriteHeader(402)
		return
	}

	token := signJWT()
	vReq, _ := http.NewRequest("POST", FacilitatorVerify, bytes.NewBuffer([]byte(sig)))
	vReq.Header.Set("Authorization", "Bearer "+token)
	vResp, err := engineClient.Do(vReq)
	if err != nil || vResp.StatusCode != 200 {
		w.WriteHeader(403); return
	}
	vResp.Body.Close()

	vtMu.Lock()
	if len(verifiedTargets) < 18 {
		vtMu.Unlock(); w.WriteHeader(503); return
	}
	targets := append([]string{}, verifiedTargets[:18]...)
	vtMu.Unlock()

	results := make([]byte, 18)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(idx int, url string) {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(r.Context(), "GET", url, nil)
			resp, err := engineClient.Do(req)
			if err == nil { 
				results[idx] = byte(resp.StatusCode)
				resp.Body.Close() 
			}
		}(i, t)
	}
	wg.Wait()

	h1, h2, h3 := sha256.Sum256(results[0:6]), sha256.Sum256(results[6:12]), sha256.Sum256(results[12:18])
	solveID := hex.EncodeToString(h1[:]) + hex.EncodeToString(h2[:]) + hex.EncodeToString(h3[:])
	
	respData := map[string]interface{}{"status": "settled", "solve": solveID}
	b, _ := json.Marshal(respData)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write(b)
	successCount.Add(1)
}

// --- UTILS ---
func loadKey() (*ecdsa.PrivateKey, error) {
	b, _ := base64.StdEncoding.DecodeString(CDP_SECRET)
	if k, err := x509.ParsePKCS8PrivateKey(b); err == nil {
		return k.(*ecdsa.PrivateKey), nil
	}
	return crypto.HexToECDSA(strings.TrimPrefix(CDP_SECRET, "0x"))
}

func signJWT() string {
	priv, _ := loadKey()
	claims := jwt.MapClaims{"sub": CDP_KEY_ID, "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()}
	t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	t.Header["kid"] = CDP_KEY_ID
	s, _ := t.SignedString(priv)
	return s
}

func scrapeAndFeed(queue chan<- string) {
	if mResp, err := engineClient.Get(MoltbookAPI); err == nil {
		var d struct{ Posts []struct{ AuthorURL string `json:"author_endpoint"` } `json:"posts"` }
		if json.NewDecoder(mResp.Body).Decode(&d) == nil {
			for _, p := range d.Posts {
				if p.AuthorURL != "" { handleDiscovery(p.AuthorURL, queue) }
			}
		}
		mResp.Body.Close()
	}

	if bResp, err := engineClient.Get(BazaarDiscovery); err == nil {
		body, _ := io.ReadAll(bResp.Body); bResp.Body.Close()
		re := regexp.MustCompile(`https?://[^\s"'<>]+`)
		for _, u := range re.FindAllString(string(body), -1) {
			if strings.Contains(u, ".ai") || strings.Contains(u, "agent") {
				handleDiscovery(u, queue)
			}
		}
	}
}

func handleDiscovery(url string, queue chan<- string) {
	if _, seen := seenURLs.LoadOrStore(url, true); !seen {
		select {
		case queue <- url:
			vtMu.Lock(); verifiedTargets = append(verifiedTargets, url); vtMu.Unlock()
		default:
		}
	}
}

func pokeWithCooldown(ctx context.Context, url string) {
	stateI, _ := verifiedURLs.LoadOrStore(url, &TargetState{LastPoke: time.Now().Add(-PokeCooldown)})
	state := stateI.(*TargetState)
	if time.Since(state.LastPoke) < PokeCooldown { return }
	state.LastPoke = time.Now()

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := engineClient.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == 402 {
			sig := buildExactPaymentPayload(url, MyWallet)
			req2, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
			req2.Header.Set("PAYMENT-SIGNATURE", sig)
			r2, _ := engineClient.Do(req2)
			if r2 != nil { r2.Body.Close() }
		}
	}
}

type TargetState struct{ LastPoke time.Time }
