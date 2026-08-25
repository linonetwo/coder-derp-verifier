package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
)

type attestorTarget struct {
	region  uint16
	derpURL string
	private key.NodePrivate
}

type attestorTargetFlags []string

func (f *attestorTargetFlags) String() string { return strings.Join(*f, ",") }
func (f *attestorTargetFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func parseAttestorTargets(values []string) ([]attestorTarget, error) {
	if len(values) == 0 {
		return nil, errors.New("at least one --derp=region=https://host:port/derp is required")
	}
	targets := make([]attestorTarget, 0, len(values))
	seen := map[uint16]struct{}{}
	for _, value := range values {
		regionRaw, derpURL, ok := strings.Cut(value, "=")
		if !ok || strings.TrimSpace(derpURL) == "" {
			return nil, fmt.Errorf("invalid --derp %q", value)
		}
		region, err := strconv.ParseUint(strings.TrimSpace(regionRaw), 10, 16)
		if err != nil || region == 0 {
			return nil, fmt.Errorf("invalid DERP region in %q", value)
		}
		if _, ok := seen[uint16(region)]; ok {
			return nil, fmt.Errorf("duplicate DERP region %d", region)
		}
		if !strings.HasPrefix(derpURL, "https://") || !strings.HasSuffix(strings.TrimRight(derpURL, "/"), "/derp") {
			return nil, fmt.Errorf("DERP target %q must be an https URL ending in /derp", derpURL)
		}
		seen[uint16(region)] = struct{}{}
		targets = append(targets, attestorTarget{region: uint16(region), derpURL: derpURL, private: key.NewNode()})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].region < targets[j].region })
	return targets, nil
}

type attestorHealth struct {
	mu          sync.Mutex
	lastSuccess map[uint16]time.Time
	now         func() time.Time
	staleAfter  time.Duration
}

func newAttestorHealth(targets []attestorTarget, staleAfter time.Duration) *attestorHealth {
	lastSuccess := make(map[uint16]time.Time, len(targets))
	for _, target := range targets {
		lastSuccess[target.region] = time.Time{}
	}
	return &attestorHealth{lastSuccess: lastSuccess, now: time.Now, staleAfter: staleAfter}
}

func (h *attestorHealth) success(region uint16) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastSuccess[region] = h.now().UTC()
}

func (h *attestorHealth) ready() bool {
	now := h.now().UTC()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, lastSuccess := range h.lastSuccess {
		if lastSuccess.IsZero() || now.Sub(lastSuccess) > h.staleAfter {
			return false
		}
	}
	return true
}

func (h *attestorHealth) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !h.ready() {
			http.Error(w, "no recent egress attestation", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func runEgressAttestor(args []string) {
	flags := flag.NewFlagSet("egress-attestor", flag.ExitOnError)
	verifierURL := flags.String("verifier", "", "Tailnet-only verifier base URL")
	tokenFile := flags.String("token-file", "/var/run/secrets/tokens/attestor", "projected service-account token")
	interval := flags.Duration("interval", time.Minute, "attestation renewal interval")
	healthListen := flags.String("health-listen", ":8080", "local health server listen address")
	var targetFlags attestorTargetFlags
	flags.Var(&targetFlags, "derp", "DERP target as region=https://host:port/derp (repeatable)")
	_ = flags.Parse(args)
	if strings.TrimSpace(*verifierURL) == "" || *interval <= 0 {
		slog.Error("--verifier and a positive --interval are required")
		os.Exit(2)
	}
	targets, err := parseAttestorTargets(targetFlags)
	if err != nil {
		slog.Error("configure egress attestor", "error", err)
		os.Exit(2)
	}
	staleAfter := *interval * 3
	if staleAfter < 2*time.Minute {
		staleAfter = 2 * time.Minute
	}
	health := newAttestorHealth(targets, staleAfter)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	healthServer := &http.Server{Addr: *healthListen, Handler: health.handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := healthServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("egress attestor health server failed", "error", err)
			stop()
		}
	}()

	for {
		for _, target := range targets {
			if err := attestDERP(ctx, *verifierURL, *tokenFile, target); err != nil {
				slog.Error("egress attestation failed", "region", target.region, "derp", target.derpURL, "error", err)
				continue
			}
			health.success(target.region)
			slog.Info("egress attestation renewed", "region", target.region, "derp", target.derpURL)
		}
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = healthServer.Shutdown(shutdownCtx)
			return
		case <-time.After(*interval):
		}
	}
}

func attestDERP(ctx context.Context, verifierURL, tokenFile string, target attestorTarget) error {
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return fmt.Errorf("read projected token: %w", err)
	}
	registration := attestationRegistration{NodePublic: target.private.Public(), Region: target.region}
	body, err := json.Marshal(registration)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(verifierURL, "/")+"/attest/register", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("register public key: %w", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("register public key: verifier returned %s", response.Status)
	}
	monitor := netmon.NewStatic()
	defer monitor.Close()
	derpClient, err := derphttp.NewClient(target.private, target.derpURL, func(format string, args ...any) {
		slog.Debug("DERP attestor", "region", target.region, "message", fmt.Sprintf(format, args...))
	}, monitor)
	if err != nil {
		return err
	}
	defer derpClient.Close()
	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := derpClient.Connect(connectCtx); err != nil {
		return err
	}
	return nil
}
