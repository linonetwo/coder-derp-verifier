package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/encoding/protowire"
	"tailscale.com/tailcfg"
)

const (
	defaultAddr         = ":8080"
	defaultQueryTimeout = 2 * time.Second
	defaultRetryCount   = 4
	defaultRetryDelay   = 250 * time.Millisecond
	maxRequestBytes     = 64 << 10
)

type admissionStore interface {
	Admit(context.Context, tailcfg.DERPAdmitClientRequest, uint16) (bool, error)
	Ping(context.Context) error
}

type postgresStore struct {
	pool *pgxpool.Pool
}

func (s *postgresStore) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func (s *postgresStore) Admit(ctx context.Context, req tailcfg.DERPAdmitClientRequest, _ uint16) (bool, error) {
	wanted, err := req.NodePublic.MarshalBinary()
	if err != nil {
		return false, err
	}
	rows, err := s.pool.Query(ctx, `SELECT node FROM tailnet_peers WHERE status = 'ok'::tailnet_status`)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var node []byte
		if err := rows.Scan(&node); err != nil {
			return false, err
		}
		got, err := nodeKey(node)
		if err != nil {
			return false, fmt.Errorf("decode Coder tailnet peer: %w", err)
		}
		if len(got) == len(wanted) && subtle.ConstantTimeCompare(got, wanted) == 1 {
			return true, nil
		}
	}
	return false, rows.Err()
}

// nodeKey extracts field 3 (Node.key) from Coder's tailnet.v2.Node protobuf.
// Keeping this decoder local avoids importing the entire Coder server module.
func nodeKey(node []byte) ([]byte, error) {
	for len(node) > 0 {
		num, typ, n := protowire.ConsumeTag(node)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		node = node[n:]
		if num == 3 {
			if typ != protowire.BytesType {
				return nil, errors.New("Node.key has unexpected wire type")
			}
			value, n := protowire.ConsumeBytes(node)
			if n < 0 {
				return nil, protowire.ParseError(n)
			}
			if len(value) == 0 {
				return nil, errors.New("Node.key is empty")
			}
			return bytes.Clone(value), nil
		}
		n = protowire.ConsumeFieldValue(num, typ, node)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		node = node[n:]
	}
	return nil, errors.New("Node.key field is missing")
}

type server struct {
	store        admissionStore
	attestor     attestationRegistrar
	queryTimeout time.Duration
	retryCount   int
	retryDelay   time.Duration
	logger       *slog.Logger
}

func (s *server) verify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, `{"Allow":false}`, http.StatusMethodNotAllowed)
		return
	}

	var req tailcfg.DERPAdmitClientRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || req.NodePublic.IsZero() || !req.Source.IsValid() {
		s.logger.Warn("invalid admission request", "source", r.RemoteAddr, "error", err)
		http.Error(w, `{"Allow":false}`, http.StatusBadRequest)
		return
	}

	region, err := requestDERPRegion(r)
	if err != nil {
		s.logger.Warn("invalid DERP region", "region", r.URL.Query().Get("region"), "error", err)
		http.Error(w, `{"Allow":false}`, http.StatusBadRequest)
		return
	}

	for attempt := 0; attempt <= s.retryCount; attempt++ {
		ctx, cancel := context.WithTimeout(r.Context(), s.queryTimeout)
		allow, queryErr := s.store.Admit(ctx, req, region)
		cancel()
		if queryErr != nil {
			s.logger.Error("admission lookup failed", "source", req.Source, "error", queryErr)
			http.Error(w, `{"Allow":false}`, http.StatusServiceUnavailable)
			return
		}
		if allow {
			_ = json.NewEncoder(w).Encode(tailcfg.DERPAdmitClientResponse{Allow: true})
			return
		}
		if attempt < s.retryCount {
			select {
			case <-r.Context().Done():
				http.Error(w, `{"Allow":false}`, http.StatusRequestTimeout)
				return
			case <-time.After(s.retryDelay):
			}
		}
	}

	s.logger.Warn("rejected DERP client", "source", req.Source, "region", region)
	_ = json.NewEncoder(w).Encode(tailcfg.DERPAdmitClientResponse{Allow: false})
}

func requestDERPRegion(r *http.Request) (uint16, error) {
	value := strings.TrimSpace(r.URL.Query().Get("region"))
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil || parsed == 0 {
		return 0, errors.New("region must be a non-zero uint16")
	}
	return uint16(parsed), nil
}

func (s *server) registerAttestor(w http.ResponseWriter, r *http.Request) {
	if s.attestor == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var registration attestationRegistration
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registration); err != nil || registration.NodePublic.IsZero() || registration.Region == 0 {
		s.logger.Warn("invalid egress attestation registration", "source", r.RemoteAddr, "error", err)
		http.Error(w, "invalid registration", http.StatusBadRequest)
		return
	}
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	token, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok || strings.TrimSpace(token) == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.queryTimeout)
	err := s.attestor.Register(ctx, registration, token)
	cancel()
	if err != nil {
		s.logger.Warn("rejected egress attestation registration", "source", r.RemoteAddr, "region", registration.Region, "error", err)
		http.Error(w, "attestation registration rejected", http.StatusForbidden)
		return
	}
	s.logger.Info("registered egress attestor", "region", registration.Region, "node_public", registration.NodePublic.ShortString())
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), s.queryTimeout)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		slog.Error("invalid duration environment variable", "name", name, "value", value, "error", err)
		os.Exit(2)
	}
	return parsed
}

func envInt(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		slog.Error("invalid integer environment variable", "name", name, "value", value)
		os.Exit(2)
	}
	return parsed
}

func runPostgres() {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		slog.Error("DATABASE_URL is required")
		os.Exit(2)
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = defaultAddr
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		slog.Error("configure PostgreSQL", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	app := &server{
		store:        &postgresStore{pool: pool},
		queryTimeout: envDuration("QUERY_TIMEOUT", defaultQueryTimeout),
		retryCount:   envInt("UNKNOWN_KEY_RETRIES", defaultRetryCount),
		retryDelay:   envDuration("UNKNOWN_KEY_RETRY_DELAY", defaultRetryDelay),
		logger:       slog.Default(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /verify", app.verify)
	mux.HandleFunc("POST /attest/register", app.registerAttestor)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", app.ready)

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		slog.Info("starting Coder DERP verifier", "addr", addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("HTTP server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "headscale-source" {
		runHeadscaleSource(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "egress-attestor" {
		runEgressAttestor(os.Args[2:])
		return
	}
	runPostgres()
}
