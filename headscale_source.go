package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
	"tailscale.com/tailcfg"
)

type headscaleEndpointStore struct {
	db         *sql.DB
	maxNodeAge time.Duration
	now        func() time.Time
}

func (s *headscaleEndpointStore) Ping(ctx context.Context) error {
	var one int
	return s.db.QueryRowContext(
		ctx,
		"SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'nodes'",
	).Scan(&one)
}

func (s *headscaleEndpointStore) Admit(ctx context.Context, req tailcfg.DERPAdmitClientRequest) (bool, error) {
	source := req.Source
	if !source.IsValid() {
		return false, errors.New("DERP source address is missing")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT endpoints, last_seen, expiry
		FROM nodes
		WHERE deleted_at IS NULL
	`)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	now := s.now().UTC()
	for rows.Next() {
		var endpointsRaw string
		var lastSeenRaw, expiryRaw sql.NullString
		if err := rows.Scan(&endpointsRaw, &lastSeenRaw, &expiryRaw); err != nil {
			return false, err
		}
		lastSeen, err := parseDatabaseTime(lastSeenRaw)
		if err != nil || lastSeen.IsZero() || now.Sub(lastSeen) > s.maxNodeAge {
			continue
		}
		expiry, err := parseDatabaseTime(expiryRaw)
		if err != nil || (!expiry.IsZero() && !expiry.After(now)) {
			continue
		}
		var endpoints []string
		if err := json.Unmarshal([]byte(endpointsRaw), &endpoints); err != nil {
			continue
		}
		for _, endpoint := range endpoints {
			if address, ok := endpointAddress(endpoint); ok && address == source {
				return true, nil
			}
		}
	}
	return false, rows.Err()
}

func endpointAddress(endpoint string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.Addr{}, false
	}
	address, err := netip.ParseAddr(host)
	return address, err == nil
}

func parseDatabaseTime(value sql.NullString) (time.Time, error) {
	if !value.Valid || value.String == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05-07:00"} {
		if parsed, err := time.Parse(layout, value.String); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported database timestamp %q", value.String)
}

func sqliteReadOnlyURL(path string) string {
	return sqliteURL(path, "ro")
}

func sqliteURL(path, mode string) string {
	path = filepath.ToSlash(path)
	if filepath.IsAbs(path) && !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	query := url.Values{}
	query.Set("mode", mode)
	query.Set("_pragma", "busy_timeout=2000")
	return (&url.URL{
		Scheme:   "file",
		Path:     path,
		RawQuery: query.Encode(),
	}).String()
}

func runHeadscaleSource(args []string) {
	flags := flag.NewFlagSet("headscale-source", flag.ExitOnError)
	database := flags.String("database", "", "path to the Headscale SQLite database")
	listen := flags.String("listen", "0.0.0.0", "HTTP listen address")
	port := flags.Int("port", 8080, "HTTP listen port")
	maxNodeAge := flags.Duration("max-node-age", 2*time.Hour, "maximum Headscale node age")
	_ = flags.Parse(args)
	if strings.TrimSpace(*database) == "" {
		slog.Error("--database is required")
		os.Exit(2)
	}

	db, err := sql.Open("sqlite", sqliteReadOnlyURL(*database))
	if err != nil {
		slog.Error("open Headscale database", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	db.SetMaxOpenConns(4)

	app := &server{
		store: &headscaleEndpointStore{
			db:         db,
			maxNodeAge: *maxNodeAge,
			now:        time.Now,
		},
		queryTimeout: defaultQueryTimeout,
		retryCount:   0,
		retryDelay:   0,
		logger:       slog.Default(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /verify", app.verify)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /readyz", app.ready)

	httpServer := &http.Server{
		Addr:              net.JoinHostPort(*listen, fmt.Sprint(*port)),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		slog.Info("starting Headscale source verifier", "addr", httpServer.Addr)
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
