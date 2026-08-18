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

type headscaleAddressSchema int

const (
	headscaleAddressSchemaUnknown headscaleAddressSchema = iota
	headscaleAddressSchemaSeparate
	headscaleAddressSchemaArray
)

func (s *headscaleEndpointStore) addressSchema(ctx context.Context) (headscaleAddressSchema, error) {
	rows, err := s.db.QueryContext(ctx, "PRAGMA table_info(nodes)")
	if err != nil {
		return headscaleAddressSchemaUnknown, err
	}
	defer rows.Close()

	var hasIPv4, hasIPv6, hasIPAddresses bool
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			return headscaleAddressSchemaUnknown, err
		}
		switch name {
		case "ipv4":
			hasIPv4 = true
		case "ipv6":
			hasIPv6 = true
		case "ip_addresses":
			hasIPAddresses = true
		}
	}
	if err := rows.Err(); err != nil {
		return headscaleAddressSchemaUnknown, err
	}
	if hasIPAddresses {
		return headscaleAddressSchemaArray, nil
	}
	if hasIPv4 && hasIPv6 {
		return headscaleAddressSchemaSeparate, nil
	}
	return headscaleAddressSchemaUnknown, errors.New("Headscale nodes address columns are unavailable")
}

func (s *headscaleEndpointStore) Ping(ctx context.Context) error {
	_, err := s.addressSchema(ctx)
	return err
}

func (s *headscaleEndpointStore) Admit(ctx context.Context, req tailcfg.DERPAdmitClientRequest) (bool, error) {
	source := req.Source
	if !source.IsValid() {
		return false, errors.New("DERP source address is missing")
	}
	schema, err := s.addressSchema(ctx)
	if err != nil {
		return false, err
	}
	var rows *sql.Rows
	switch schema {
	case headscaleAddressSchemaArray:
		rows, err = s.db.QueryContext(ctx, `
			SELECT ip_addresses, '', endpoints, last_seen, expiry
			FROM nodes
			WHERE deleted_at IS NULL
		`)
	case headscaleAddressSchemaSeparate:
		rows, err = s.db.QueryContext(ctx, `
			SELECT ipv4, ipv6, endpoints, last_seen, expiry
			FROM nodes
			WHERE deleted_at IS NULL
		`)
	default:
		return false, errors.New("unsupported Headscale nodes address schema")
	}
	if err != nil {
		return false, err
	}
	defer rows.Close()

	now := s.now().UTC()
	for rows.Next() {
		var firstAddressRaw, secondAddressRaw, endpointsRaw string
		var lastSeenRaw, expiryRaw sql.NullString
		if err := rows.Scan(&firstAddressRaw, &secondAddressRaw, &endpointsRaw, &lastSeenRaw, &expiryRaw); err != nil {
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
		var addresses []string
		if schema == headscaleAddressSchemaArray {
			if err := json.Unmarshal([]byte(firstAddressRaw), &addresses); err != nil {
				return false, fmt.Errorf("parse Headscale node ip_addresses: %w", err)
			}
		} else {
			addresses = []string{firstAddressRaw, secondAddressRaw}
		}
		for _, rawAddress := range addresses {
			if strings.TrimSpace(rawAddress) == "" {
				continue
			}
			address, err := netip.ParseAddr(rawAddress)
			if err != nil {
				return false, fmt.Errorf("parse Headscale node IP address %q: %w", rawAddress, err)
			}
			if address == source {
				return true, nil
			}
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
