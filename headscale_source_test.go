package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"tailscale.com/tailcfg"
)

func TestEndpointAddress(t *testing.T) {
	tests := map[string]string{
		"192.0.2.1:123":     "192.0.2.1",
		"[2001:db8::1]:123": "2001:db8::1",
	}
	for input, want := range tests {
		got, ok := endpointAddress(input)
		if !ok || got.String() != want {
			t.Fatalf("endpointAddress(%q) = %v, %v; want %s, true", input, got, ok, want)
		}
	}
	if _, ok := endpointAddress("invalid"); ok {
		t.Fatal("invalid endpoint was accepted")
	}
}

func TestHeadscaleEndpointStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "headscale.db")
	db, err := sql.Open("sqlite", sqliteURL(path, "rwc"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE nodes (
		ip_addresses TEXT, endpoints TEXT, last_seen TEXT, expiry TEXT, deleted_at TEXT
	)`); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	add := func(addresses, endpoints []string, lastSeen time.Time, expiry *time.Time, deleted bool) {
		t.Helper()
		encodedAddresses, _ := json.Marshal(addresses)
		encodedEndpoints, _ := json.Marshal(endpoints)
		var expiryValue any
		if expiry != nil {
			expiryValue = expiry.Format(time.RFC3339Nano)
		}
		var deletedValue any
		if deleted {
			deletedValue = now.Format(time.RFC3339Nano)
		}
		if _, err := db.Exec(
			"INSERT INTO nodes VALUES (?, ?, ?, ?, ?)",
			string(encodedAddresses), string(encodedEndpoints),
			lastSeen.Format(time.RFC3339Nano), expiryValue, deletedValue,
		); err != nil {
			t.Fatal(err)
		}
	}
	add(
		[]string{"100.64.0.7", "fd7a:115c:a1e0::7"},
		[]string{"198.51.100.7:41641", "[2001:db8::7]:41641"},
		now, nil, false,
	)
	add([]string{"100.64.0.8"}, []string{"198.51.100.8:41641"}, now.Add(-3*time.Hour), nil, false)
	expired := now.Add(-time.Second)
	add([]string{"100.64.0.9"}, []string{"198.51.100.9:41641"}, now, &expired, false)
	add([]string{"100.64.0.10"}, []string{"198.51.100.10:41641"}, now, nil, true)

	store := &headscaleEndpointStore{db: db, maxNodeAge: 2 * time.Hour, now: func() time.Time { return now }}
	for _, source := range []string{
		"100.64.0.7",
		"fd7a:115c:a1e0::7",
		"198.51.100.7",
		"2001:db8::7",
	} {
		allowed, err := store.Admit(context.Background(), tailcfg.DERPAdmitClientRequest{Source: netip.MustParseAddr(source)})
		if err != nil || !allowed {
			t.Fatalf("source %s: allowed=%v err=%v", source, allowed, err)
		}
	}
	for _, source := range []string{
		"100.64.0.8",
		"100.64.0.9",
		"100.64.0.10",
		"100.64.0.11",
		"fd7a:115c:a1e0::11",
		"198.51.100.8",
		"198.51.100.9",
		"198.51.100.10",
		"198.51.100.11",
	} {
		allowed, err := store.Admit(context.Background(), tailcfg.DERPAdmitClientRequest{Source: netip.MustParseAddr(source)})
		if err != nil || allowed {
			t.Fatalf("source %s: allowed=%v err=%v", source, allowed, err)
		}
	}
}

func TestSQLiteReadOnlyURL(t *testing.T) {
	got := sqliteReadOnlyURL("/var/lib/headscale/db/headscale.db")
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "file" || parsed.Path != "/var/lib/headscale/db/headscale.db" ||
		parsed.Query().Get("mode") != "ro" || parsed.Query().Get("_pragma") != "busy_timeout=2000" {
		t.Fatalf("got %q", got)
	}
}
