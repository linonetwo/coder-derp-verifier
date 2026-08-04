package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type fakeStore struct {
	contains bool
	err      error
	calls    int
}

func (f *fakeStore) Admit(context.Context, tailcfg.DERPAdmitClientRequest) (bool, error) {
	f.calls++
	return f.contains, f.err
}
func (f *fakeStore) Ping(context.Context) error { return f.err }

func TestNodeKey(t *testing.T) {
	want := bytes.Repeat([]byte{0x42}, 32)
	var encoded []byte
	encoded = protowire.AppendTag(encoded, 1, protowire.VarintType)
	encoded = protowire.AppendVarint(encoded, 123)
	encoded = protowire.AppendTag(encoded, 3, protowire.BytesType)
	encoded = protowire.AppendBytes(encoded, want)

	got, err := nodeKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestVerify(t *testing.T) {
	private := key.NewNode()
	reqBody, err := json.Marshal(tailcfg.DERPAdmitClientRequest{NodePublic: private.Public()})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		store  *fakeStore
		status int
		allow  bool
	}{
		{"allow known key", &fakeStore{contains: true}, http.StatusOK, true},
		{"reject unknown key", &fakeStore{}, http.StatusOK, false},
		{"fail closed on database error", &fakeStore{err: errors.New("down")}, http.StatusServiceUnavailable, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := &server{
				store:        tt.store,
				queryTimeout: time.Second,
				retryCount:   0,
				retryDelay:   time.Millisecond,
				logger:       testLogger(t),
			}
			request := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(reqBody))
			response := httptest.NewRecorder()
			app.verify(response, request)
			if response.Code != tt.status {
				t.Fatalf("status %d, want %d; body=%s", response.Code, tt.status, response.Body.String())
			}
			var result tailcfg.DERPAdmitClientResponse
			_ = json.Unmarshal(response.Body.Bytes(), &result)
			if result.Allow != tt.allow {
				t.Fatalf("allow %v, want %v", result.Allow, tt.allow)
			}
		})
	}
}

func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
