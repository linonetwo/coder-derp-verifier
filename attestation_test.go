package main

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type fakeTokenReviewer struct {
	identity attestationIdentity
	err      error
}

func (f fakeTokenReviewer) Review(context.Context, string) (attestationIdentity, error) {
	return f.identity, f.err
}

func TestEgressAttestationBindsObservedSourceToRegion(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	store, err := newEgressAttestation(egressAttestationConfig{
		Regions:               "1002",
		LeaseTTL:              5 * time.Minute,
		RegistrationTTL:       20 * time.Minute,
		AllowedServiceAccount: "monitoring:coder-derp-egress-attestor",
		TokenReviewer: fakeTokenReviewer{identity: attestationIdentity{
			Username: "system:serviceaccount:monitoring:coder-derp-egress-attestor",
			NodeName: "westlake",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	attestorKey := key.NewNode()
	if err := store.Register(context.Background(), attestationRegistration{NodePublic: attestorKey.Public(), Region: 1002}, "token"); err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddr("124.160.108.240")
	if !store.Admit(tailcfg.DERPAdmitClientRequest{NodePublic: attestorKey.Public(), Source: source}, 1002) {
		t.Fatal("registered attestor was rejected")
	}
	if !store.Admit(tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public(), Source: source}, 1002) {
		t.Fatal("Coder client from attested source was rejected")
	}
	if store.Admit(tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public(), Source: source}, 1001) {
		t.Fatal("lease unexpectedly crossed DERP regions")
	}
	if store.Admit(tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public(), Source: netip.MustParseAddr("183.134.204.229")}, 1002) {
		t.Fatal("unobserved source was admitted")
	}
	now = now.Add(5*time.Minute + time.Nanosecond)
	if store.Admit(tailcfg.DERPAdmitClientRequest{NodePublic: key.NewNode().Public(), Source: source}, 1002) {
		t.Fatal("expired lease was admitted")
	}
}

func TestEgressAttestationRejectsUnexpectedIdentity(t *testing.T) {
	store, err := newEgressAttestation(egressAttestationConfig{
		Regions:               "1002",
		LeaseTTL:              time.Minute,
		RegistrationTTL:       time.Minute,
		AllowedServiceAccount: "monitoring:coder-derp-egress-attestor",
		TokenReviewer: fakeTokenReviewer{identity: attestationIdentity{
			Username: "system:serviceaccount:monitoring:default",
			NodeName: "westlake",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = store.Register(context.Background(), attestationRegistration{NodePublic: key.NewNode().Public(), Region: 1002}, "token")
	if err == nil {
		t.Fatal("unexpected service account was accepted")
	}

	store.reviewer = fakeTokenReviewer{err: errors.New("token review down")}
	err = store.Register(context.Background(), attestationRegistration{NodePublic: key.NewNode().Public(), Region: 1002}, "token")
	if err == nil {
		t.Fatal("TokenReview failure was accepted")
	}
}
