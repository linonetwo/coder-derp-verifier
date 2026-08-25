package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// attestationRegistration is sent by the per-node attestor before it opens a
// DERP connection. The corresponding /verify call lets the verifier observe
// the public TCP source; the registration itself never claims an egress IP.
type attestationRegistration struct {
	NodePublic key.NodePublic `json:"node_public"`
	Region     uint16         `json:"region"`
}

type attestationRegistrar interface {
	Register(context.Context, attestationRegistration, string) error
}

type attestationIdentity struct {
	Username string
	NodeName string
}

type tokenReviewer interface {
	Review(context.Context, string) (attestationIdentity, error)
}

type egressAttestationConfig struct {
	Regions               string
	LeaseTTL              time.Duration
	RegistrationTTL       time.Duration
	AllowedServiceAccount string
	TokenReviewer         tokenReviewer
}

type egressRegistration struct {
	nodeName string
	region   uint16
	expires  time.Time
}

type egressLease struct {
	nodeName string
	expires  time.Time
}

type egressAttestation struct {
	regions               map[uint16]struct{}
	leaseTTL              time.Duration
	registrationTTL       time.Duration
	allowedServiceAccount string
	reviewer              tokenReviewer
	now                   func() time.Time

	mu            sync.Mutex
	registrations map[string]egressRegistration // DERP node public key -> registration
	leases        map[string]egressLease        // region + observed public source -> lease
}

func newEgressAttestation(config egressAttestationConfig) (*egressAttestation, error) {
	if config.TokenReviewer == nil {
		return nil, errors.New("TokenReview client is required")
	}
	if strings.TrimSpace(config.AllowedServiceAccount) == "" || !strings.Contains(config.AllowedServiceAccount, ":") {
		return nil, errors.New("allowed service account must be namespace:name")
	}
	if config.LeaseTTL <= 0 || config.RegistrationTTL <= 0 {
		return nil, errors.New("attestation TTLs must be positive")
	}
	regions := map[uint16]struct{}{}
	for _, raw := range strings.Split(config.Regions, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		value, err := strconv.ParseUint(raw, 10, 16)
		if err != nil || value == 0 {
			return nil, fmt.Errorf("invalid attestation DERP region %q", raw)
		}
		regions[uint16(value)] = struct{}{}
	}
	if len(regions) == 0 {
		return nil, errors.New("at least one attestation DERP region is required")
	}
	return &egressAttestation{
		regions:               regions,
		leaseTTL:              config.LeaseTTL,
		registrationTTL:       config.RegistrationTTL,
		allowedServiceAccount: config.AllowedServiceAccount,
		reviewer:              config.TokenReviewer,
		now:                   time.Now,
		registrations:         map[string]egressRegistration{},
		leases:                map[string]egressLease{},
	}, nil
}

func (s *egressAttestation) Register(ctx context.Context, registration attestationRegistration, bearerToken string) error {
	if registration.NodePublic.IsZero() || registration.Region == 0 {
		return errors.New("node public key and region are required")
	}
	if _, ok := s.regions[registration.Region]; !ok {
		return fmt.Errorf("region %d is not configured for egress attestation", registration.Region)
	}
	identity, err := s.reviewer.Review(ctx, bearerToken)
	if err != nil {
		return fmt.Errorf("review projected service-account token: %w", err)
	}
	if identity.Username != "system:serviceaccount:"+s.allowedServiceAccount {
		return fmt.Errorf("unexpected service account %q", identity.Username)
	}
	if strings.TrimSpace(identity.NodeName) == "" {
		return errors.New("projected service-account token is not bound to a node")
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	s.registrations[registration.NodePublic.String()] = egressRegistration{
		nodeName: identity.NodeName,
		region:   registration.Region,
		expires:  now.Add(s.registrationTTL),
	}
	return nil
}

// Admit returns true for a registered attestor and records its source as a
// short lease. Other Coder inner-tailnet node keys can use only that exact
// source and DERP region until the lease expires.
func (s *egressAttestation) Admit(req tailcfg.DERPAdmitClientRequest, region uint16) bool {
	if region == 0 || !req.Source.IsValid() {
		return false
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if registration, ok := s.registrations[req.NodePublic.String()]; ok && registration.region == region {
		s.leases[egressLeaseKey(region, req.Source)] = egressLease{
			nodeName: registration.nodeName,
			expires:  now.Add(s.leaseTTL),
		}
		return true
	}
	_, ok := s.leases[egressLeaseKey(region, req.Source)]
	return ok
}

func (s *egressAttestation) pruneLocked(now time.Time) {
	for public, registration := range s.registrations {
		if !registration.expires.After(now) {
			delete(s.registrations, public)
		}
	}
	for source, lease := range s.leases {
		if !lease.expires.After(now) {
			delete(s.leases, source)
		}
	}
}

func egressLeaseKey(region uint16, source netip.Addr) string {
	return strconv.FormatUint(uint64(region), 10) + "|" + source.String()
}

type attestedHeadscaleStore struct {
	headscale   *headscaleEndpointStore
	attestation *egressAttestation
}

func (s *attestedHeadscaleStore) Admit(ctx context.Context, req tailcfg.DERPAdmitClientRequest, region uint16) (bool, error) {
	if s.attestation.Admit(req, region) {
		return true, nil
	}
	return s.headscale.Admit(ctx, req, region)
}

func (s *attestedHeadscaleStore) Ping(ctx context.Context) error {
	return s.headscale.Ping(ctx)
}

func (s *attestedHeadscaleStore) Register(ctx context.Context, registration attestationRegistration, bearerToken string) error {
	return s.attestation.Register(ctx, registration, bearerToken)
}

type kubernetesTokenReviewerConfig struct {
	APIServer string
	CAFile    string
	TokenFile string
	Audience  string
}

type kubernetesTokenReviewer struct {
	apiURL    string
	client    *http.Client
	tokenFile string
	audience  string
}

func newKubernetesTokenReviewer(config kubernetesTokenReviewerConfig) (*kubernetesTokenReviewer, error) {
	apiURL := strings.TrimSpace(config.APIServer)
	if apiURL == "" {
		host := os.Getenv("KUBERNETES_SERVICE_HOST")
		if host == "" {
			host = "kubernetes.default.svc"
		}
		port := os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS")
		if port == "" {
			port = "443"
		}
		apiURL = "https://" + netJoinHostPort(host, port)
	}
	parsed, err := url.Parse(apiURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid Kubernetes API URL %q", apiURL)
	}
	if strings.TrimSpace(config.Audience) == "" {
		return nil, errors.New("TokenReview audience is required")
	}
	if strings.TrimSpace(config.TokenFile) == "" || strings.TrimSpace(config.CAFile) == "" {
		return nil, errors.New("Kubernetes service-account token and CA files are required")
	}
	caPEM, err := os.ReadFile(config.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read Kubernetes API CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("parse Kubernetes API CA")
	}
	return &kubernetesTokenReviewer{
		apiURL: strings.TrimRight(apiURL, "/") + "/apis/authentication.k8s.io/v1/tokenreviews",
		client: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}},
		tokenFile: config.TokenFile,
		audience:  config.Audience,
	}, nil
}

func netJoinHostPort(host, port string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

func (s *kubernetesTokenReviewer) Review(ctx context.Context, token string) (attestationIdentity, error) {
	verifierToken, err := os.ReadFile(s.tokenFile)
	if err != nil {
		return attestationIdentity{}, fmt.Errorf("read verifier service-account token: %w", err)
	}
	payload := struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       struct {
			Token     string   `json:"token"`
			Audiences []string `json:"audiences"`
		} `json:"spec"`
	}{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"}
	payload.Spec.Token = token
	payload.Spec.Audiences = []string{s.audience}
	body, err := json.Marshal(payload)
	if err != nil {
		return attestationIdentity{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiURL, bytes.NewReader(body))
	if err != nil {
		return attestationIdentity{}, err
	}
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(verifierToken)))
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return attestationIdentity{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		return attestationIdentity{}, fmt.Errorf("TokenReview returned %s", response.Status)
	}
	var reviewed struct {
		Status struct {
			Authenticated bool     `json:"authenticated"`
			Audiences     []string `json:"audiences"`
			User          struct {
				Username string              `json:"username"`
				Extra    map[string][]string `json:"extra"`
			} `json:"user"`
		} `json:"status"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxRequestBytes))
	if err := decoder.Decode(&reviewed); err != nil {
		return attestationIdentity{}, fmt.Errorf("decode TokenReview: %w", err)
	}
	if !reviewed.Status.Authenticated {
		return attestationIdentity{}, errors.New("projected service-account token is not authenticated")
	}
	if !containsString(reviewed.Status.Audiences, s.audience) {
		return attestationIdentity{}, errors.New("projected service-account token was not accepted for the attestation audience")
	}
	return attestationIdentity{
		Username: reviewed.Status.User.Username,
		NodeName: firstTokenReviewExtra(reviewed.Status.User.Extra, "authentication.kubernetes.io/node-name"),
	}, nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func firstTokenReviewExtra(extra map[string][]string, name string) string {
	if values := extra[name]; len(values) > 0 {
		return values[0]
	}
	return ""
}
