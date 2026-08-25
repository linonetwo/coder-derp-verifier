# coder-derp-verifier

`coder-derp-verifier` is a Go fail-closed admission controller for a
[Tailscale DERP server](https://github.com/tailscale/tailscale/tree/main/cmd/derper).
One binary provides two explicitly selected admission backends:

- the default PostgreSQL backend permits node public keys currently present
  in Coder's HA coordinator `tailnet_peers` table with status `ok`;
- the `headscale-source` backend permits source IPs found in recent Headscale
  node endpoints.

This is a small external adapter. It does not patch or replace Coder or DERP.

> [!IMPORTANT]
> This backend requires Coder's PostgreSQL high-availability coordinator.
> A single-replica Coder AGPL deployment uses an in-memory coordinator and
> leaves `tailnet_peers` empty, so this verifier must not be attached there.
> It will correctly fail closed, which would reject every Coder client.

## Why a separate verifier?

DERP traffic is end-to-end encrypted, but a public DERP without admission
control can still be used as a relay by unrelated clients. Tailscale's
`--verify-client-url` is the supported extension point. Existing open-source
verifiers cover Tailscale SaaS OAuth, a local `tailscaled`, or a static key
file; Coder uses its own ephemeral tailnet and node keys.

## Headscale source-IP backend

For single-replica Coder AGPL, the `headscale-source` subcommand provides a
weaker but practical alternative when every Coder client and workspace host is
also enrolled in an outer Headscale network. It admits a DERP connection only
when the TCP source IP appears in a recent, non-expired Headscale node endpoint.

Run the `-headscale-source` image on the Headscale host with a read-only mount
of its SQLite database:

```sh
docker run --rm -p 8080:8080 \
  -v /var/lib/headscale/db:/headscale:ro \
  ghcr.io/linonetwo/coder-derp-verifier-headscale-source:latest \
  --database /headscale/headscale.db --max-node-age 2h
```

The `-headscale-source` image contains the same static Go binary as the default
image and selects the subcommand in its entrypoint. It does not contain a
Python runtime.

This backend does **not** prove that the inner Coder node key belongs to
Coder. It proves that the connection originates from the same public IP as a
recent outer Headscale node. Devices behind one NAT share that authorization.
Use it only when this trade-off is acceptable, bind it to a private interface,
and restrict the verifier port to the DERP host.

### Kubernetes egress attestation

Some worker networks use destination/protocol-aware NAT: a Headscale UDP
endpoint is not necessarily the TCP source that the public Coder DERP sees.
For that case, `headscale-source` can add short-lived leases for explicitly
configured DERP regions:

1. a non-privileged DaemonSet on each worker creates an ephemeral DERP node
   key and sends it to `POST /attest/register` with a projected Kubernetes
   ServiceAccount token;
2. the verifier uses Kubernetes `TokenReview`, requires the configured
   `namespace:serviceaccount`, and records the Pod-bound node name; and
3. only when that registered key completes a real DERP handshake does
   `/verify?region=<id>` observe and lease the actual TCP source. Other Coder
   keys are admitted only from that exact source and region until the lease
   expires.

This does not use a generic public-IP service, does not expose a new public
listener, and does not change a Grafana dashboard. Registration and leases are
in-memory by design: loss of the verifier or attestor expires access rather
than retaining stale authorization.

Enable it only for the DERP regions that have a public endpoint reachable from
the worker Pod network:

```sh
coder-derp-verifier headscale-source \
  --database /headscale/headscale.db \
  --attestation-regions=1002 \
  --attestation-lease-ttl=5m \
  --attestation-registration-ttl=20m \
  --attestation-service-account=monitoring:coder-derp-egress-attestor \
  --attestation-audience=coder-derp-egress-attestor
```

The verifier's ServiceAccount needs only `create` on
`authentication.k8s.io/tokenreviews`. The attestor must mount an audience-bound
projected token and use the companion `-attestor` image, for example:

```sh
coder-derp-verifier egress-attestor \
  --verifier=http://100.64.0.1:18080 \
  --derp=1002=https://coder-derp.example:41647/derp
```

Configure the associated DERP with the immutable region query label:

```sh
derper --verify-client-url=http://verifier:8080/verify?region=1002 \
  --verify-client-url-fail-open=false
```

## Run

Create a PostgreSQL role with read-only access to Coder's live primary:

```sql
CREATE ROLE coder_derp_verifier LOGIN PASSWORD 'use-a-generated-secret';
GRANT CONNECT ON DATABASE coder TO coder_derp_verifier;
GRANT USAGE ON SCHEMA public TO coder_derp_verifier;
GRANT SELECT ON TABLE public.tailnet_peers TO coder_derp_verifier;
```

Then run:

```sh
docker run --rm -p 8080:8080 \
  -e DATABASE_URL='postgres://coder_derp_verifier:...@postgres/coder?sslmode=require' \
  ghcr.io/linonetwo/coder-derp-verifier:latest
```

Configure DERP:

```sh
derper \
  --verify-clients=false \
  --verify-client-url=http://coder-derp-verifier:8080/verify \
  --verify-client-url-fail-open=false
```

The verifier retries an unknown key briefly because a newly started Coder
client can race its first DERP dial against Coder's peer registration.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | required | PostgreSQL connection string for Coder's live primary |
| `LISTEN_ADDR` | `:8080` | HTTP listen address |
| `QUERY_TIMEOUT` | `2s` | Timeout for each database lookup |
| `UNKNOWN_KEY_RETRIES` | `4` | Retries before rejecting an unknown key |
| `UNKNOWN_KEY_RETRY_DELAY` | `250ms` | Delay between unknown-key retries |

Endpoints:

- `POST /verify`: Tailscale DERP admission API
- `POST /attest/register`: projected-token registration for configured egress
  attestors (enabled only with `--attestation-regions`)
- `GET /healthz`: process liveness
- `GET /readyz`: database readiness

Database failures return HTTP 503. DERP must use
`--verify-client-url-fail-open=false` so failures deny access.

## Security notes

- Use a dedicated PostgreSQL role with only `SELECT` on `tailnet_peers`.
- Keep this service cluster-internal; only DERP should reach `/verify`.
- `tailnet_peers` is an unlogged, ephemeral Coder HA-coordinator table. Query
  the active primary, never an asynchronous replica.
- Requests are capped at 64 KiB and unknown JSON fields are rejected.

## License

MIT.
