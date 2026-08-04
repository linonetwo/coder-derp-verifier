# coder-derp-verifier

`coder-derp-verifier` is a fail-closed admission controller for a
[Tailscale DERP server](https://github.com/tailscale/tailscale/tree/main/cmd/derper).
It permits only node public keys that are currently present in Coder's
PostgreSQL HA coordinator `tailnet_peers` table with status `ok`.

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

For single-replica Coder AGPL, `headscale_source_verifier.py` provides a
weaker but practical alternative when every Coder client and workspace host is
also enrolled in an outer Headscale network. It admits a DERP connection only
when the TCP source IP appears in a recent, non-expired Headscale node
endpoint.

Run the `-headscale-source` image on the Headscale host with a read-only mount
of its SQLite database:

```sh
docker run --rm -p 8080:8080 \
  -v /var/lib/headscale/db:/headscale:ro \
  ghcr.io/linonetwo/coder-derp-verifier-headscale-source:latest \
  --database /headscale/headscale.db --max-node-age 2h
```

This backend does **not** prove that the inner Coder node key belongs to
Coder. It proves that the connection originates from the same public IP as a
recent outer Headscale node. Devices behind one NAT share that authorization.
Use it only when this trade-off is acceptable, bind it to a private interface,
and restrict the verifier port to the DERP host.

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
