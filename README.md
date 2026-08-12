# podsquire

`podsquire` is a small container init wrapper for workloads that need SPIFFE
certificates, local mTLS proxy listeners, Vault-backed configuration, and simple
subprocess supervision without baking that plumbing into the application.

It can run as PID 1 around your application, as a sidecar, or as a one-shot init
container that writes certificates to a shared volume.

## Features

- **SPIFFE/SPIRE certificate bootstrap** — fetches an X.509 SVID from the SPIRE
  Workload API, writes `tls.crt`, `tls.key`, `ca.crt`, and optionally a combined
  key+cert PEM file, then renews before expiry.
- **Static certificate mode** — use existing cert/key/CA files when SPIRE is not
  available, for example in local development.
- **mTLS proxy listeners** — expose local plaintext HTTP or TCP listeners that
  connect to upstream services with the SPIFFE client certificate.
- **Subprocess supervision** — launch an application command, optionally signal
  it on certificate or secret refresh, and restart it on failure with bounded
  retry limits.
- **Vault secret injection** — authenticate to HashiCorp Vault with the pod's
  Kubernetes service account token and deliver KV secrets as environment
  variables or an atomically-written JSON file.
- **User-defined proxy presets** — define your own environment-specific proxy
  shortcuts in configuration; no private service definitions are bundled in the
  package.

All features are optional. Enable only the sections your container needs.

## Installation

```bash
pip install podsquire
```

For local development from this repository:

```bash
pip install -e .
```

## Quick start

Run with a YAML config:

```bash
podsquire --config /app/podsquire.yml
```

Fetch SPIFFE cert material and exit, useful as an init container:

```bash
podsquire --pull-certs-only /var/run/secrets/tls
```

That writes:

```text
/var/run/secrets/tls/tls.crt
/var/run/secrets/tls/tls.key
/var/run/secrets/tls/ca.crt
/var/run/secrets/tls/tls.key+cert
```

## Configuration overview

Copy `config-example.yml` and adjust it for your environment. Top-level sections
are optional, but a long-running process should include at least one of:

- `spire` or `static`
- `subprocess`
- `proxies`
- `enabled_proxy_presets`
- `vault_secrets`

### SPIRE certificate management

```yaml
spire:
  # Optional. Defaults to SPIFFE_ENDPOINT_SOCKET, then /run/spire/sockets/agent.sock.
  # socket: unix:///run/spire/sockets/agent.sock

  cert_path: /tmp/podsquire/tls.crt
  key_path: /tmp/podsquire/tls.key
  ca_path: /tmp/podsquire/ca.crt
  combined_path: /tmp/podsquire/tls.key+cert

  renewal_interval: 60
  expiry_threshold: 3600
  retry_interval: 5
```

`combined_path` writes a single PEM file containing the private key followed by
the certificate chain. Some clients, including PyMongo's
`tlsCertificateKeyFile`, expect this shape.

### Static cert mode

```yaml
static:
  cert_path: /var/run/secrets/tls/tls.crt
  key_path:  /var/run/secrets/tls/tls.key
  ca_path:   /var/run/secrets/tls/ca.crt
```

Static mode does not renew certificates.

### Subprocess supervision

```yaml
subprocess:
  command: "python3 -m myapp --port 8080"
  path: /app
  reload_signal: SIGHUP
  restart:
    enabled: true
    max_restarts: 5
    window_seconds: 300
```

If `reload_signal` is configured under `subprocess`, podsquire sends that signal
when SPIFFE certificates are renewed.

### Proxy listeners

```yaml
proxies:
  - name: api
    mode: http        # http or tcp
    local_host: 127.0.0.1
    local_port: 18080
    remote_host: api.default.svc.cluster.local
    remote_port: 8443
    verify_remote: true
```

Modes:

| Mode | Behaviour | Use for |
|------|-----------|---------|
| `http` | HTTP/1.1 reverse proxy; rewrites the `Host` header | REST/HTTP APIs |
| `tcp` | Raw byte tunnel | MongoDB, gRPC, AMQP, custom TCP protocols |

When `verify_remote` is `true`, the upstream server certificate is verified
against the SPIFFE trust bundle written to `ca_path`. Hostname checking is
disabled because SPIFFE SVIDs normally identify workloads with URI SANs rather
than DNS SANs.

### Proxy presets

Podsquire intentionally does **not** bundle environment-specific service names or
DNS records. If you want short names for your own platform services, define them
in your config:

```yaml
proxy_presets:
  vault:
    mode: http
    local_host: 127.0.0.1
    local_port: 8200
    remote_host: vault.example.svc.cluster.local
    remote_port: 8200
    verify_remote: true
  mongo:
    mode: tcp
    local_host: 127.0.0.1
    local_port: 27017
    remote_host: mongodb.example.svc.cluster.local
    remote_port: 27017
    verify_remote: true

enabled_proxy_presets:
  - vault
  - mongo
```

Explicit entries under `proxies:` take precedence when they use the same `name`
as a preset.

### Vault secret injection

```yaml
vault_secrets:
  kv_path: apps/my-service/config
  url: http://127.0.0.1:8200
  role: my-service
  kv_mount_point: secret
  kv_version: 2
  output_mode: env
  refresh_interval_minutes: 0
```

Podsquire authenticates to Vault using the Kubernetes service account token at:

```text
/var/run/secrets/kubernetes.io/serviceaccount/token
```

Supported output modes:

| Mode | Behaviour | Best for |
|------|-----------|----------|
| `env` | Inject secrets into podsquire's environment before the subprocess starts/restarts | Apps that read config from env at startup |
| `json_file` | Write secrets atomically to a JSON file | Apps that can reload config without restart |

For JSON-file mode:

```yaml
vault_secrets:
  kv_path: apps/my-service/config
  output_mode: json_file
  json_file_path: /var/run/secrets/podsquire/vault-secrets.json
  reload_signal: SIGUSR1
```

Environment fallback variables:

| YAML key | Env var | Default |
|----------|---------|---------|
| `kv_path` | `VAULT_KV_PATH` | required if `vault_secrets` is enabled |
| `url` | `VAULT_URL` | `http://127.0.0.1:8200` |
| `role` | `VAULT_ROLE` | `podsquire` |
| `kv_mount_point` | `VAULT_KV_MOUNT_POINT` | unset |
| `kv_version` | `VAULT_KV_VERSION` | `1` |
| `json_file_path` | `VAULT_JSON_FILE_PATH` | required for `json_file` mode |

Secret values are never logged. In `env` mode, all keys returned by Vault are
placed into `os.environ` for the subprocess to inherit. Keys containing
`ToBase64` are base64-encoded for compatibility with legacy env conventions.

## Deployment patterns

### PID 1 wrapper

```text
container start → podsquire → fetch certs → start app → supervise app
```

```bash
exec podsquire --config /app/podsquire.yml
```

### Cert init container

```bash
podsquire --pull-certs-only /var/run/secrets/tls
```

Mount the same volume into the main container and point your application at the
written PEM files.

### Sidecar proxy

Run podsquire with `spire`/`static` and `proxies`, but without `subprocess`. The
main application container connects to the local service address exposed by the
sidecar, for example `127.0.0.1:27017` for a MongoDB TCP tunnel.

## Demo connectivity app

`python -m podsquire.connectivity_test` is a tiny demo subprocess. Configure its
checks with `PODSQUIRE_CHECKS_JSON`:

```bash
export PODSQUIRE_CHECKS_JSON='[{"name":"vault","url":"http://127.0.0.1:8200/v1/sys/health","ok_statuses":[200,429]}]'
```

It also demonstrates reloading the JSON secrets file on `SIGUSR1`.

## Development checks

From the package directory:

```bash
python -m compileall podsquire
python -m pytest
python -m build
python -m twine check dist/*
```
