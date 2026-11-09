# SENTINEL Tool Integration Framework (TIF) — Registry v1

This patch adds the first TIF milestone: strict manifest validation, immutable
version records, registration APIs, and a capability catalogue.

## Important execution boundary

This milestone deliberately does **not** execute user-supplied containers.
The current scanner has no Docker Engine socket, and this patch does not add
one. User-supplied images are untrusted code. Giving the scanner or backend
unrestricted Docker socket access would create a host compromise path.

Registered integrations are stored and discoverable for inspection. They are
not executable yet. The enable endpoint fails closed until a separately
isolated runner and runtime validation are implemented.

## Manifest v1

- YAML parsed with `yaml.safe_load`.
- Unknown fields rejected.
- Only container runtime supported.
- Image must be pinned by `@sha256:<64 hex>` digest.
- Entrypoint is an argument array, never a shell command string.
- CPU, memory and timeout bounds enforced.
- Operation names and parameter schemas validated.
- JSON output contract required.

Example:

```yaml
manifest_version: "1.0"
tool_id: graphql_mapper
name: GraphQL Mapper
version: "1.0.0"
description: Discovers GraphQL endpoints on authorized web applications.
runtime:
  type: container
  image: registry.example.com/security/graphql-mapper@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  entrypoint: ["/app/graphql-mapper"]
  timeout_seconds: 300
  memory_mb: 512
  cpus: 1.0
  read_only_rootfs: true
  network_access: scoped_targets_only
capabilities:
  - graphql_discovery
  - endpoint_enumeration
operations:
  discover:
    description: Discover GraphQL endpoints.
    parameters:
      url:
        type: string
        description: In-scope HTTP or HTTPS URL.
        required: true
      depth:
        type: integer
        description: Maximum discovery depth.
        required: false
        minimum: 1
        maximum: 3
output_format: json
output_schema_version: "1.0"
```

The digest above is illustrative. Replace it with the real immutable image digest.

## API

- `POST /integrations/register` — body: `{"manifest_yaml":"...","created_by":"..."}`
- `GET /integrations`
- `GET /integrations/{integration_id}`
- `GET /integrations/{integration_id}/versions`
- `GET /integrations/capabilities`
- `POST /integrations/{integration_id}/enable`
- `POST /integrations/{integration_id}/disable`

Registration validates and stores a manifest. It does not pull or run the image.
Enabling currently returns HTTP 409 until the isolated runner is available.
Versions are immutable; registering a new version disables the integration.

## Database

Development bootstrap uses SQLAlchemy `create_all`, which creates the new tables
without deleting existing data. Do not use `docker compose down -v`.

Production must use Alembic migrations and authenticated organization-level
ownership/RBAC. `created_by` is currently an audit label, not authenticated
identity.

## Next milestone: isolated container runner

The runner must be a separately trusted component, not part of the untrusted
tool container. It must pin the resolved image digest, enforce CPU/memory/time
limits, use read-only rootfs and temporary bounded storage, drop capabilities,
disable privilege escalation, apply seccomp/AppArmor, restrict network egress
to the approved scope, and return bounded JSON plus raw output artifacts.
Only after runtime validation should an integration become executable and
participate in the existing proposal → approval → GATE → signed authorization
pipeline.
