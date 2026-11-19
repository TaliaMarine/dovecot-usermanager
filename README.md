# Dovecot User Manager

> **AI-generated codebase.** Backend, frontend, Helm chart, CI/CD and this README were written by an AI
> coding agent (Claude), directed by a human. It is built for a private homelab, behind an OIDC gate, not
> for public exposure. Review the code (especially [`internal/auth`](./internal/auth) and the RBAC in
> [`charts/dovecot-usermanager/templates/role.yaml`](./charts/dovecot-usermanager/templates/role.yaml))
> before trusting it with anything that matters.

A small web UI to manage the mailbox users of a [Dovecot](https://github.com/dovecot) deployment on
Kubernetes. Dovecot authenticates against a passwd-file kept in a Kubernetes Secret; this app edits that
Secret.

- List, add, delete users; change passwords; optionally generate a random password (shown once).
- **Restart Dovecot** button (patches `kubectl.kubernetes.io/restartedAt` on the Deployment).
- **OIDC login only**, Authorization Code + PKCE (S256), public client, no client secret. The page
  redirects to the identity provider on open. Only members of the admin group (default `homelab-admins`,
  read from the ID token `groups` claim) get in.
- Go 1.27 backend (stdlib `net/http`, `client-go`) and Vue 3 + Vuetify 4 frontend, one distroless image.
- Every change is audit-logged to stdout (`msg=audit actor=... action=... target=...`).

## How it fits with Dovecot

| Contract | Default |
|---|---|
| Namespace | the app's own (Dovecot lives in the same one) |
| Users Secret / key | `dovecot-users` / `passwd` (created by the app when missing) |
| Dovecot Deployment | `dovecot` |
| passwd-file line | `user@domain:{SCHEME}hash`, extra fields/comments of existing lines are preserved |

Mount the Secret into Dovecot **as a directory**, not with `subPath` (subPath mounts never refresh). Kubelet
syncs Secret volumes within about a minute and Dovecot's `passwd-file` driver re-reads the file when its
mtime changes, so no restart is normally needed:

```yaml
volumes:
  - name: users
    secret: { secretName: dovecot-users, optional: true }
volumeMounts:
  - { name: users, mountPath: /etc/dovecot/users, readOnly: true }   # file: /etc/dovecot/users/passwd
```

Passwords are stored as `{SHA512-CRYPT}` by default. `PASSWORD_SCHEME=ARGON2ID` is implemented as well
(19 MiB, t=2, p=1) but has not been verified against `doveadm pw -t` yet.

## Install

```sh
helm install dovecot-usermanager oci://ghcr.io/taliamarine/charts/dovecot-usermanager --version <x.y.z> \
  --namespace dovecot \
  --set oidc.issuerUrl=https://authentik.example.com/application/o/dovecot-usermanager/ \
  --set oidc.clientId=<client-id> \
  --set oidc.redirectUrl=https://dovecot-usermanager.example.com/api/auth/callback \
  --set sessionKey.secretRef.name=dovecot-usermanager-session \
  --set ingress.host=dovecot-usermanager.example.com
```

The identity provider client must be a **public** client with redirect URI
`https://<host>/api/auth/callback`, scopes `openid profile email`, and the `groups` claim in the ID token
(authentik includes it with `profile`).

`sessionKey` Secret: a key `key` with at least 32 random characters, used to encrypt the session cookie.
Generate it with e.g. [kubernetes-secret-generator](https://github.com/mittwald/kubernetes-secret-generator)
or `kubectl create secret generic dovecot-usermanager-session --from-literal=key=$(openssl rand -hex 32)`.
Changing it signs everyone out.

### Configuration (environment)

| Variable | Default | |
|---|---|---|
| `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_REDIRECT_URL` | required | redirect URL must end in `/api/auth/callback` |
| `SESSION_KEY` | required | ≥ 32 bytes |
| `NAMESPACE` | required | set by the chart from the pod's namespace |
| `ADMIN_GROUP` | `homelab-admins` | group required in the `groups` claim |
| `USERS_SECRET_NAME` / `USERS_SECRET_KEY` | `dovecot-users` / `passwd` | |
| `DOVECOT_DEPLOYMENT` | `dovecot` | |
| `PASSWORD_SCHEME` | `SHA512-CRYPT` | or `ARGON2ID` |
| `LISTEN_ADDR`, `FRONTEND_DIR` | `:8080`, `./frontend/dist` | |

### RBAC

Namespaced `Role`: `create` secrets (cannot be name-restricted), `get`/`update` only the users Secret, and
`get`/`patch` only the Dovecot Deployment. Nothing else.

When managed by Argo CD, do not put the `dovecot-users` Secret in Git (the app owns its content), or add
an `ignoreDifferences` on `/data`.

## Security notes

- CSRF: session cookie is `SameSite=Lax`; every mutating request also needs the header
  `X-Requested-With: dovecot-usermanager` and, if the browser sends `Origin`, it must match the app origin.
- Sessions are AES-256-GCM encrypted cookies (12 h), no server-side state. Deleting a user does not delete
  their mail on the volume.
- Intended for private networks only.

## Development

```sh
go test -race ./...
cd frontend && npm ci && npm run lint && npm run build
# run against your kubeconfig (needs the env vars above; use https for Secure cookies or an https tunnel)
go run ./cmd/usermanager
cd frontend && npm run dev   # proxies /api to :8080
```

## Releases

Conventional Commits on `main` drive [release-please](https://github.com/googleapis/release-please); merging
its PR tags a release, which publishes `ghcr.io/taliamarine/dovecot-usermanager:<version>` and the chart
`oci://ghcr.io/taliamarine/charts/dovecot-usermanager`. [Renovate](./renovate.json) keeps dependencies
current (weekly, non-major automerge).
