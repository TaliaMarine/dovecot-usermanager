# Developer tasks. Run `just` to list them.
set shell := ["bash", "-euo", "pipefail", "-c"]

image := "dovecot-usermanager:dev"
chart := "charts/dovecot-usermanager"

default:
    @just --list

# Install frontend dependencies.
setup:
    cd frontend && npm ci

# Everything CI checks.
check: lint test build helm

# Format Go code and frontend sources.
fmt:
    gofmt -w .
    cd frontend && npx prettier --write .

# gofmt, go vet, eslint, prettier.
lint:
    test -z "$(gofmt -l . | grep -v '^frontend/')" || { gofmt -l .; exit 1; }
    go vet ./...
    cd frontend && npm run lint && npm run format-check

# Go tests with the race detector.
test:
    go test ./... -race

# Build the frontend and the backend binary into ./bin.
build: build-frontend
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/usermanager ./cmd/usermanager

build-frontend:
    cd frontend && npm run build

# Lint and render the Helm chart with minimal required values.
helm:
    helm lint {{ chart }} {{ helm_values }}
    helm template t {{ chart }} {{ helm_values }} > /dev/null

helm_values := "--set oidc.issuerUrl=https://auth.example.com/application/o/x/ --set oidc.clientId=x --set oidc.redirectUrl=https://um.example.com/api/auth/callback --set ingress.host=um.example.com --set sessionKey.secretRef.name=s"

# Run the backend against your current kubeconfig. Needs OIDC_ISSUER_URL and OIDC_CLIENT_ID
# in the environment; the redirect URL points at the Vite dev server (http://localhost:5173).
# Pair with `just dev-frontend`.
dev-backend namespace="dovecot":
    NAMESPACE={{ namespace }} \
    OIDC_REDIRECT_URL="${OIDC_REDIRECT_URL:-http://localhost:5173/api/auth/callback}" \
    SESSION_KEY="${SESSION_KEY:-$(printf 'dev%.0s' {1..16})}" \
    go run ./cmd/usermanager

# Vite dev server with /api proxied to the backend on :8080.
dev-frontend:
    cd frontend && npm run dev

# Build the container image locally.
docker-build:
    docker build -t {{ image }} .

# Remove build output.
clean:
    rm -rf bin frontend/dist
