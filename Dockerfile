# syntax=docker/dockerfile:1

FROM node:24-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM golang:1.27-alpine AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /usermanager ./cmd/usermanager

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=backend /usermanager ./usermanager
COPY --from=frontend /src/frontend/dist ./frontend/dist
# Numeric so the kubelet can verify runAsNonRoot (distroless has no /etc/passwd).
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/usermanager"]
