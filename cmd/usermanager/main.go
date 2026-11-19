package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/TaliaMarine/dovecot-usermanager/internal/api"
	"github.com/TaliaMarine/dovecot-usermanager/internal/auth"
	"github.com/TaliaMarine/dovecot-usermanager/internal/hash"
	"github.com/TaliaMarine/dovecot-usermanager/internal/kube"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func must(key string) string {
	v := os.Getenv(key)
	if v == "" {
		slog.Error("missing required environment variable", "name", key)
		os.Exit(1)
	}
	return v
}

func fatal(msg string, err error) {
	slog.Error(msg, "error", err)
	os.Exit(1)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := rest.InClusterConfig()
	if err != nil { // local development: fall back to ~/.kube/config
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{}).ClientConfig()
		if err != nil {
			fatal("kubernetes config", err)
		}
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		fatal("kubernetes client", err)
	}

	hasher, err := hash.New(env("PASSWORD_SCHEME", hash.SHA512Crypt))
	if err != nil {
		fatal("password scheme", err)
	}
	redirectURL := must("OIDC_REDIRECT_URL")
	sessions, err := auth.NewSessionManager([]byte(must("SESSION_KEY")), strings.HasPrefix(redirectURL, "https://"))
	if err != nil {
		fatal("session key", err)
	}
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	authn, err := auth.NewAuthenticator(dctx, must("OIDC_ISSUER_URL"), must("OIDC_CLIENT_ID"), redirectURL, env("ADMIN_GROUP", "homelab-admins"), sessions)
	cancel()
	if err != nil {
		fatal("oidc", err)
	}

	store := kube.NewStore(client, must("NAMESPACE"), env("USERS_SECRET_NAME", "dovecot-users"),
		env("USERS_SECRET_KEY", "passwd"), env("DOVECOT_DEPLOYMENT", "dovecot"))
	srv, err := api.New(authn, store, hasher, redirectURL, env("FRONTEND_DIR", "./frontend/dist"))
	if err != nil {
		fatal("server", err)
	}

	httpSrv := &http.Server{
		Addr: env("LISTEN_ADDR", ":8080"), Handler: srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = httpSrv.Shutdown(sctx)
	}()
	slog.Info("listening", "addr", httpSrv.Addr, "scheme", hasher.Scheme())
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal("serve", err)
	}
}
