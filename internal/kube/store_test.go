package kube

import (
	"context"
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/TaliaMarine/dovecot-usermanager/internal/passwd"
)

func TestMutateCreatesAndUpdates(t *testing.T) {
	cs := fake.NewClientset()
	s := NewStore(cs, "dovecot", "dovecot-users", "passwd", "dovecot")
	ctx := context.Background()

	if u, err := s.Users(ctx); err != nil || len(u) != 0 {
		t.Fatalf("empty: %v %v", u, err)
	}
	if err := s.Mutate(ctx, func(f *passwd.File) error { return f.Add("a@x.be", "{S}h1") }); err != nil {
		t.Fatal(err)
	}
	if err := s.Mutate(ctx, func(f *passwd.File) error { return f.Add("b@x.be", "{S}h2") }); err != nil {
		t.Fatal(err)
	}
	sec, _ := cs.CoreV1().Secrets("dovecot").Get(ctx, "dovecot-users", metav1.GetOptions{})
	if string(sec.Data["passwd"]) != "a@x.be:{S}h1\nb@x.be:{S}h2\n" {
		t.Fatalf("data = %q", sec.Data["passwd"])
	}
	if u, _ := s.Users(ctx); len(u) != 2 {
		t.Fatalf("users = %v", u)
	}
}

func TestMutateErrorDoesNotWrite(t *testing.T) {
	cs := fake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "dovecot-users", Namespace: "dovecot"},
		Data:       map[string][]byte{"passwd": []byte("a@x.be:{S}h\n")},
	})
	s := NewStore(cs, "dovecot", "dovecot-users", "passwd", "dovecot")
	err := s.Mutate(context.Background(), func(f *passwd.File) error { return f.Add("a@x.be", "{S}h") })
	if !errors.Is(err, passwd.ErrExists) {
		t.Fatalf("err = %v", err)
	}
	for _, a := range cs.Actions() {
		if a.GetVerb() == "update" {
			t.Fatal("secret updated despite error")
		}
	}
}

func TestRestartPatchesAnnotation(t *testing.T) {
	cs := fake.NewClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "dovecot", Namespace: "dovecot"}})
	s := NewStore(cs, "dovecot", "dovecot-users", "passwd", "dovecot")
	if err := s.Restart(context.Background()); err != nil {
		t.Fatal(err)
	}
	d, _ := cs.AppsV1().Deployments("dovecot").Get(context.Background(), "dovecot", metav1.GetOptions{})
	if d.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] == "" {
		t.Fatal("restartedAt not set")
	}
}
