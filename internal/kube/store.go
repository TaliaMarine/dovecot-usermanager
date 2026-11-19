// Package kube reads and writes the Dovecot users Secret and restarts the
// Dovecot Deployment.
package kube

import (
	"context"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	"github.com/TaliaMarine/dovecot-usermanager/internal/passwd"
)

// Store wraps the users Secret.
type Store struct {
	client     kubernetes.Interface
	namespace  string
	secretName string
	key        string
	deployment string
	mu         sync.Mutex // serializes read-modify-write within this replica
}

func NewStore(client kubernetes.Interface, namespace, secretName, key, deployment string) *Store {
	return &Store{client: client, namespace: namespace, secretName: secretName, key: key, deployment: deployment}
}

// Users lists the user names (never hashes). A missing Secret means no users.
func (s *Store) Users(ctx context.Context) ([]string, error) {
	sec, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.secretName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	users := passwd.Parse(sec.Data[s.key]).Users()
	if users == nil {
		users = []string{}
	}
	return users, nil
}

// Mutate applies fn to the passwd file and writes it back with optimistic
// concurrency (resourceVersion); the Secret is created when missing. Errors
// returned by fn abort without writing.
func (s *Store) Mutate(ctx context.Context, fn func(*passwd.File) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	secrets := s.client.CoreV1().Secrets(s.namespace)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		sec, err := secrets.Get(ctx, s.secretName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			f := passwd.Parse(nil)
			if err := fn(f); err != nil {
				return err
			}
			_, err = secrets.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: s.secretName, Namespace: s.namespace, Labels: map[string]string{
					"app.kubernetes.io/managed-by": "dovecot-usermanager",
				}},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{s.key: f.Bytes()},
			}, metav1.CreateOptions{})
			return err
		}
		if err != nil {
			return err
		}
		f := passwd.Parse(sec.Data[s.key])
		if err := fn(f); err != nil {
			return err
		}
		if sec.Data == nil {
			sec.Data = map[string][]byte{}
		}
		sec.Data[s.key] = f.Bytes() // Update carries sec.ResourceVersion -> 409 on a concurrent write
		_, err = secrets.Update(ctx, sec, metav1.UpdateOptions{})
		return err
	})
}

// Restart triggers a rolling restart of the Dovecot Deployment, like
// `kubectl rollout restart`.
func (s *Store) Restart(ctx context.Context) error {
	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":%q}}}}}`,
		time.Now().UTC().Format(time.RFC3339))
	_, err := s.client.AppsV1().Deployments(s.namespace).Patch(ctx, s.deployment, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{})
	return err
}
