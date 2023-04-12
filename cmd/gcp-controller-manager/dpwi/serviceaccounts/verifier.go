/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package serviceaccounts provides a common verifier to verify if a Kubernetes Service Account (KSA)
// can act as a GCP Service Account (GSA). It also listens to and process KSA events.
// If a KSA's permission changes, it notifies the configmap handler to update configmap
// and the node syncer to sync related nodes.
package serviceaccounts

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	core "k8s.io/api/core/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/cloud-provider-gcp/cmd/gcp-controller-manager/dpwi/ctxlog"
	"k8s.io/cloud-provider-gcp/cmd/gcp-controller-manager/dpwi/hms"
)

const (
	// serviceAccountAnnotationGSAEmail is the key to the GCP Service Account annotation
	// in ServiceAccount objects.
	serviceAccountAnnotationGSAEmail = "iam.gke.io/gcp-service-account"
)

var (
	saRegexp                    = regexp.MustCompile(`^[^@]+@([a-z][-a-z0-9]{4,}[a-z0-9]\.iam|developer|appspot|cloudbuild)\.gserviceaccount\.com$`)
	domainScopedProjectSARegexp = regexp.MustCompile(`^[^@]+@([a-z][-a-z0-9]{4,}[a-z0-9])\.(([-a-z0-9])+\.)*iam\.gserviceaccount\.com$`)
)

// Verifier verifies if a Kubernetes Service Account (KSA)
// can act as a GCP Service Account (GSA) or not.
type Verifier struct {
	hms         *hms.Client
	saIndexer   cache.Indexer
	verifiedSAs *saMap
	loadGroup   singleflight.Group
}

// NewVerifier creates a new Verifier.
func NewVerifier(saInformer coreinformers.ServiceAccountInformer, hmsAuthzURL string) (*Verifier, error) {
	hms, err := hms.NewClient(hmsAuthzURL, &clientcmdapi.AuthProviderConfig{Name: "gcp"})
	if err != nil {
		return nil, err
	}
	v := &Verifier{
		hms:         hms,
		saIndexer:   saInformer.Informer().GetIndexer(),
		verifiedSAs: newSAMap(),
	}
	return v, nil
}

// GSAEmail identifies a GCP service account in email format.
type GSAEmail string

// ServiceAccount identifies a K8s service account object by its namespace and name.  Empty
// Namespace indicates the corresponding Kubernetes object was created in the "default" namespace.
type ServiceAccount struct {
	Namespace, Name string
}

// MarshalText implements the encoding.TextMarshaler interface.
func (sa ServiceAccount) MarshalText() ([]byte, error) {
	return []byte(sa.String()), nil
}

// String returns sa in a string as "<namespace>/<name>" or "default/<name>" if sa.Namespace is
// empty.
func (sa ServiceAccount) String() string {
	if sa.Namespace == "" {
		return fmt.Sprintf("default/%s", sa.Name)
	}
	return fmt.Sprintf("%s/%s", sa.Namespace, sa.Name)
}

func (sa ServiceAccount) Key() string {
	return fmt.Sprintf("%s/%s", sa.Namespace, sa.Name)
}

func saFromKey(key string) (ServiceAccount, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return ServiceAccount{}, err
	}
	return ServiceAccount{namespace, name}, nil
}

// VerifiedGSA returns the verified GSA for a given KSA if it has been verified and stored in memory.
// Otherwise, it calls HMS or Auth server to verify and store the result in memory.
func (v *Verifier) VerifiedGSA(ctx context.Context, ksa ServiceAccount) (GSAEmail, error) {
	gsa, ok := v.verifiedSAs.get(ksa)
	if ok {
		return gsa, nil
	}
	key := ksa.Key()
	resChan := v.loadGroup.DoChan(key, func() (entry any, err error) {
		return v.ForceVerify(ctx, ksa.Key())
	})
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("original request context is done: %w", ctx.Err())
	case res := <-resChan:
		return res.Val.(GSAEmail), res.Err
	}
}

func (v *Verifier) isProcessed(ksa ServiceAccount) bool {
	_, ok := v.verifiedSAs.get(ksa)
	return ok
}

// ForceVerify verifies a KSA no matter it has been verified or not.
func (v *Verifier) ForceVerify(ctx context.Context, key string) (GSAEmail, error) {
	gsa, ksa, err := v.getGSA(ctx, key)
	if err != nil {
		return "", err
	}
	if gsa == "" {
		v.verifiedSAs.addOrUpdate(ctx, ksa, gsa)
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	permitted, err := v.hms.Authorize(ctx, ksa.Namespace, ksa.Name, string(gsa))
	if err != nil {
		return "", fmt.Errorf("failed to authorize %s:%s; err: %v", ksa, gsa, err)
	}
	if !permitted {
		gsa = ""
	}
	v.verifiedSAs.addOrUpdate(ctx, ksa, gsa)
	return gsa, err
}

func (v *Verifier) getGSA(ctx context.Context, key string) (GSAEmail, ServiceAccount, error) {
	o, exists, err := v.saIndexer.GetByKey(key)
	if err != nil {
		return "", ServiceAccount{}, fmt.Errorf("failed to get ServiceAccount %q: %v", key, err)
	}
	if !exists {
		ctxlog.Warningf(ctx, "Dropping non-existed key %q: %v", key, err)
		sa, err := saFromKey(key)
		if err == nil {
			v.verifiedSAs.delete(sa)
		}
		return "", ServiceAccount{}, nil
	}
	sa, ok := o.(*core.ServiceAccount)
	if !ok {
		ctxlog.Warningf(ctx, "Dropping invalid object from SA queue with key %q: %#v", key, o)
		return "", ServiceAccount{}, nil
	}

	ann, found := sa.ObjectMeta.Annotations[serviceAccountAnnotationGSAEmail]
	if found && ann != "" && !validGSAEmail(ann) {
		ctxlog.Warningf(ctx, "Ignore invalid GSA: %q for KSA: %q", ann, key)
		ann = ""
	}
	return GSAEmail(ann), ServiceAccount{sa.Namespace, sa.Name}, nil
}

func validGSAEmail(email string) bool {
	if saRegexp.MatchString(email) {
		return true
	}
	if domainScopedProjectSARegexp.MatchString(email) {
		return true
	}
	return false
}

// AllVerified returns a full set of verified KSA-GSA pairs.
func (v *Verifier) AllVerified(ctx context.Context) (map[ServiceAccount]GSAEmail, error) {
	m := make(map[ServiceAccount]GSAEmail)
	for _, key := range v.saIndexer.ListKeys() {
		ksa, gsa, err := v.verifiedGSAPerKey(ctx, key)
		// Don't let some failures block the whole process.
		// A ksa failure here means that the ksa event is still in processing or
		// in the backlog of the SA event handler. Once the SA is processed successfully,
		// it will send another configmap event.
		if err != nil {
			ctxlog.Warningf(ctx, "Ignore the failure verifying ksa %q: %v", key, err)
			continue
		}
		if gsa != "" {
			m[ksa] = gsa
		}
	}
	return m, nil
}

func (v *Verifier) verifiedGSAPerKey(ctx context.Context, key string) (ServiceAccount, GSAEmail, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return ServiceAccount{}, "", err
	}
	ksa := ServiceAccount{
		Namespace: namespace,
		Name:      name,
	}
	gsa, err := v.VerifiedGSA(ctx, ksa)
	return ksa, gsa, err
}

// saMap is a Mutax protected map of GSAEmail keyed by ServiceAccount.
type saMap struct {
	sync.RWMutex
	ma map[ServiceAccount]GSAEmail
}

func newSAMap() *saMap {
	t := make(map[ServiceAccount]GSAEmail)
	return &saMap{
		ma: t,
	}
}

func (m *saMap) addOrUpdate(ctx context.Context, sa ServiceAccount, gsa GSAEmail) {
	m.Lock()
	defer m.Unlock()
	lastGSA, found := m.ma[sa]
	if found && string(gsa) == string(lastGSA) {
		ctxlog.Infof(ctx, "ksa %v can act as gsa %v instead of %v", sa, lastGSA, gsa)
	} else {
		ctxlog.Infof(ctx, "ksa %v can act as gsa %v", sa, gsa)
	}
	m.ma[sa] = gsa
}

func (m *saMap) delete(sa ServiceAccount) {
	m.Lock()
	defer m.Unlock()
	delete(m.ma, sa)
}

// get looks up sa from m and returns its gsa if sa exists.
func (m *saMap) get(sa ServiceAccount) (GSAEmail, bool) {
	m.RLock()
	defer m.RUnlock()
	gsa, ok := m.ma[sa]
	return gsa, ok
}
