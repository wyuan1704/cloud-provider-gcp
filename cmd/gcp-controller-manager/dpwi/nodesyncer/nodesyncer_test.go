/*
Copyright 2019 The Kubernetes Authors.

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

package nodesyncer

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/cloud-provider-gcp/cmd/gcp-controller-manager/dpwi/serviceaccounts"
)

const (
	testNamespace = "testnamespace"
	testSAName    = "testsa"
	testGSA       = "testsa@testnamespace.wonderland"
	testNode      = "gke-test-node"
	testLoc       = "us-nowhere9-x"
)

type fakeVerifier struct{}

func (v *fakeVerifier) VerifiedGSA(ksa serviceaccounts.ServiceAccount) (serviceaccounts.GSAEmail, error) {
	if ksa.Namespace == testNamespace && ksa.Name == testSAName {
		return testGSA, nil
	}
	return "", nil
}

type fakeSyncer struct {
	nodeName string
	count    int
}

func (s *fakeSyncer) Enqueue(key interface{}) {
	s.nodeName = key.(string)
	s.count++
}

type fakeIndexer struct {
	cache.Indexer
	obj interface{}
	err error
}

func (f fakeIndexer) GetByKey(key string) (interface{}, bool, error) {
	return f.obj, f.obj != nil, f.err
}

type testHMS struct {
	server *httptest.Server
	m      sync.Mutex
	req    []byte
	resp   interface{}
	ok     bool
}

func newTestHMS(resp interface{}, ok bool) *testHMS {
	hms := &testHMS{resp: resp, ok: ok}
	hms.server = httptest.NewServer(hms)
	return hms
}

func (hms *testHMS) getLastRequest() []byte {
	hms.m.Lock()
	defer hms.m.Unlock()
	return hms.req
}

// ServeHTTP implements the http.Handler interface.
func (hms *testHMS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hms.m.Lock()
	defer hms.m.Unlock()
	if !hms.ok {
		http.Error(w, "random error message", http.StatusInternalServerError)
		return
	}
	var err error
	hms.req, err = ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "error reading request", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hms.resp)
}

func TestProcess(t *testing.T) {
}

func newPod(namespace, sa, node string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "testPod",
		},
		Spec: v1.PodSpec{
			ServiceAccountName: sa,
			NodeName:           node,
		},
	}
}
