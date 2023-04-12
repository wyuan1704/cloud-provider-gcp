/*
Copyright 2018 The Kubernetes Authors.

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

package main

import (
	"context"
	"sort"
	"time"

	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/cloud-provider-gcp/cmd/gcp-controller-manager/dpwi/configmap"
	"k8s.io/cloud-provider-gcp/cmd/gcp-controller-manager/dpwi/nodesyncer"
	"k8s.io/cloud-provider-gcp/cmd/gcp-controller-manager/dpwi/pods"
	"k8s.io/cloud-provider-gcp/cmd/gcp-controller-manager/dpwi/serviceaccounts"
	"k8s.io/klog/v2"
	"k8s.io/kubernetes/pkg/controller/certificates"
)

type controllerContext struct {
	client                                 clientset.Interface
	sharedInformers                        informers.SharedInformerFactory
	recorder                               record.EventRecorder
	gcpCfg                                 gcpConfig
	clusterSigningGKEKubeconfig            string
	csrApproverVerifyClusterMembership     bool
	csrApproverAllowLegacyKubelet          bool
	csrApproverUseGCEInstanceListReferrers bool
	verifiedSAs                            *saMap
	hmsAuthorizeSAMappingURL               string
	hmsSyncNodeURL                         string
	delayDirectPathGSARemove               bool
	clearStalePodsOnNodeRegistration       bool
}

// loops returns all the control loops that the GCPControllerManager can start.
// We append GCP to all of these to disambiguate them in API server and audit
// logs. These loops are intentionally started in a random order.
func loops() map[string]func(context.Context, *controllerContext) error {
	ll := map[string]func(context.Context, *controllerContext) error{
		"node-certificate-approver": func(ctx context.Context, controllerCtx *controllerContext) error {
			approver := newNodeApprover(controllerCtx)
			approveController := certificates.NewCertificateController(
				"node-certificate-approver",
				controllerCtx.client,
				controllerCtx.sharedInformers.Certificates().V1().CertificateSigningRequests(),
				approver.handle,
			)
			go approveController.Run(ctx, 20)
			return nil
		},
		"istiod-certificate-approver": func(ctx context.Context, controllerCtx *controllerContext) error {
			approver := newIstiodApprover(controllerCtx)
			approveController := certificates.NewCertificateController(
				"istiod-certificate-approver",
				controllerCtx.client,
				controllerCtx.sharedInformers.Certificates().V1().CertificateSigningRequests(),
				approver.handle,
			)
			go approveController.Run(ctx, 20)
			return nil
		},
		"oidc-certificate-approver": func(ctx context.Context, controllerCtx *controllerContext) error {
			approver := newOIDCApprover(controllerCtx)
			approveController := certificates.NewCertificateController(
				"oidc-certificate-approver",
				controllerCtx.client,
				controllerCtx.sharedInformers.Certificates().V1().CertificateSigningRequests(),
				approver.handle,
			)
			go approveController.Run(ctx, 20)
			return nil
		},
		"certificate-signer": func(ctx context.Context, controllerCtx *controllerContext) error {
			signer, err := newGKESigner(controllerCtx)
			if err != nil {
				return err
			}
			signController := certificates.NewCertificateController(
				"signer",
				controllerCtx.client,
				controllerCtx.sharedInformers.Certificates().V1().CertificateSigningRequests(),
				signer.handle,
			)

			go signController.Run(ctx, 20)
			return nil
		},
		"node-annotator": func(ctx context.Context, controllerCtx *controllerContext) error {
			nodeAnnotateController, err := newNodeAnnotator(
				controllerCtx.client,
				controllerCtx.sharedInformers.Core().V1().Nodes(),
				controllerCtx.gcpCfg.Compute,
			)
			if err != nil {
				return err
			}
			go nodeAnnotateController.Run(20, ctx.Done())
			return nil
		},
	}
	if *directPath {
		ll["direct-path-with-workload-identity"] = func(ctx context.Context, controllerCtx *controllerContext) error {
			verifier, err := serviceaccounts.NewVerifier(
				controllerCtx.sharedInformers.Core().V1().ServiceAccounts(),
				controllerCtx.hmsAuthorizeSAMappingURL,
			)
			if err != nil {
				return err
			}
			cmHandler := configmap.NewEventHandler(
				controllerCtx.client,
				controllerCtx.sharedInformers.Core().V1().ConfigMaps(),
				verifier,
			)

			saSync := controllerCtx.sharedInformers.Core().V1().ServiceAccounts().Informer().HasSynced
			go func() {
				start := time.Now()
				cache.WaitForCacheSync(ctx.Done(), saSync)
				klog.Infof("Wait %v to start configmap handler", time.Since(start))
				cmHandler.Run(1, ctx)
			}()

			syncer, err := nodesyncer.NewEventHandler(
				controllerCtx.sharedInformers.Core().V1().Pods(),
				controllerCtx.sharedInformers.Core().V1().Nodes(),
				verifier,
				controllerCtx.hmsSyncNodeURL,
				controllerCtx.client,
			)
			if err != nil {
				return nil
			}
			saHandler := serviceaccounts.NewEventHandler(
				controllerCtx.sharedInformers.Core().V1().ServiceAccounts(),
				controllerCtx.sharedInformers.Core().V1().Pods(),
				verifier,
				cmHandler.Enqueue,
				syncer.EnqueueKey,
			)
			go func() {
				start := time.Now()
				cache.WaitForCacheSync(ctx.Done(), saSync)
				klog.Infof("Wait %v to start service account handler", time.Since(start))
				saHandler.Run(3, ctx)
			}()

			podHandler, err := pods.NewEventHandler(
				controllerCtx.sharedInformers.Core().V1().Pods().Informer(),
				verifier,
				syncer,
			)
			if err != nil {
				return nil
			}
			podSync := controllerCtx.sharedInformers.Core().V1().Pods().Informer().HasSynced
			go func() {
				start := time.Now()
				for _, s := range []func() bool{saSync, podSync} {
					cache.WaitForCacheSync(ctx.Done(), s)
				}
				klog.Infof("Wait %v to start podhandler", time.Since(start))
				podHandler.Run(20, ctx)
			}()
			go func() {
				cache.WaitForCacheSync(ctx.Done(), controllerCtx.sharedInformers.Core().V1().Nodes().Informer().HasSynced)
				syncer.Run(30, ctx)
			}()

			return nil
		}
	}
	if *kubeletReadOnlyCSRApprover {
		ll["kubelet-readonly-approver"] = func(ctx context.Context, controllerCtx *controllerContext) error {
			approver := newKubeletReadonlyCSRApprover(controllerCtx)
			approveController := certificates.NewCertificateController(
				"kubelet-readonly-approver",
				controllerCtx.client,
				controllerCtx.sharedInformers.Certificates().V1().CertificateSigningRequests(),
				approver.handle,
			)
			go approveController.Run(ctx, 20)
			return nil
		}
	}
	return ll
}

func loopNames() []string {
	names := make([]string, 0)
	for name := range loops() {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
