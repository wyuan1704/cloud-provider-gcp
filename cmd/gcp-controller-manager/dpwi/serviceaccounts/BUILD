load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "serviceaccounts",
    srcs = [
        "handler.go",
        "verifier.go",
    ],
    importpath = "k8s.io/cloud-provider-gcp/cmd/gcp-controller-manager/dpwi/serviceaccounts",
    visibility = ["//visibility:public"],
    deps = [
        "//cmd/gcp-controller-manager/dpwi/ctxlog",
        "//cmd/gcp-controller-manager/dpwi/eventhandler",
        "//cmd/gcp-controller-manager/dpwi/hms",
        "//vendor/golang.org/x/sync/singleflight",
        "//vendor/k8s.io/api/core/v1:core",
        "//vendor/k8s.io/apimachinery/pkg/util/wait",
        "//vendor/k8s.io/client-go/informers/core/v1:core",
        "//vendor/k8s.io/client-go/tools/cache",
        "//vendor/k8s.io/client-go/tools/clientcmd/api",
        "//vendor/k8s.io/client-go/util/workqueue",
        "//vendor/k8s.io/klog/v2:klog",
    ],
)

go_test(
    name = "serviceaccounts_test",
    srcs = ["verifier_test.go"],
    embed = [":serviceaccounts"],
)
