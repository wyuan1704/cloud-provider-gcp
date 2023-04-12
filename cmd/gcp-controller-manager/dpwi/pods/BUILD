load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "pods",
    srcs = ["pods.go"],
    importpath = "k8s.io/cloud-provider-gcp/cmd/gcp-controller-manager/dpwi/pods",
    visibility = ["//visibility:public"],
    deps = [
        "//cmd/gcp-controller-manager/dpwi/ctxlog",
        "//cmd/gcp-controller-manager/dpwi/eventhandler",
        "//cmd/gcp-controller-manager/dpwi/serviceaccounts",
        "//vendor/github.com/google/uuid",
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
    name = "pods_test",
    srcs = ["pods_test.go"],
    embed = [":pods"],
    deps = [
        "//vendor/k8s.io/api/core/v1:core",
        "//vendor/k8s.io/apimachinery/pkg/apis/meta/v1:meta",
        "//vendor/k8s.io/client-go/tools/cache",
    ],
)
