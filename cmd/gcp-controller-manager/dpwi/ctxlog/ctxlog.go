package ctxlog

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/klog/v2"
)

// The type is unexported to prevent collisions
type contextKey string

type fragment func(ctx context.Context) string

const (
	EventKey        contextKey = "Event"
	BackgroundIDKey contextKey = "Background"
)

var fragments = []fragment{eventFragment, backgroundIDFragment}

func eventFragment(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v := ctx.Value(EventKey)
	if v == nil {
		return ""
	}
	return fmt.Sprintf("event:%q", v)
}

func backgroundIDFragment(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v := ctx.Value(BackgroundIDKey)
	if v == nil {
		return ""
	}
	str := fmt.Sprintf("%v", v)
	if len(str) > 8 {
		str = str[:8]
	}
	return fmt.Sprintf("background-id:%q", str)
}

func Infof(ctx context.Context, format string, args ...interface{}) {
	klog.InfoDepth(1, addFragments(ctx, fmt.Sprintf(format, args)))
}

func Warningf(ctx context.Context, format string, args ...interface{}) {
	klog.WarningDepth(1, addFragments(ctx, fmt.Sprintf(format, args)))
}

func Errorf(ctx context.Context, format string, args ...interface{}) {
	klog.ErrorDepth(1, addFragments(ctx, fmt.Sprintf(format, args)))
}

func addFragments(ctx context.Context, ori string) string {
	var values []string
	for _, f := range fragments {
		v := f(ctx)
		if v != "" {
			values = append(values, v)
		}
	}
	return fmt.Sprintf("[%s] %s", strings.Join(values, " "), ori)
}
