package prober

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/horazont/prometheus-xmpp-blackbox-exporter/internal/config"
)

type ProbeFn func(ctx context.Context, target string, config config.Module, registry *prometheus.Registry) bool
