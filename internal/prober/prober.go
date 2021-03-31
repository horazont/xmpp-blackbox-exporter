package prober

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/horazont/xmpp-blackbox-exporter/internal/config"
)

type ProbeFn func(ctx context.Context, module, target string, config config.Module, clients Clients, registry *prometheus.Registry) bool
