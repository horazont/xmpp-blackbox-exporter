package prober

import (
	"context"
	"crypto/tls"
	"errors"
	"go.uber.org/zap"
	"net"
	"time"

	"mellium.im/xmpp"
	"mellium.im/xmpp/jid"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/horazont/xmpp-blackbox-exporter/internal/config"
)

var (
	ErrNoTLS = errors.New("TLS not negotiated")
)

func executeProbeC2S(ctx context.Context, conn net.Conn, addr jid.JID, tls_config *tls.Config, ct *connTrace) (tls_state *tls.ConnectionState, info StreamInfo, err error) {
	capture := NewCapturingStartTLS(tls_config)

	features := make([]xmpp.StreamFeature, 0)
	if tls_config != nil {
		features = append(features, traceStreamFeature(capture.ToStreamFeature(), &ct.starttlsDone))
	}
	features = append(features, CheckSASLOffered(&info.SASLOffered, &info.SASLMechanisms))

	session, err := xmpp.NewClientSession(
		ctx,
		addr,
		conn,
		features...,
	)
	defer session.Close()

	if err != nil {
		return tls_state, info, err
	}

	info.Negotiated = true

	if tls_config != nil {
		tls_conn, ok := capture.CapturedWriter.(*tls.Conn)
		if !ok {
			return tls_state, info, ErrNoTLS
		}
		err = tls_conn.Handshake()
		if err != nil {
			return tls_state, info, err
		}

		tls_state = &tls.ConnectionState{}
		*tls_state = tls_conn.ConnectionState()
	}

	return tls_state, info, nil
}

func ProbeC2S(ctx context.Context, module, target string, config config.Module, _ Clients, registry *prometheus.Registry) bool {
	sl := zap.S()

	probeSSLLastChainExpiry := prometheus.NewGauge(prometheus.GaugeOpts{
		// TODO: rename
		Name: "probe_ssl_earliest_cert_expiry",
		Help: "Returns earliest SSL cert expiry date",
	})

	probeSSLNextChainExpiry := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ssl_next_chain_expiry",
		Help: "Returns the date when the next valid chain expires",
	})

	probeFailedDueToSASLMechanism := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_failed_due_to_sasl_mechanism",
		Help: "1 if the probe failed due to a forbidden or missing SASL mechanism",
	})

	durationGaugeVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_xmpp_duration_seconds",
		Help: "Duration of xmpp connection by phase",
	}, []string{"phase"})

	registry.MustRegister(durationGaugeVec)
	registry.MustRegister(probeFailedDueToSASLMechanism)

	probeSASLMechanisms := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "probe_sasl_mechanism_offered",
			Help: "1 if the SASL mechanism was offered",
		},
		[]string{"mechanism"},
	)

	host, addr, err := parseTarget(target, false)
	if err != nil {
		sl.Errorw("failed to parse c2s probe target",
			"target", target,
			"module", module,
			"err", err,
		)
		return false
	}

	tls_config, err := NewTLSConfig(&config.C2S.TLSConfig, addr.Domainpart())
	if err != nil {
		sl.Errorw("failed to process TLS config for c2s probe",
			"module", module,
			"target", target,
			"err", err,
		)
		return false
	}

	ct := connTrace{}
	ct.auth = false
	ct.starttls = !config.C2S.DirectTLS
	ct.start = time.Now()

	tls_state_from_dial, conn, err := dialXMPP(ctx, config.C2S.DirectTLS, tls_config, host, addr, false, config.C2S.RestrictAddressFamily)
	if err != nil {
		sl.Errorw("failed to dial for c2s probe",
			"module", module,
			"target", target,
			"err", err,
		)
		return false
	}
	defer conn.Close()

	ct.connectDone = time.Now()
	durationGaugeVec.WithLabelValues("connect").Set(ct.connectDone.Sub(ct.start).Seconds())

	var tls_state_from_probe *tls.ConnectionState
	var stream_info StreamInfo
	{
		tls_config_to_pass := tls_config
		if config.C2S.DirectTLS {
			tls_config_to_pass = nil
		}
		tls_state_from_probe, stream_info, err = executeProbeC2S(ctx, conn, addr, tls_config_to_pass, &ct)
	}

	if !ct.starttls {
		ct.starttlsDone = ct.connectDone
	}
	durationGaugeVec.WithLabelValues("starttls").Set(ct.starttlsDone.Sub(ct.connectDone).Seconds())

	var tls_state tls.ConnectionState
	if tls_state_from_dial != nil {
		tls_state = *tls_state_from_dial
	} else if tls_state_from_probe != nil {
		tls_state = *tls_state_from_probe
	}

	if !tls_state.HandshakeComplete {
		sl.Errorw("TLS handshake did not complete for c2s probe",
			"module", module,
			"target", target,
			"err", err,
		)
		return false
	}

	registry.MustRegister(probeSSLNextChainExpiry)
	registry.MustRegister(probeSSLLastChainExpiry)

	next_chain, last_chain := getChainExpiries(tls_state.VerifiedChains)
	probeSSLNextChainExpiry.Set(float64(next_chain.Unix()))
	probeSSLLastChainExpiry.Set(float64(last_chain.Unix()))

	if config.C2S.ExportSASLMechanisms {
		registry.MustRegister(probeSASLMechanisms)
		for _, mech_available := range stream_info.SASLMechanisms {
			probeSASLMechanisms.With(prometheus.Labels{"mechanism": mech_available}).Set(1)
		}
	}

	sasl_ok := ValidateSASLMechanisms(
		stream_info.SASLMechanisms,
		config.C2S.ForbidSASLMechanisms,
		config.C2S.RequireSASLMechanisms,
	)
	if !sasl_ok {
		sl.Debugw("failing probe because of SASL requirements",
			"module", module,
			"target", target,
			"err", err,
		)
		probeFailedDueToSASLMechanism.Set(1)
	}

	return sasl_ok
}
