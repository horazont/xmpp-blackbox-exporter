package prober

import (
	"context"
	"crypto/tls"
	"fmt"
	"go.uber.org/zap"
	"net"
	"time"

	"mellium.im/xmpp"
	"mellium.im/xmpp/jid"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/horazont/xmpp-blackbox-exporter/internal/config"
)

func executeProbeS2S(ctx context.Context, conn net.Conn, from jid.JID, to jid.JID, tls_config *tls.Config, ct *connTrace) (tls_state *tls.ConnectionState, info StreamInfo, err error) {
	capture := NewCapturingStartTLS(tls_config)

	features := make([]xmpp.StreamFeature, 0)
	if tls_config != nil {
		features = append(features, traceStreamFeature(capture.ToStreamFeature(), &ct.starttlsDone))
	}
	features = append(
		features,
		CheckSASLOffered(&info.SASLOffered, &info.SASLMechanisms),
		CheckDialbackOffered(&info.DialbackOffered),
	)

	session, err := xmpp.NewServerSession(
		ctx,
		to.Domain(),
		from,
		conn,
		features...,
	)
	defer session.Close()

	if err != nil {
		return tls_state, info, fmt.Errorf("failed to negotiate session: %s", err.Error())
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

func ProbeS2S(ctx context.Context, module, target string, config config.Module, _ Clients, registry *prometheus.Registry) bool {
	sl := zap.S()

	probeSSLLastChainExpiry := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ssl_earliest_cert_expiry",
		Help: "Returns the date when the last valid chain expires",
	})

	probeSSLNextChainExpiry := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ssl_next_chain_expiry",
		Help: "Returns the date when the next valid chain expires",
	})

	probeFailedDueToSASLMechanism := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_failed_due_to_sasl_mechanism",
		Help: "1 if the probe failed due to a forbidden or missing SASL mechanism",
	})

	probeFailedDueToDialback := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_failed_due_to_dialback",
		Help: "1 if the probe failed due to the offering of dialback",
	})

	durationGaugeVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_xmpp_duration_seconds",
		Help: "Duration of xmpp connection by phase",
	}, []string{"phase"})

	registry.MustRegister(durationGaugeVec)
	registry.MustRegister(probeFailedDueToSASLMechanism)
	registry.MustRegister(probeFailedDueToDialback)

	probeSASLMechanisms := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "probe_sasl_mechanism_offered",
			Help: "1 if the SASL mechanism was offered",
		},
		[]string{"mechanism"},
	)

	probeDialbackOffered := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "probe_dialback_offered",
			Help: "1 if dialback was offered",
		},
	)

	host, to, err := parseTarget(target, true)
	if err != nil {
		sl.Errorw("failed to parse s2s probe target",
			"target", target,
			"module", module,
			"err", err,
		)
		return false
	}

	// ignoring error here, the address has already been validated by the
	// config reloader
	from, _ := jid.Parse(config.S2S.From)

	tls_config, err := NewTLSConfig(&config.S2S.TLSConfig, to.Domainpart())
	if err != nil {
		sl.Errorw("failed to process TLS config for s2s probe",
			"module", module,
			"target", target,
			"err", err,
		)
		return false
	}

	ct := connTrace{}
	ct.auth = false
	ct.starttls = !config.S2S.DirectTLS
	ct.start = time.Now()

	tls_state_from_dial, conn, err := dialXMPP(ctx, config.S2S.DirectTLS, tls_config, host, to, true, config.S2S.RestrictAddressFamily)
	if err != nil {
		sl.Errorw("failed to dial for s2s probe",
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
		if config.S2S.DirectTLS {
			tls_config_to_pass = nil
		}
		tls_state_from_probe, stream_info, err = executeProbeS2S(ctx, conn, from, to, tls_config_to_pass, &ct)
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
		sl.Errorw("TLS handshake did not complete for s2s probe",
			"module", module,
			"target", target,
			"err", err,
		)
		return false
	}

	_ = stream_info

	registry.MustRegister(probeSSLNextChainExpiry)
	registry.MustRegister(probeSSLLastChainExpiry)

	next_chain, last_chain := getChainExpiries(tls_state.VerifiedChains)
	probeSSLNextChainExpiry.Set(float64(next_chain.Unix()))
	probeSSLLastChainExpiry.Set(float64(last_chain.Unix()))

	if config.S2S.ExportAuthMechanisms {
		registry.MustRegister(probeSASLMechanisms)
		registry.MustRegister(probeDialbackOffered)
		for _, mech_available := range stream_info.SASLMechanisms {
			probeSASLMechanisms.With(prometheus.Labels{"mechanism": mech_available}).Set(1)
		}
		if stream_info.DialbackOffered {
			probeDialbackOffered.Set(1)
		} else {
			probeDialbackOffered.Set(0)
		}
	}

	sasl_ok := ValidateSASLMechanisms(
		stream_info.SASLMechanisms,
		config.S2S.ForbidSASLMechanisms,
		config.S2S.RequireSASLMechanisms,
	)
	if !sasl_ok {
		sl.Debugw("failing probe because of SASL requirements",
			"module", module,
			"target", target,
			"err", err,
		)
		probeFailedDueToSASLMechanism.Set(1)
	}

	dialback_failed := (config.S2S.RequireDialback && !stream_info.DialbackOffered ||
		config.S2S.ForbidDialback && stream_info.DialbackOffered)
	if dialback_failed {
		probeFailedDueToDialback.Set(1)
	}

	return sasl_ok && !dialback_failed
}
