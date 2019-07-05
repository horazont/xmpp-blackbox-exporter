package prober

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"time"

	"mellium.im/xmpp"
	"mellium.im/xmpp/jid"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/horazont/prometheus-xmpp-blackbox-exporter/config"
)

func executeProbeC2S(ctx context.Context, conn net.Conn, addr jid.JID, tls_config *tls.Config, ct *connTrace) (tls_state *tls.ConnectionState, mechanisms []string, err error) {
	capture := NewCapturingStartTLS(tls_config)
	sasl_offered := false

	features := make([]xmpp.StreamFeature, 0)
	if tls_config != nil {
		features = append(features, traceStreamFeature(capture.ToStreamFeature(), &ct.starttlsDone))
	}
	features = append(features, CheckSASLOffered(&sasl_offered, &mechanisms))

	session, err := xmpp.NegotiateSession(
		ctx,
		addr.Domain(),
		addr,
		conn,
		false,
		xmpp.NewNegotiator(
			xmpp.StreamConfig{
				Lang:     "en",
				Features: features,
			},
		),
	)
	defer session.Close()

	if err != nil {
		return tls_state, mechanisms, err
	}

	if tls_config != nil {
		tls_conn := capture.CapturedWriter.(*tls.Conn)
		err = tls_conn.Handshake()
		if err != nil {
			return tls_state, mechanisms, err
		}

		tls_state = &tls.ConnectionState{}
		*tls_state = tls_conn.ConnectionState()
	}

	return tls_state, mechanisms, nil
}

func ProbeC2S(ctx context.Context, target string, config config.Module, registry *prometheus.Registry) bool {
	probeSSLEarliestCertExpiry := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ssl_earliest_cert_expiry",
		Help: "Returns earliest SSL cert expiry date",
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

	host, addr, err := parseTarget(target)
	if err != nil {
		log.Printf("failed to parse target %s: %s", target, err)
		return false
	}

	ct := connTrace{}
	ct.auth = false
	ct.starttls = !config.C2S.DirectTLS
	ct.start = time.Now()

	tls_config, err := newTLSConfig(&config.C2S.TLSConfig, addr.Domainpart())
	if err != nil {
		log.Printf("failed to process TLS config: %s", err)
		return false
	}

	tls_state_from_dial, conn, err := dial(ctx, config.C2S.DirectTLS, tls_config, host, addr, false)
	if err != nil {
		log.Printf("failed to probe c2s to %s: %s", target, err)
		return false
	}
	defer conn.Close()

	ct.connectDone = time.Now()
	durationGaugeVec.WithLabelValues("connect").Set(ct.connectDone.Sub(ct.start).Seconds())

	var tls_state_from_probe *tls.ConnectionState
	var mechanisms []string
	{
		tls_config_to_pass := tls_config
		if config.C2S.DirectTLS {
			tls_config_to_pass = nil
		}
		tls_state_from_probe, mechanisms, err = executeProbeC2S(ctx, conn, addr, tls_config_to_pass, &ct)
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
		log.Printf("handshake not completed: %s", err)
		return false
	}

	registry.MustRegister(probeSSLEarliestCertExpiry)
	probeSSLEarliestCertExpiry.Set(float64(getEarliestCertExpiry(tls_state.VerifiedChains).Unix()))

	log.Printf("mechanisms = %s", mechanisms)

	if config.C2S.ExportSASLMechanisms {
		registry.MustRegister(probeSASLMechanisms)
		for _, mech_available := range mechanisms {
			probeSASLMechanisms.With(prometheus.Labels{"mechanism": mech_available}).Set(1)
		}
	}

	if config.C2S.RequireSASLMechanisms != nil {
		hit := false
	outer:
		for _, mech_required := range config.C2S.RequireSASLMechanisms {
			for _, mech_available := range mechanisms {
				if mech_available == mech_required {
					hit = true
					break outer
				}
			}
		}
		if !hit {
			probeFailedDueToSASLMechanism.Set(1)
			return false
		}
	}

	if config.C2S.ForbidSASLMechanisms != nil {
		for _, mech_forbidden := range config.C2S.ForbidSASLMechanisms {
			for _, mech_available := range mechanisms {
				if mech_available == mech_forbidden {
					probeFailedDueToSASLMechanism.Set(1)
					return false
				}
			}
		}
	}

	return true
}
