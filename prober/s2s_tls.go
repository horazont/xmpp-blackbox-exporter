package prober

import (
	"context"
	"crypto/tls"
	"log"
	"net"

	"mellium.im/xmpp"
	"mellium.im/xmpp/jid"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/horazont/prometheus-xmpp-blackbox-exporter/config"
)

func executeProbeS2S(ctx context.Context, conn net.Conn, from jid.JID, to jid.JID, tls_config *tls.Config) (tls_state *tls.ConnectionState, err error) {
	capture := NewCapturingStartTLS(tls_config)

	features := make([]xmpp.StreamFeature, 0)
	if tls_config != nil {
		features = append(features, capture.ToStreamFeature())
	}

	session, err := xmpp.NegotiateSession(
		ctx,
		to.Domain(),
		from,
		conn,
		false,
		xmpp.NewNegotiator(
			xmpp.StreamConfig{
				Lang:     "en",
				Features: features,
				S2S:      true,
			},
		),
	)
	defer session.Close()

	if err != nil {
		return tls_state, err
	}

	if tls_config != nil {
		tls_conn := capture.CapturedWriter.(*tls.Conn)
		err = tls_conn.Handshake()
		if err != nil {
			return tls_state, err
		}

		tls_state = &tls.ConnectionState{}
		*tls_state = tls_conn.ConnectionState()
	}

	return tls_state, nil
}

func ProbeS2S(ctx context.Context, target string, config config.Module, registry *prometheus.Registry) bool {
	probeSSLEarliestCertExpiry := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ssl_earliest_cert_expiry",
		Help: "Returns earliest SSL cert expiry date",
	})

	host, to, err := parseTarget(target, true)
	if err != nil {
		log.Printf("failed to parse target %s: %s", target, err)
		return false
	}

	// ignoring error here, the address has already been validated by the
	// config reloader
	from, _ := jid.Parse(config.S2S.From)

	tls_config, err := newTLSConfig(&config.S2S.TLSConfig, to.Domainpart())
	if err != nil {
		log.Printf("failed to process TLS config: %s", err)
		return false
	}

	tls_state_from_dial, conn, err := dialXMPP(ctx, config.S2S.DirectTLS, tls_config, host, to, true)
	if err != nil {
		log.Printf("failed to probe c2s to %s: %s", target, err)
		return false
	}
	defer conn.Close()

	var tls_state_from_probe *tls.ConnectionState
	{
		tls_config_to_pass := tls_config
		if config.S2S.DirectTLS {
			tls_config_to_pass = nil
		}
		tls_state_from_probe, err = executeProbeS2S(ctx, conn, from, to, tls_config_to_pass)
	}

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

	return true
}
