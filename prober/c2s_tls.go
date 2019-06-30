package prober

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"

	"mellium.im/xmpp"
	"mellium.im/xmpp/jid"

	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"

	"github.com/horazont/prometheus-xmpp-blackbox-exporter/config"
)

func parseTarget(target string) (string, jid.JID, error) {
	url, err := url.Parse(target)
	if err != nil {
		return "", jid.JID{}, err
	}

	if url.Scheme != "xmpp" {
		return "", jid.JID{}, fmt.Errorf("invalid URL scheme for C2S probe: %s", url.Scheme)
	}

	if url.Opaque != "" {
		return "", jid.JID{}, fmt.Errorf("automatically discovering the XMPP endpoint is not supported yet")
	}

	host := url.Host
	addr, err := jid.Parse(strings.TrimLeft(url.Path, "/"))
	if err != nil {
		return "", jid.JID{}, fmt.Errorf("failed to parse destination JID from %q: %s", url.Path, err)
	}

	if addr.Localpart() == "" {
		addr, err = addr.WithLocal("blackbox")
		if err != nil {
			return "", jid.JID{}, err
		}
	}

	return host, addr, nil
}

func dialTCP(ctx context.Context, host string) (net.Conn, error) {
	dialer := net.Dialer{}
	dialer.Deadline, _ = ctx.Deadline()
	conn, err := dialer.Dial("tcp", host)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func executeProbe(ctx context.Context, conn net.Conn, addr jid.JID, config config.C2SProbe) (tls_state tls.ConnectionState, mechanisms []string, err error) {
	tls_config, err := pconfig.NewTLSConfig(&config.TLSConfig)
	if err != nil {
		return
	}

	if tls_config.ServerName == "" {
		tls_config.ServerName = addr.Domainpart()
	}

	capture := NewCapturingStartTLS(tls_config)

	session, err := xmpp.NegotiateSession(
		ctx,
		addr.Domain(),
		addr,
		conn,
		false,
		xmpp.NewNegotiator(
			xmpp.StreamConfig{
				Lang: "en",
				Features: []xmpp.StreamFeature{
					capture.ToStreamFeature(),
					CheckSASLOffered(&mechanisms),
				},
			},
		),
	)
	defer session.Close()

	if capture.CapturedWriter == nil {
		return tls_state, mechanisms, err
	}

	tls_conn := capture.CapturedWriter.(*tls.Conn)
	err = tls_conn.Handshake()
	if err != nil {
		return tls_state, mechanisms, err
	}
	return tls_conn.ConnectionState(), mechanisms, nil
}

func ProbeC2S(ctx context.Context, target string, config config.Module, registry *prometheus.Registry) bool {
	probeSSLEarliestCertExpiry := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ssl_earliest_cert_expiry",
		Help: "Returns earliest SSL cert expiry date",
	})
	registry.MustRegister(probeSSLEarliestCertExpiry)

	probeFailedDueToSASLMechanism := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_failed_due_to_sasl_mechanism",
		Help: "1 if the probe failed due to a forbidden or missing SASL mechanism",
	})
	registry.MustRegister(probeFailedDueToSASLMechanism)

	host, addr, err := parseTarget(target)
	if err != nil {
		log.Printf("failed to parse target %s: %s", target, err)
		return false
	}

	conn, err := dialTCP(ctx, host)
	if err != nil {
		log.Printf("failed to probe c2s to %s: %s", target, err)
		return false
	}

	tls_state, mechanisms, err := executeProbe(ctx, conn, addr, config.C2S)
	if !tls_state.HandshakeComplete {
		log.Printf("handshake not completed: %s", err)
		return false
	}

	probeSSLEarliestCertExpiry.Set(float64(getEarliestCertExpiry(tls_state.VerifiedChains).Unix()))

	log.Printf("mechanisms = %s", mechanisms)

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
