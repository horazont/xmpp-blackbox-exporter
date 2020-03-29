package prober

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"log"
	"net"
	"time"

	"mellium.im/sasl"
	"mellium.im/xmlstream"
	"mellium.im/xmpp"
	"mellium.im/xmpp/jid"
	"mellium.im/xmpp/stanza"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/horazont/prometheus-xmpp-blackbox-exporter/internal/config"
)

type teeLogger struct {
	prefix string
}

func (l teeLogger) Write(p []byte) (n int, err error) {
	log.Printf("%s %s", l.prefix, p)
	return len(p), nil
}

func login(ctx context.Context, tlsConfig *tls.Config, clientAddr jid.JID, password string, directTLS bool) (ct connTrace, conn net.Conn, session *xmpp.Session, err error) {
	ct.auth = true
	ct.starttls = !directTLS
	ct.start = time.Now()

	_, conn, err = dialXMPP(ctx, directTLS, tlsConfig, "", clientAddr, false)
	if err != nil {
		log.Printf("failed to connect to domain %s: %s", clientAddr.Domainpart(), err)
		return ct, nil, nil, err
	}

	ct.connectDone = time.Now()

	features := []xmpp.StreamFeature{
		xmpp.SASL(
			clientAddr.Localpart(),
			password,
			sasl.ScramSha256Plus, sasl.ScramSha1Plus, sasl.ScramSha256, sasl.ScramSha1, sasl.Plain,
		),
		traceStreamFeature(xmpp.BindResource(), &ct.authDone),
	}
	if !directTLS {
		features = append([]xmpp.StreamFeature{traceStreamFeature(xmpp.StartTLS(true, tlsConfig), &ct.starttlsDone)}, features...)
	}

	session, err = xmpp.NegotiateSession(
		ctx,
		clientAddr.Domain(),
		clientAddr,
		conn,
		false,
		xmpp.NewNegotiator(
			xmpp.StreamConfig{
				Lang:     "en",
				Features: features,
			},
		),
	)
	if err != nil {
		conn.Close()
		return ct, nil, nil, err
	}

	if !ct.starttls {
		ct.starttlsDone = ct.connectDone
	}

	return ct, conn, session, err
}

func ProbePing(ctx context.Context, target string, cfg config.Module, registry *prometheus.Registry) bool {
	durationGaugeVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_xmpp_duration_seconds",
		Help: "Duration of xmpp connection by phase",
	}, []string{"phase"})
	registry.MustRegister(durationGaugeVec)

	pingTimeoutGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ping_timeout",
		Help: "Indicator that the ping timed out",
	})
	registry.MustRegister(pingTimeoutGauge)

	pingRTTGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_xmpp_ping_duration_seconds",
		Help: "Ping round-trip time",
	})

	client_addr, err := jid.Parse(cfg.Ping.Address)
	if err != nil {
		log.Printf("invalid client JID %q: %s", cfg.Ping.Address, err)
		return false
	}

	target_addr, err := jid.Parse(target)
	if err != nil {
		log.Printf("invalid target JID %q: %s", target, err)
		return false
	}

	tls_cfg, err := newTLSConfig(&cfg.Ping.TLSConfig, client_addr.Domainpart())
	if err != nil {
		log.Printf("invalid tls cfg: %s", err)
		return false
	}

	ct, conn, session, err := login(
		ctx,
		tls_cfg,
		client_addr,
		cfg.Ping.Password,
		cfg.Ping.DirectTLS,
	)
	if err != nil {
		log.Printf("failed to establish session for %s: %s", client_addr, err)
		return false
	}
	defer conn.Close()
	defer session.Close()

	durationGaugeVec.WithLabelValues("connect").Set(ct.connectDone.Sub(ct.start).Seconds())
	durationGaugeVec.WithLabelValues("starttls").Set(ct.starttlsDone.Sub(ct.connectDone).Seconds())
	durationGaugeVec.WithLabelValues("auth").Set(ct.authDone.Sub(ct.starttlsDone).Seconds())

	go session.Serve(nil)

	tping := time.Now()

	iq := stanza.IQ{
		To:   target_addr,
		Type: stanza.GetIQ,
	}

	response_stream, err := session.SendIQElement(ctx, xmlstream.Wrap(
		nil,
		xml.StartElement{Name: xml.Name{Local: "ping", Space: "urn:xmpp:ping"}},
	), iq)
	if response_stream != nil {
		defer response_stream.Close()
	}

	tpong := time.Now()

	registry.MustRegister(pingRTTGauge)
	pingRTTGauge.Set(tpong.Sub(tping).Seconds())

	if err != nil {
		log.Printf("failed to send stanza: %s", err)
		pingTimeoutGauge.Set(1)
		return false
	}

	response := struct {
		stanza.IQ
		Error stanza.Error `xml:"jabber:client error"`
		Ping  struct{}     `xml:"urn:xmpp:ping ping"`
	}{}
	d := xml.NewTokenDecoder(response_stream)
	start_token, err := d.Token()
	start := start_token.(xml.StartElement)
	err = d.DecodeElement(&response, &start)
	if err != nil {
		log.Printf("failed to parse: %s", err)
		return false
	}

	var result config.PingResult
	if response.Type == stanza.ResultIQ {
		result.Success = true
	} else if response.Type == stanza.ErrorIQ {
		result.ErrorType = string(response.Error.Type)
		result.ErrorCondition = string(response.Error.Condition)
	} else {
		log.Printf("failed to parse: %s", err)
		return false
	}

	permittedResults := cfg.Ping.ExpectedResults
	if permittedResults == nil {
		permittedResults = []config.PingResult{config.PingResult{Success: true}}
	}

	for _, permitted := range permittedResults {
		if permitted.Matches(result) {
			return true
		}
	}

	return false
}
