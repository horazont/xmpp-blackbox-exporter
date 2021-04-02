package prober

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"go.uber.org/zap"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"mellium.im/xmlstream"
	"mellium.im/xmpp"
	"mellium.im/xmpp/jid"
	"mellium.im/xmpp/stanza"

	"github.com/horazont/xmpp-blackbox-exporter/internal/config"
)

type AccountInfo struct {
	Registered bool
	Account    jid.JID
	Password   string
}

type ibrCheckContext struct {
	ctx         context.Context
	config      *config.IBRProbe
	streamFrom  jid.JID
	domain      jid.JID
	accountInfo AccountInfo
	tlsConfig   *tls.Config

	durationGaugeVec *prometheus.GaugeVec
	errorGaugeVec    *prometheus.GaugeVec
}

func (c *ibrCheckContext) executeRegistration(conn net.Conn, tls_config *tls.Config, ct *connTrace) (tls_state *tls.ConnectionState, err error) {
	capture := NewCapturingStartTLS(tls_config)

	features := make([]xmpp.StreamFeature, 0)
	if tls_config != nil {
		features = append(features, traceStreamFeature(capture.ToStreamFeature(), &ct.starttlsDone))
	}
	features = append(features, Register(c.config.Prefix, c.domain.Domainpart(), &c.accountInfo.Account, &c.accountInfo.Password))

	session, err := xmpp.NewClientSession(
		c.ctx,
		c.streamFrom,
		conn,
		features...,
	)
	defer session.Close()

	if err != nil {
		return tls_state, err
	}

	c.accountInfo.Registered = true
	ct.authDone = time.Now()

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

func cancelRegistrationTokenReader() xml.TokenReader {
	return xmlstream.Wrap(
		xmlstream.MultiReader(
			xmlstream.Wrap(
				nil,
				xml.StartElement{Name: xml.Name{
					Local: "remove",
				}},
			),
		),
		xml.StartElement{Name: xml.Name{
			Space: "jabber:iq:register",
			Local: "query",
		}},
	)
}

func ProbeIBR(ctx context.Context, module, target string, config config.Module, _ Clients, registry *prometheus.Registry) bool {
	sl := zap.S()

	host, addr, err := parseTarget(target, false)
	if err != nil {
		sl.Errorw("failed to parse IBR probe target",
			"target", target,
			"module", module,
			"err", err,
		)
		return false
	}

	tls_config, err := NewTLSConfig(&config.IBR.TLSConfig, addr.Domainpart())
	if err != nil {
		sl.Errorw("failed to process TLS config for IBR probe",
			"module", module,
			"target", target,
			"err", err,
		)
		return false
	}

	c := &ibrCheckContext{
		ctx:        ctx,
		config:     &config.IBR,
		streamFrom: addr,
		domain:     addr.Domain(),
		tlsConfig:  tls_config,
		durationGaugeVec: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_xmpp_duration_seconds",
			Help: "Duration of xmpp connection by phase",
		}, []string{"phase"}),
		errorGaugeVec: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_xmpp_ibr_error",
			Help: "The last error encountered, if any",
		}, []string{"type", "condition"}),
	}

	registry.MustRegister(c.durationGaugeVec)

	ct := connTrace{}
	ct.auth = false
	ct.starttls = !config.IBR.DirectTLS
	ct.start = time.Now()

	_, conn, err := dialXMPP(ctx, config.IBR.DirectTLS, tls_config, host, addr, false, config.IBR.RestrictAddressFamily)
	if err != nil {
		sl.Errorw("failed to dial for IBR probe",
			"module", module,
			"target", target,
			"phase", "registration",
			"err", err,
		)
		return false
	}
	defer conn.Close()

	ct.connectDone = time.Now()
	c.durationGaugeVec.WithLabelValues("connect").Set(ct.connectDone.Sub(ct.start).Seconds())

	{
		tls_config_to_pass := tls_config
		if config.C2S.DirectTLS {
			tls_config_to_pass = nil
		}
		_, err = c.executeRegistration(conn, tls_config_to_pass, &ct)
	}

	if !ct.starttls {
		ct.starttlsDone = ct.connectDone
	}
	c.durationGaugeVec.WithLabelValues("starttls").Set(ct.starttlsDone.Sub(ct.connectDone).Seconds())

	if err != nil {
		sl.Debugw("registration failed",
			"module", module,
			"target", target,
			"phase", "registration",
			"err", err,
		)

		stanzaError, ok := err.(*stanza.Error)
		if ok && config.IBR.ExportErrorInfo {
			registry.MustRegister(c.errorGaugeVec)
			c.errorGaugeVec.WithLabelValues(
				string(stanzaError.Type),
				string(stanzaError.Condition),
			).Set(1)
		}

		return false
	}

	c.durationGaugeVec.WithLabelValues("register").Set(ct.authDone.Sub(ct.starttlsDone).Seconds())

	clientCfg := ClientConfig{
		TLS:           c.tlsConfig,
		ClientAddress: c.accountInfo.Account,
		Password:      c.accountInfo.Password,
		DirectTLS:     c.config.DirectTLS,
	}
	ct, conn, session, err := clientCfg.Login(c.ctx)
	if err != nil {
		sl.Errorw("failed to dial for IBR probe",
			"module", module,
			"target", target,
			"phase", "validation",
			"err", err,
		)
	}
	defer conn.Close()
	defer session.Close()

	c.durationGaugeVec.WithLabelValues("cancel-connect").Set(ct.connectDone.Sub(ct.start).Seconds())
	c.durationGaugeVec.WithLabelValues("cancel-starttls").Set(ct.starttlsDone.Sub(ct.connectDone).Seconds())
	c.durationGaugeVec.WithLabelValues("cancel-auth").Set(ct.authDone.Sub(ct.starttlsDone).Seconds())

	go session.Serve(nil)

	response_stream, err := session.SendIQ(ctx, stanza.IQ{
		Type: stanza.SetIQ,
	}.Wrap(cancelRegistrationTokenReader()))
	if response_stream != nil {
		defer response_stream.Close()
	}

	if err != nil {
		sl.Errorw("failed to log into account after IBR probe",
			"module", module,
			"target", target,
			"phase", "validation",
			"err", err,
		)
		return false
	}

	response := struct {
		stanza.IQ
		Error stanza.Error `xml:"jabber:client error"`
	}{}
	d := xml.NewTokenDecoder(response_stream)
	start_token, err := d.Token()
	start := start_token.(xml.StartElement)
	err = d.DecodeElement(&response, &start)
	if err != nil {
		sl.Errorw("failed to parse cancellation reply after IBR probe",
			"module", module,
			"target", target,
			"phase", "validation",
			"err", err,
		)
		return false
	}

	if response.Type != stanza.ResultIQ {
		sl.Errorw("failed to cancel account after IBR probe",
			"module", module,
			"target", target,
			"phase", "validation",
			"err", err,
		)
		return false
	}

	return true
}
