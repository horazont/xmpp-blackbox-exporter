package prober

import (
	"context"
	"encoding/xml"
	"go.uber.org/zap"
	"net"
	"time"

	"mellium.im/xmlstream"
	"mellium.im/xmpp"
	"mellium.im/xmpp/jid"
	"mellium.im/xmpp/stanza"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/horazont/xmpp-blackbox-exporter/internal/config"
)

type teeLogger struct {
	prefix string
	logger *zap.Logger
}

func (l teeLogger) Write(p []byte) (n int, err error) {
	l.logger.Debug(l.prefix,
		zap.Binary("data", p),
	)
	return len(p), nil
}

func ProbePing(ctx context.Context, module, target string, cfg config.Module, clients Clients, registry *prometheus.Registry) bool {
	sl := zap.S()

	durationGaugeVec := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "probe_xmpp_duration_seconds",
		Help: "Duration of xmpp connection by phase",
	}, []string{"phase"})

	pingTimeoutGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ping_timeout",
		Help: "Indicator that the ping timed out",
	})
	registry.MustRegister(pingTimeoutGauge)

	pingRTTGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_xmpp_ping_duration_seconds",
		Help: "Ping round-trip time",
	})

	var session *xmpp.Session
	var conn net.Conn
	var ct connTrace

	client, ok := clients[cfg.Ping.Account]
	if !ok {
		sl.Errorw("undeclared client; probably config reload race",
			"account", cfg.Ping.Account,
			"module", module,
		)
		return false
	}

	target_addr, err := jid.Parse(target)
	if err != nil {
		sl.Errorw("invalid ping probe target JID",
			"target", target,
			"module", module,
			"err", err,
		)
		return false
	}

	if cfg.Ping.NoSharedConnection {
		registry.MustRegister(durationGaugeVec)

		ct, conn, session, err = client.Config.Login(ctx)
		if err != nil {
			sl.Errorw("failed to established non-shared session for ping",
				"target", target,
				"account", cfg.Ping.Account,
				"module", module,
				"err", err,
			)
			return false
		}
		defer conn.Close()
		defer session.Close()
		durationGaugeVec.WithLabelValues("connect").Set(ct.connectDone.Sub(ct.start).Seconds())
		durationGaugeVec.WithLabelValues("starttls").Set(ct.starttlsDone.Sub(ct.connectDone).Seconds())
		durationGaugeVec.WithLabelValues("auth").Set(ct.authDone.Sub(ct.starttlsDone).Seconds())

		go session.Serve(nil)
	} else {
		session, err = client.AcquireSession(ctx)
		if err != nil {
			sl.Errorw("failed to acquire shared session for ping",
				"target", target,
				"account", cfg.Ping.Account,
				"module", module,
				"err", err,
			)
			return false
		}
	}

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
		sl.Errorw("failed to send stanza",
			"target", target,
			"account", cfg.Ping.Account,
			"module", module,
			"err", err,
		)
		pingTimeoutGauge.Set(1)
		if !cfg.Ping.NoSharedConnection {
			// ensure that it’s still alive
			client.Healthcheck()
		}
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
		sl.Errorw("failed to parse ping reply",
			"target", target,
			"account", cfg.Ping.Account,
			"module", module,
			"err", err,
		)
		return false
	}

	var result config.PingResult
	if response.Type == stanza.ResultIQ {
		result.Success = true
	} else if response.Type == stanza.ErrorIQ {
		result.ErrorType = string(response.Error.Type)
		result.ErrorCondition = string(response.Error.Condition)
	} else {
		sl.Errorw("failed to parse ping result",
			"target", target,
			"account", cfg.Ping.Account,
			"module", module,
			"err", err,
		)
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

	sl.Debugw("ping result did not match requirements, returning error",
		"target", target,
		"module", module,
		"account", cfg.Ping.Account,
	)
	return false
}
