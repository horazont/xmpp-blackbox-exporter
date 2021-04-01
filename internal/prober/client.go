package prober

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"go.uber.org/zap"
	"net"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"

	"mellium.im/sasl"
	"mellium.im/xmlstream"
	"mellium.im/xmpp"
	"mellium.im/xmpp/jid"
	"mellium.im/xmpp/stanza"
)

var ErrClientClosed = errors.New("The client is already closed")

type ClientConfig struct {
	TLS           *tls.Config
	ClientAddress jid.JID
	Password      string
	DirectTLS     bool
}

func (cfg *ClientConfig) Login(ctx context.Context) (ct connTrace, conn net.Conn, session *xmpp.Session, err error) {
	sl := zap.S()

	ct.auth = true
	ct.starttls = !cfg.DirectTLS
	ct.start = time.Now()

	_, conn, err = dialXMPP(ctx, cfg.DirectTLS, cfg.TLS, "", cfg.ClientAddress, false, "")
	if err != nil {
		sl.Debugw("failed to connect for client session",
			"domain", cfg.ClientAddress.Domainpart(),
			"err", err,
		)
		return ct, nil, nil, err
	}

	ct.connectDone = time.Now()

	features := []xmpp.StreamFeature{
		xmpp.SASL(
			cfg.ClientAddress.Localpart(),
			cfg.Password,
			sasl.ScramSha256, sasl.ScramSha1, sasl.Plain,
		),
		traceStreamFeature(xmpp.BindResource(), &ct.authDone),
	}
	if !cfg.DirectTLS {
		features = append([]xmpp.StreamFeature{traceStreamFeature(xmpp.StartTLS(cfg.TLS), &ct.starttlsDone)}, features...)
	}

	session, err = xmpp.NewSession(
		ctx,
		cfg.ClientAddress.Domain(),
		cfg.ClientAddress,
		conn,
		0,
		xmpp.NewNegotiator(
			xmpp.StreamConfig{
				Lang: "en",
				Features: func(s *xmpp.Session, _features ...xmpp.StreamFeature) []xmpp.StreamFeature {
					return features
				},
			},
		),
	)
	if err != nil {
		conn.Close()
		sl.Debugw("stream negotiation failed for client session",
			"domain", cfg.ClientAddress.Domainpart(),
			"err", err,
		)
		return ct, nil, nil, err
	}

	if !ct.starttls {
		ct.starttlsDone = ct.connectDone
	}

	return ct, conn, session, err
}

type ClientFactory interface {
	Login(ctx context.Context) (ct connTrace, conn net.Conn, session *xmpp.Session, err error)
}

type Client struct {
	Config             *ClientConfig
	HealthCheckTimeout time.Duration

	// runtime state
	sessionLock *semaphore.Weighted
	conn        net.Conn
	session     *xmpp.Session
	isAlive     bool
	closed      bool

	healthCheckLock    sync.Mutex
	healthCheckRunning bool
}

func NewClient(Config *ClientConfig) *Client {
	result := new(Client)
	result.Config = Config
	result.HealthCheckTimeout = 15 * time.Second
	result.sessionLock = semaphore.NewWeighted(1)
	return result
}

// Return the current session or establish a new session if there is no
// current session.
//
// If session establishment fails, it is not retried, but an error is returned.
// The next call to AcquireSession will retry.
func (c *Client) AcquireSession(ctx context.Context) (*xmpp.Session, error) {
	sl := zap.S()

	err := c.sessionLock.Acquire(ctx, 1)
	if err != nil {
		return nil, err
	}
	defer c.sessionLock.Release(1)

	if c.closed {
		sl.Debugw("attempt to use closed client session",
			"client_address", c.Config.ClientAddress.String(),
		)
		return nil, ErrClientClosed
	}

	if !c.isAlive {
		sl.Debugw("client session not alive, recreating",
			"client_address", c.Config.ClientAddress.String(),
		)
		err := c.createSession(ctx)
		if err != nil {
			sl.Warnw("failed to recreate offline client session",
				"client_address", c.Config.ClientAddress.String(),
				"err", err,
			)
			return nil, err
		}

		sl.Infow("client session established",
			"client_address", c.Config.ClientAddress.String(),
		)
		return c.session, nil
	}

	return c.session, nil
}

func (c *Client) createSession(ctx context.Context) error {
	_, conn, session, err := c.Config.Login(ctx)
	if err != nil {
		return err
	}

	c.conn = conn
	c.session = session
	c.isAlive = true

	go c.runSession()
	return nil
}

// Schedule a healthcheck if there isn’t currently one running
//
// If the healthcheck fails, the connection will be closed and a new session
// will be established for the next use.
func (c *Client) Healthcheck() {
	sl := zap.S()

	c.healthCheckLock.Lock()
	defer c.healthCheckLock.Unlock()
	if c.healthCheckRunning {
		return
	}

	err := c.sessionLock.Acquire(context.TODO(), 1)
	if err != nil {
		sl.Panicw("failed to acquire sessionLock despite being ready to wait for eternity",
			"client_address", c.Config.ClientAddress.String(),
			"err", err,
		)
	}
	defer c.sessionLock.Release(1)
	if !c.isAlive {
		return
	}

	c.healthCheckRunning = true
	go c.healthcheck()
}

func (c *Client) getSessionRef() *xmpp.Session {
	sl := zap.S()
	err := c.sessionLock.Acquire(context.TODO(), 1)
	if err != nil {
		sl.Warnw("failed to get lock to obtain session",
			"client_address", c.Config.ClientAddress.String(),
			"err", err,
		)
		return nil
	}
	defer c.sessionLock.Release(1)
	if !c.isAlive {
		return nil
	}
	return c.session
}

func (c *Client) healthcheck() {
	sl := zap.S()

	c.healthCheckLock.Lock()
	defer c.healthCheckLock.Unlock()
	defer func() {
		c.healthCheckRunning = false
	}()

	iq := stanza.IQ{
		To:   c.Config.ClientAddress,
		Type: stanza.GetIQ,
	}

	session := c.getSessionRef()
	if session == nil {
		sl.Warnw("client health check failed",
			"client_address", c.Config.ClientAddress.String(),
			"err", "session nil",
		)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.HealthCheckTimeout)
	response_stream, err := session.SendIQElement(
		ctx,
		xmlstream.Wrap(
			nil,
			xml.StartElement{Name: xml.Name{Local: "ping", Space: "urn:xmpp:ping"}},
		),
		iq,
	)
	cancel()
	if response_stream != nil {
		defer response_stream.Close()
	}

	if err != nil {
		sl.Warnw("client health check failed",
			"client_address", c.Config.ClientAddress.String(),
			"err", err,
		)
		// Do NOT reuse the context from above; if the health check fails, we
		// have to eventually kill the session.
		err = c.sessionLock.Acquire(context.TODO(), 1)
		if err != nil {
			sl.Warnw("failed to clean up session after failed health check",
				"client_address", c.Config.ClientAddress.String(),
				"err", err,
			)
			return
		}
		defer c.sessionLock.Release(1)
		if c.session == session {
			c.abort()
		}
		return
	}

	response := struct {
		stanza.IQ
		Error stanza.Error `xml:"jabber:client error"`
		Ping  struct{}     `xml:"urn:xmpp:ping ping"`
	}{}
	d := xml.NewTokenDecoder(response_stream)
	start_token, err := d.Token()
	start := start_token.(xml.StartElement)
	d.DecodeElement(&response, &start)
}

func (c *Client) runSession() {
	sl := zap.S()
	err := c.getSessionRef().Serve(nil)
	sl.Infow("client session closed",
		"client_address", c.Config.ClientAddress.String(),
		"err", err,
	)
	err = c.sessionLock.Acquire(context.TODO(), 1)
	if err != nil {
		sl.Warnw("failed to acquire session lock for termination",
			"client_address", c.Config.ClientAddress.String(),
			"err", err,
		)
		return
	}
	defer c.sessionLock.Release(1)
	// instakill after error
	c.abort()
}

func (c *Client) abort() {
	if c.isAlive {
		c.session.SetCloseDeadline(time.Now())
		c.session.Close()
		c.conn.Close()
		c.isAlive = false
		c.session = nil
		c.conn = nil
	}
}

func (c *Client) Close() {
	c.sessionLock.Acquire(context.TODO(), 1)
	defer c.sessionLock.Release(1)
	c.abort()
	c.closed = true
}

type Clients map[string]*Client
