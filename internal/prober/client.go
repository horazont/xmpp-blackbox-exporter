package prober

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"log"
	"net"
	"sync"
	"time"

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
	ct.auth = true
	ct.starttls = !cfg.DirectTLS
	ct.start = time.Now()

	_, conn, err = dialXMPP(ctx, cfg.DirectTLS, cfg.TLS, "", cfg.ClientAddress, false, "")
	if err != nil {
		log.Printf("failed to connect to domain %s: %s", cfg.ClientAddress.Domainpart(), err)
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
		features = append([]xmpp.StreamFeature{traceStreamFeature(xmpp.StartTLS(true, cfg.TLS), &ct.starttlsDone)}, features...)
	}

	session, err = xmpp.NegotiateSession(
		ctx,
		cfg.ClientAddress.Domain(),
		cfg.ClientAddress,
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

type ClientFactory interface {
	Login(ctx context.Context) (ct connTrace, conn net.Conn, session *xmpp.Session, err error)
}

type Client struct {
	Config             *ClientConfig
	HealthCheckTimeout time.Duration

	// runtime state
	sessionLock sync.Mutex
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
	return result
}

// Return the current session or establish a new session if there is no
// current session.
//
// If session establishment fails, it is not retried, but an error is returned.
// The next call to AcquireSession will retry.
func (c *Client) AcquireSession(ctx context.Context) (*xmpp.Session, error) {
	c.sessionLock.Lock()
	defer c.sessionLock.Unlock()

	if c.closed {
		return nil, ErrClientClosed
	}

	if !c.isAlive {
		err := c.createSession(ctx)
		if err != nil {
			return nil, err
		}

		return c.session, nil
	}

	return c.session, nil
}

func (c *Client) createSession(ctx context.Context) error {
	_, conn, session, err := c.Config.Login(context.TODO())
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
	c.healthCheckLock.Lock()
	defer c.healthCheckLock.Unlock()
	if c.healthCheckRunning {
		return
	}

	c.sessionLock.Lock()
	defer c.sessionLock.Unlock()
	if !c.isAlive {
		return
	}

	c.healthCheckRunning = true
	go c.healthcheck()
}

func (c *Client) healthcheck() {
	c.healthCheckLock.Lock()
	defer c.healthCheckLock.Unlock()
	defer func() {
		c.healthCheckRunning = false
	}()

	iq := stanza.IQ{
		To:   c.Config.ClientAddress,
		Type: stanza.GetIQ,
	}

	session := func() *xmpp.Session {
		c.sessionLock.Lock()
		defer c.sessionLock.Unlock()
		if !c.isAlive {
			return nil
		}
		return c.session
	}()
	if session == nil {
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
		log.Printf("health check on client failed: %s", err)
		c.abort()
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
	err := c.session.Serve(nil)
	log.Printf("client session closed: %s", err)
	c.sessionLock.Lock()
	defer c.sessionLock.Unlock()
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
	c.sessionLock.Lock()
	defer c.sessionLock.Unlock()
	c.abort()
	c.closed = true
}

type Clients map[string]*Client
