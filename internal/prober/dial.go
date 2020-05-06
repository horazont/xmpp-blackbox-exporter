package prober

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
	"time"

	pconfig "github.com/prometheus/common/config"

	"mellium.im/xmpp/dial"
	"mellium.im/xmpp/jid"

	"github.com/horazont/xmpp-blackbox-exporter/internal/config"
)

var ErrNotThisNetwork = errors.New("address family disabled by config and configured address family not offered")

type connTrace struct {
	starttls     bool
	auth         bool
	start        time.Time
	connectDone  time.Time
	starttlsDone time.Time
	authDone     time.Time
}

func dialXMPP(ctx context.Context, directTLS bool, tls_config *tls.Config, host string, to jid.JID, s2s bool, restrictAddressFamily config.AddressFamily) (tls_state *tls.ConnectionState, conn net.Conn, err error) {

	controlFunc := func(network, address string, c syscall.RawConn) error {
		if restrictAddressFamily.MatchesNetwork(network) {
			return nil
		}
		return ErrNotThisNetwork
	}

	if host == "" {
		dialer := dial.Dialer{
			NoTLS:     !directTLS,
			S2S:       s2s,
			TLSConfig: tls_config,
		}
		dialer.Control = controlFunc
		dialer.Deadline, _ = ctx.Deadline()
		conn, err = dialer.Dial(ctx, "tcp", to)
	} else {
		dialer := net.Dialer{}
		dialer.Control = controlFunc
		dialer.Deadline, _ = ctx.Deadline()
		conn, err = dialer.Dial("tcp", host)
	}

	if err != nil {
		return
	}

	if directTLS {
		tls_state = &tls.ConnectionState{}
		*tls_state = conn.(*tls.Conn).ConnectionState()
	}

	return
}

func parseTarget(target string, s2s bool) (string, jid.JID, error) {
	url, err := url.Parse(target)
	if err != nil {
		return "", jid.JID{}, err
	}

	if url.Scheme != "xmpp" {
		return "", jid.JID{}, fmt.Errorf("invalid URL scheme for probe: %s", url.Scheme)
	}

	var (
		jid_s string
		host  string
	)
	if url.Opaque != "" {
		jid_s = url.Opaque
		host = ""
	} else {
		jid_s = strings.TrimLeft(url.Path, "/")
		host = url.Host
	}

	addr, err := jid.Parse(jid_s)
	if err != nil {
		return "", jid.JID{}, fmt.Errorf("failed to parse destination JID from %q: %s", url.Path, err)
	}

	if s2s && addr.Localpart() != "" {
		return "", jid.JID{}, fmt.Errorf("S2S probes do not support a localpart")
	} else if !s2s && addr.Localpart() == "" {
		addr, err = addr.WithLocal("blackbox")
		if err != nil {
			return "", jid.JID{}, err
		}
	}

	return host, addr, nil
}

func NewTLSConfig(cfg *pconfig.TLSConfig, domain string) (*tls.Config, error) {
	tls_config, err := pconfig.NewTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	if tls_config.ServerName == "" {
		tls_config.ServerName = domain
	}
	return tls_config, err
}
