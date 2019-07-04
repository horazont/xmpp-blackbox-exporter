package prober

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	pconfig "github.com/prometheus/common/config"

	"mellium.im/xmpp"
	"mellium.im/xmpp/jid"
)

type connTrace struct {
	starttls     bool
	auth         bool
	start        time.Time
	connectDone  time.Time
	starttlsDone time.Time
	authDone     time.Time
}

func dial(ctx context.Context, directTLS bool, tls_config *tls.Config, host string, addr jid.JID, s2s bool) (tls_state *tls.ConnectionState, conn net.Conn, err error) {
	if host == "" {
		dialer := xmpp.Dialer{
			NoTLS:     !directTLS,
			S2S:       s2s,
			TLSConfig: tls_config,
		}
		dialer.Deadline, _ = ctx.Deadline()
		conn, err = dialer.Dial(ctx, "tcp", addr)
	} else {
		dialer := net.Dialer{}
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

func parseTarget(target string) (string, jid.JID, error) {
	url, err := url.Parse(target)
	if err != nil {
		return "", jid.JID{}, err
	}

	if url.Scheme != "xmpp" {
		return "", jid.JID{}, fmt.Errorf("invalid URL scheme for C2S probe: %s", url.Scheme)
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

	if addr.Localpart() == "" {
		addr, err = addr.WithLocal("blackbox")
		if err != nil {
			return "", jid.JID{}, err
		}
	}

	return host, addr, nil
}

func newTLSConfig(cfg *pconfig.TLSConfig, domain string) (*tls.Config, error) {
	tls_config, err := pconfig.NewTLSConfig(cfg)
	if err != nil {
		return nil, err
	}

	if tls_config.ServerName == "" {
		tls_config.ServerName = domain
	}
	return tls_config, err
}
