package prober

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	pconfig "github.com/prometheus/common/config"

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

func isNotFound(err error) bool {
	dnsErr, ok := err.(*net.DNSError)
	return ok && dnsErr.IsNotFound
}

func generateFallbackRecords(service string, domainpart string) []*net.SRV {
	switch service {
	case "xmpp-client":
		return []*net.SRV{&net.SRV{
			Target: domainpart,
			Port:   5222,
		}}
	case "xmpp-server":
		return []*net.SRV{&net.SRV{
			Target: domainpart,
			Port:   5269,
		}}
	}
	return nil
}

func lookupXMPPService(ctx context.Context, resolver *net.Resolver, service string, addr jid.JID) (addrs []*net.SRV, err error) {
	_, addrs, err = resolver.LookupSRV(ctx, service, "tcp", addr.Domainpart())
	if err != nil {
		if !isNotFound(err) {
			return nil, err
		}

		return generateFallbackRecords(service, addr.Domainpart()), nil
	}

	if len(addrs) == 1 && addrs[0].Target == "." {
		return nil, nil
	}
	return addrs, nil
}

type StartTLSConfigurableDialer struct {
	net.Dialer
	DirectTLS bool
	TLSConfig *tls.Config
}

func (d *StartTLSConfigurableDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if d.DirectTLS {
		return tls.DialWithDialer(
			&d.Dialer,
			network,
			address,
			d.TLSConfig,
		)
	} else {
		return d.Dialer.DialContext(
			ctx,
			network,
			address,
		)
	}
}

type XMPPDialer struct {
	StartTLSConfigurableDialer
	S2S bool
}

func (d *XMPPDialer) Dial(ctx context.Context, network string, addr jid.JID) (net.Conn, error) {
	var service string
	if d.DirectTLS {
		if d.S2S {
			service = "xmpps-server"
		} else {
			service = "xmpps-client"
		}
	} else {
		if d.S2S {
			service = "xmpp-server"
		} else {
			service = "xmpp-client"
		}
	}

	addrs, err := lookupXMPPService(ctx, d.Resolver, service, addr)
	if err != nil {
		return nil, err
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no %s service found at address %s", service, addr.Domain())
	}

	for _, srvRecord := range addrs {
		var conn net.Conn
		var addrError error
		netAddress := net.JoinHostPort(
			srvRecord.Target,
			strconv.FormatUint(uint64(srvRecord.Port), 10),
		)
		conn, addrError = d.StartTLSConfigurableDialer.Dial(
			ctx,
			network,
			netAddress,
		)
		if addrError != nil {
			err = addrError
			continue
		}

		return conn, nil
	}

	return nil, err
}

func dialXMPP(ctx context.Context, directTLS bool, tls_config *tls.Config, host string, to jid.JID, s2s bool, restrictAddressFamily config.AddressFamily) (tls_state *tls.ConnectionState, conn net.Conn, err error) {
	ctxDeadline, _ := ctx.Deadline()

	if host == "" {
		dialer := XMPPDialer{
			StartTLSConfigurableDialer: StartTLSConfigurableDialer{
				Dialer: net.Dialer{
					Deadline: ctxDeadline,
				},
				DirectTLS: directTLS,
				TLSConfig: tls_config,
			},
			S2S: s2s,
		}
		conn, err = dialer.Dial(ctx, restrictAddressFamily.Network("tcp"), to)
	} else {
		dialer := StartTLSConfigurableDialer{
			Dialer: net.Dialer{
				Deadline: ctxDeadline,
			},
			DirectTLS: directTLS,
			TLSConfig: tls_config,
		}
		conn, err = dialer.Dial(ctx, restrictAddressFamily.Network("tcp"), host)
	}

	// Set the deadline correctly for all connections we use. This is correct
	// for both single-use connections (c2s, s2s, ibr) as well as shared
	// connections (ping; as we reset it there later).
	conn.SetDeadline(ctxDeadline)

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
