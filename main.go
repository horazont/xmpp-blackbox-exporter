package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"

	"mellium.im/xmpp"
	"mellium.im/xmpp/jid"
)

func probeC2SAuthOffered(domain, host string, port int) error {
	addr, err := jid.Parse("null@" + domain)
	if err != nil {
		return err
	}

	tls_config := &tls.Config{
		ServerName: domain,
	}

	session, err := xmpp.DialClientSession(
		context.TODO(),
		addr,
		xmpp.StartTLS(true, tls_config),
	)
	if session == nil {
		return err
	}

	session.Close()

	return nil
}

func main() {
	connect_host_p := flag.String("connect-host", "", "")
	connect_port_p := flag.Int("connect-port", -1, "")

	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "need XMPP domain argument")
		os.Exit(2)
	}

	xmpp_domain := flag.Arg(0)

	err := probeC2SAuthOffered(xmpp_domain, *connect_host_p, *connect_port_p)
	if err != nil {
		log.Printf("probe failed: %s", err)
		os.Exit(2)
	}
}
