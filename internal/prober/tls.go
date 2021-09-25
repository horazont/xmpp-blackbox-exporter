package prober

import (
	"crypto/x509"
	"time"
)

func getChainExpiries(chains [][]*x509.Certificate) (time.Time, time.Time) {
	has_any_chain := false
	last_expiry := time.Time{}
	first_expiry := time.Time{}

	for _, chain := range chains {
		has_any_cert := false
		chain_expiry := time.Time{}
		for _, cert := range chain {
			if (!has_any_cert || chain_expiry.After(cert.NotAfter)) && !cert.NotAfter.IsZero() {
				has_any_cert = true
				chain_expiry = cert.NotAfter
			}
		}

		if !has_any_cert {
			continue
		}
		if !has_any_chain {
			first_expiry = chain_expiry
			last_expiry = chain_expiry
			has_any_chain = true
		} else {
			if chain_expiry.After(last_expiry) {
				last_expiry = chain_expiry
			}
			if chain_expiry.Before(first_expiry) {
				first_expiry = chain_expiry
			}
		}
	}

	return first_expiry, last_expiry
}
