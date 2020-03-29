package prober

import (
	"crypto/x509"
	"time"
)

func getEarliestCertExpiry(chains [][]*x509.Certificate) time.Time {
	has_any := false
	expiry := time.Time{}

	for _, chain := range chains {
		for _, cert := range chain {
			if (!has_any || expiry.After(cert.NotAfter)) && !cert.NotAfter.IsZero() {
				has_any = true
				expiry = cert.NotAfter
			}
		}
	}

	return expiry
}
