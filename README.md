# Prometheus XMPP Blackbox Exporter

This project is a [Prometheus exporter](https://prometheus.io/docs/instrumenting/exporters/)
which allows to probe XMPP services and export metrics from the probes to
Prometheus.

Like the official [blackbox_exporter](https://github.com/prometheus/blackbox_exporter),
it operates "from a distance", executing blackbox probes against the service.

## [Configuration](CONFIGURATION.md)

The configuration is very similar to the blackbox exporter. The full reference
is available in [CONFIGURATION.md](CONFIGURATION.md).

See also the [example configuration](example.yml).

## Build & Usage

```
$ export GO111MODULE=on
$ go build cmd/prometheus-xmpp-blackbox-exporter/xmpp_blackbox_exporter.go
$ ./xmpp_blackbox_exporter -config.file example.yml
```

Issue an example probe:

```
$ curl localhost:9604/probe\?module=c2s_normal_auth\&target=xmpp:xmpp.org
# HELP probe_duration_seconds Returns how long the probe took to complete in seconds
# TYPE probe_duration_seconds gauge
probe_duration_seconds 1.385793072
# HELP probe_failed_due_to_sasl_mechanism 1 if the probe failed due to a forbidden or missing SASL mechanism
# TYPE probe_failed_due_to_sasl_mechanism gauge
probe_failed_due_to_sasl_mechanism 0
# HELP probe_sasl_mechanism_offered 1 if the SASL mechanism was offered
# TYPE probe_sasl_mechanism_offered gauge
probe_sasl_mechanism_offered{mechanism="PLAIN"} 1
probe_sasl_mechanism_offered{mechanism="SCRAM-SHA-1"} 1
probe_sasl_mechanism_offered{mechanism="SCRAM-SHA-1-PLUS"} 1
# HELP probe_ssl_earliest_cert_expiry Returns earliest SSL cert expiry date
# TYPE probe_ssl_earliest_cert_expiry gauge
probe_ssl_earliest_cert_expiry 1.566256987e+09
# HELP probe_success Displays whether or not the probe was a success
# TYPE probe_success gauge
probe_success 1
```

### Target URIs

Supported formats:

* Standard connection procedure: `xmpp:some.domain.example`. Uses normal
  RFC 6120 / XEP-0368 (if `directtls: true`) connection procedure via SRV
  lookups.
* Specific connection: `xmpp://hostname:port/some.domain`. Connects to
  `hostname` at `port` to reach `some.domain`. This skips SRV lookups and can
  be used to probe individual nodes of an HA fallback chain or a cluster.

## Future Work

- Support authentication and issuing IQ pings as probes
