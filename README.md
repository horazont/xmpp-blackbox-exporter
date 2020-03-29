# Prometheus XMPP Blackbox Exporter

[![Docker Cloud Build Status](https://img.shields.io/docker/cloud/build/xsfjonas/prometheus-xmpp-blackbox-exporter.svg)](https://hub.docker.com/r/xsfjonas/prometheus-xmpp-blackbox-exporter)

This project is a [Prometheus exporter](https://prometheus.io/docs/instrumenting/exporters/)
which allows to probe XMPP services and export metrics from the probes to
Prometheus.

Like the official [blackbox_exporter](https://github.com/prometheus/blackbox_exporter),
it operates "from a distance", executing blackbox probes against the service.

## Features

- Test c2s and s2s connectivity for standard RFC 6120 hosts and hosts supporting
  [XEP-0368](https://xmpp.org/extensions/xep-0368.html).
- Test for specific SASL mechanisms
- Send IQ pings and test for specific error conditions or success
- For c2s and s2s tests, connect to specific hosts, circumventing SRV lookup
- Test In-Band registration

### Standard support

- [RFC 6120](https://tools.ietf.org/html/rfc6120) – basic XMPP client
- [XEP-0077](https://xmpp.org/extensions/xep-0077.html) v2.4 – IBR prober

  Note: Supports only non-Dataform-based registration.

- [XEP-0199](https://xmpp.org/extensions/xep-0199.html) v2.0.1 – XMPP in-band ping
- [XEP-0368](https://xmpp.org/extensions/xep-0368.html) v1.0.0 – XMPP over TLS (without STARTTLS)

  Note: Support for mixing `xmpps-client` and `xmpp-client` records is
  currently not implemented; use of `xmpps-client` records needs to be
  requested explicitly via `directtls: true` in the configuration of the
  respective prober and will override use of `xmpp-client` records. The same
  applies to `xmpps-server`.

## [Configuration](CONFIGURATION.md)

The configuration is very similar to the blackbox exporter. The full reference
is available in [CONFIGURATION.md](CONFIGURATION.md).

See also the [example configuration](example.yml).

## Build & Usage

### Building from Source

```
$ export GO111MODULE=on
$ go build cmd/prometheus-xmpp-blackbox-exporter/xmpp_blackbox_exporter.go
$ ./xmpp_blackbox_exporter -config.file example.yml
```

### Running using Docker

```
$ docker run --rm -p 9604:9604 horazont/prometheus-xmpp-blackbox-exporter:latest
```

### Example Probe

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

For c2s, s2s and IBR probes, the following target URI formats are supported:

* Standard connection procedure: `xmpp:some.domain.example`. Uses normal
  RFC 6120 / XEP-0368 (if `directtls: true`) connection procedure via SRV
  lookups.
* Specific connection: `xmpp://hostname:port/some.domain`. Connects to
  `hostname` at `port` to reach `some.domain`. This skips SRV lookups and can
  be used to probe individual nodes of an HA fallback chain or a cluster.

Ping propes only support a normal JID (not wrapped in an `xmpp:` URI) as
input. That is the JID which will be pinged from the account configured in the
configuration.
