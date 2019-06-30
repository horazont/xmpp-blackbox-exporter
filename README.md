# Prometheus XMPP Blackbox Exporter

This project is a [Prometheus exporter](https://prometheus.io/docs/instrumenting/exporters/)
which allows to probe XMPP services and export metrics from the probes to
Prometheus.

Like the official [blackbox_exporter](https://github.com/prometheus/blackbox_exporter),
it operates "from a distance", executing blackbox probes against the service.

## Configuration

The configuration is very similar to the blackbox exporter. Please refer to
there for the style. Currently, there is only one prober implemented (`c2s`)
which establishes a C2S connection with TLS and exports TLS information and
can check for offered SASL mechanisms. Login is not supported yet.

## Build & Usage

```
$ dep ensure
$ go build cmd/prometheus-xmpp-blackbox-exporter/xmpp_blackbox_exporter.go
$ ./xmpp_blackbox_exporter -config.file example.yml -web.listen-address localhost:9900
```

Issue an example probe (this is my service at the time of writing):

```
$ curl localhost:9900/probe\?module=c2s_normal_auth\&target=xmpp://xmpp-public.sotecware.net:5222/sotecware.net
```

The host part of the URL specifies the exact machine/port to connect to, to
skip SRV resolution (not skipping resolution is currently not supported). This
allows to probe multiple nodes of a cluster independently and
deterministically.

## Future Work

- Support for S2S streams
- Support for SRV resolution
- Support for direct TLS (XEP-0368)
- Support authentication and issuing IQ pings as probes
