# XMPP blackbox exporter configuration

The file is written in [YAML format](http://en.wikipedia.org/wiki/YAML),
defined by the scheme described below. Brackets indicate that a parameter is
optional. For non-list parameters the value is set to the specified default.

Generic placeholders are defined as follows:

* `<boolean>`: a boolean that can take the values `true` or `false`
* `<int>`: a regular integer
* `<duration>`: a duration matching the regular expression `[0-9]+(ms|[smhdwy])`
* `<filename>`: a valid path in the current working directory
* `<string>`: a regular string
* `<secret>`: a regular string that is a secret, such as a password
* `<regex>`: a regular expression

The other placeholders are specified separately.

**Note:** The concept of this configuration is intentionally very similar to
the concept of the official [blackbox_exporter](https://github.com/prometheus/blackbox_exporter).

## Configuration

The top level of the configuration file is a mapping with a single key
(`modules`), where the prober modules are configured.

```yml
modules:
    <string>: <module>
```

### <module>

```yml
    # The prober to use. One of c2s, s2s, ping.
    prober: <prober_string>

    # How long to probe before giving up
    [ timeout: <duration> ]

    # Exactly the one matching the prober string given above must be defined
    [ c2s: <c2s_probe> ]
    [ s2s: <s2s_probe> ]
    [ ping: <ping_probe> ]
```

### <c2s_probe>

```yml
    # If true, _xmpps-client SRV records will be used instead of _xmpp-client
    # SRV records and direct TLS will be used instead of STARTTLS
    [ directtls: <boolean> ]

    # If given, the named SASL mechanisms must be present in the stream
    # features after TLS, otherwise the probe fails.
    fail_if_sasl_mechanism_not_offered:
      [ - <string> ]

    # If given, the named SASL mechanisms must NOT be present in the stream
    # features after TLS, otherwise the probe fails.
    fail_if_sasl_mechanism_offered:
      [ - <string> ]

    # If true, a metric vector which names all SASL mechanisms offered by the
    # service is exported. Note that this allows the probed service to cause
    # metric churn on your Prometheus, so you might want to enable this with
    # care
    [ export_sasl_mechanisms: <boolean> ]

    # Configure how TLS is established. Used for both direct TLS and STARTTLS.
    [ tls_config: <tls_config> ]

```

### <s2s_probe>

```yml
    # If true, _xmpps-server SRV records will be used instead of _xmpp-server
    # SRV records and direct TLS will be used instead of STARTTLS
    [ directtls: <boolean> ]

    # Configure how TLS is established. Used for both direct TLS and STARTTLS.
    [ tls_config: <tls_config> ]

```

### <ping_probe>

```yml
    # If true, _xmpps-server SRV records will be used instead of _xmpp-server
    # SRV records and direct TLS will be used instead of STARTTLS
    [ directtls: <boolean> ]

    # Configure how TLS is established. Used for both direct TLS and STARTTLS.
    [ tls_config: <tls_config> ]

    # The credentials to connect with for sending the ping. At this time, only
    # password authentication is supported.
    client_address: <string>
    client_password: <string>

```

A ping probe requires a normal JID (no URI) as target.

### <tls_config>

See [upstream configuration](https://github.com/prometheus/blackbox_exporter/blob/master/CONFIGURATION.md#tls_config).
