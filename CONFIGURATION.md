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
accounts:
    <string>: <account>
```

### <module>

```yml
    # The prober to use. One of c2s, s2s, ping, ibr.
    prober: <prober_string>

    # How long to probe before giving up
    [ timeout: <duration> ]

    # Exactly the one matching the prober string given above must be defined
    [ c2s: <c2s_probe> ]
    [ s2s: <s2s_probe> ]
    [ ping: <ping_probe> ]
    [ ibr: <ibr_probe> ]
```

### <c2s_probe>

Connect to the client-to-server port of the target XMPP service, negotiate TLS
and check offered SASL mechanisms.

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

    # If set, only the IP protocol version given below will be used. If the
    # XMPP service is not reachable under that version, the check will fail.
    [ restrict_ip_version: <ip_version> ]

```

### <s2s_probe>

Connect to the server-to-server port of the target XMPP service, negotiate TLS
and check offered SASL mechanisms as well as dialback.

```yml
    # The address from which the S2S stream will appear to originate.
    # Must be a domain-only bare JID.
    from: <string>

    # If true, _xmpps-server SRV records will be used instead of _xmpp-server
    # SRV records and direct TLS will be used instead of STARTTLS
    [ directtls: <boolean> ]

    # Configure how TLS is established. Used for both direct TLS and STARTTLS.
    [ tls_config: <tls_config> ]

    # If given, the named SASL mechanisms must be present in the stream
    # features after TLS, otherwise the probe fails.
    fail_if_sasl_mechanism_not_offered:
      [ - <string> ]

    # If given, the named SASL mechanisms must NOT be present in the stream
    # features after TLS, otherwise the probe fails.
    fail_if_sasl_mechanism_offered:
      [ - <string> ]

    # If true, the probe will be considered unsuccessful if dialback is
    # offered.
    [ fail_if_dialback_offered: <boolean> ]

    # If true, the probe will be considered unsuccessful if dialback is
    # NOT offered.
    [ fail_if_dialback_not_offered: <boolean> ]

    # If true, a metric vector which names all SASL mechanisms offered by the
    # service is exported. Note that this allows the probed service to cause
    # metric churn on your Prometheus, so you might want to enable this with
    # care.
    # In addition, a Gauge indicating the presence of the dialback feature is
    # exported.
    [ export_auth_mechanisms: <boolean> ]

    # If set, only the IP protocol version given below will be used. If the
    # XMPP service is not reachable under that version, the check will fail.
    [ restrict_ip_version: <ip_version> ]

```

### <ping_probe>

Log into a provisioned XMPP account and send an XMPP Ping (XEP-0199) to the
target entity of the probe.

```yml
    # The name of the account to use, as defined on the top level.
    account: <string>

    # If set to true, this ping probe will always create a fresh XMPP
    # connection which will be discarded afterwards instead of sharing a
    # single connection for multiple checks using the same account.
    [ no_shared_connection: <boolean> ]

    # Explicitly specify which results are allowed; if omitted, it defaults to
    # the successful result.
    fail_if_not:
      [ - <ping_result> ]

```

A ping probe requires a normal JID (no URI) as target.

#### <ping_result>

```yml
    # Match successful pings
    [ success: <bool> ]

    # Match on the error condition for non-successful pings
    [ error_condition: <string> ]

    # Match on the error type for non-successful pings
    [ error_type: <string> ]
```

### <ibr_probe>

Register an account at the target XMPP service, log into the new account and
delete it.

```yml
    # If true, _xmpps-client SRV records will be used instead of _xmpp-client
    # SRV records and direct TLS will be used instead of STARTTLS
    [ directtls: <boolean> ]

    # Configure how TLS is established. Used for both direct TLS and STARTTLS.
    [ tls_config: <tls_config> ]

    # Constant prefix to attach to the account names. Strongly recommended to
    # be able to clean up debris in case something goes wrong.
    [ prefix: <string> ]

    # If an error occurs during registration and this is set to true, a
    # constant metric with `type` and `condition` labels matching the
    # respective properties of the XMPP error which was returned will be
    # exported.
    #
    # Note that when using this with untrusted servers, they may be able to
    # cause a high cardinality in these labels, so enable with care.
    [ export_error_info: <boolean> ]

    # If set, only the IP protocol version given below will be used. If the
    # XMPP service is not reachable under that version, the check will fail.
    [ restrict_ip_version: <ip_version> ]

```

### <tls_config>

See [upstream configuration](https://github.com/prometheus/blackbox_exporter/blob/master/CONFIGURATION.md#tls_config).

### <account>

Configures an account used for in-band checks like the `<ping_probe>`.

```yml
    # The credentials to connect with for sending the ping. At this time, only
    # password authentication is supported.
    client_address: <string>
    client_password: <string>

    # If true, _xmpps-client SRV records will be used instead of _xmpp-client
    # SRV records and direct TLS will be used instead of STARTTLS
    [ directtls: <boolean> ]

    # Configure how TLS is established. Used for both direct TLS and STARTTLS.
    [ tls_config: <tls_config> ]

    # The maximum timeout to wait for a health check ping reply.
    # Health check pings are sent after a probe using the account failed. They
    # are sent to the domain of the account. Any reply (even an IQ error) is
    # treated as success.
    # The probe which triggered the health check is not retried.
    # The default is 15s.
    [ health_check_timeout: <duration> ]
```

### <ip_version>

A string with one of the following values: ``ipv4``, ``ipv6``.
