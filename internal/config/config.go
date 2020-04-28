package config

import (
	"fmt"
	"os"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/prometheus/common/config"

	"mellium.im/xmpp/jid"
)

type SafeConfig struct {
	sync.RWMutex

	C *Config
}

func LoadConfig(confFile string) (c *Config, err error) {
	c = &Config{}

	yamlReader, err := os.Open(confFile)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %s", err)
	}
	defer yamlReader.Close()

	decoder := yaml.NewDecoder(yamlReader)
	decoder.SetStrict(true)

	if err = decoder.Decode(c); err != nil {
		return nil, fmt.Errorf("error parsing config file: %s", err)
	}

	if err = c.Validate(); err != nil {
		return nil, fmt.Errorf("error validating config file: %s", err)
	}

	return c, nil
}

type C2SProbe struct {
	DirectTLS             bool             `yaml:"directtls,omitempty"`
	TLSConfig             config.TLSConfig `yaml:"tls_config,omitempty"`
	RequireSASLMechanisms []string         `yaml:"fail_if_sasl_mechanism_not_offered,omitempty"`
	ForbidSASLMechanisms  []string         `yaml:"fail_if_sasl_mechanism_offered,omitempty"`
	ExportSASLMechanisms  bool             `yaml:"export_sasl_mechanisms,omitempty"`
}

type S2SProbe struct {
	DirectTLS             bool             `yaml:"directtls,omitempty"`
	TLSConfig             config.TLSConfig `yaml:"tls_config,omitempty"`
	RequireSASLMechanisms []string         `yaml:"fail_if_sasl_mechanism_not_offered,omitempty"`
	ForbidSASLMechanisms  []string         `yaml:"fail_if_sasl_mechanism_offered,omitempty"`
	RequireDialback       bool             `yaml:"fail_if_dialback_not_offered,omitempty"`
	ForbidDialback        bool             `yaml:"fail_if_dialback_offered,omitempty"`
	ExportAuthMechanisms  bool             `yaml:"export_auth_mechanisms,omitempty"`
	From                  string           `yaml:"from"`
}

type PingResult struct {
	Success        bool   `yaml:"success,omitempty"`
	ErrorType      string `yaml:"error_type,omitempty"`
	ErrorCondition string `yaml:"error_condition,omitempty"`
}

type PingProbe struct {
	Account            string        `yaml:"account,omitempty"`
	NoSharedConnection bool          `yaml:"no_shared_connection,omitempty"`
	PingTimeout        time.Duration `yaml:"ping_timeout,omitempty"`
	ExpectedResults    []PingResult  `yaml:"fail_if_not,omitempty"`
}

func (r PingResult) Matches(other PingResult) bool {
	if r.Success {
		return other.Success
	}
	if r.ErrorType != "" && r.ErrorType != other.ErrorType {
		return false
	}
	if r.ErrorCondition != "" && r.ErrorCondition != other.ErrorCondition {
		return false
	}
	return true
}

type IBRProbe struct {
	Prefix          string           `yaml:"prefix,omitempty"`
	TLSConfig       config.TLSConfig `yaml:"tls_config,omitempty"`
	DirectTLS       bool             `yaml:"directtls,omitempty"`
	ExportErrorInfo bool             `yaml:"export_error_info,omitempty"`
}

type Module struct {
	Prober  string        `yaml:"prober,omitempty"`
	Timeout time.Duration `yaml:"timeout,omitempty"`
	C2S     C2SProbe      `yaml:"c2s,omitempty"`
	S2S     S2SProbe      `yaml:"s2s,omitempty"`
	Ping    PingProbe     `yaml:"ping,omitempty"`
	IBR     IBRProbe      `yaml:"ibr,omitempty"`
}

type Account struct {
	DirectTLS bool             `yaml:"directtls,omitempty"`
	TLSConfig config.TLSConfig `yaml:"tls_config,omitempty"`
	Address   string           `yaml:"client_address,omitempty"`
	Password  string           `yaml:"client_password,omitempty"`
}

type Config struct {
	Modules  map[string]Module  `yaml:"modules"`
	Accounts map[string]Account `yaml:"accounts"`
}

func (s *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Config
	return unmarshal((*plain)(s))
}

func (s *Module) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Module
	return unmarshal((*plain)(s))
}

func (s *C2SProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain C2SProbe
	return unmarshal((*plain)(s))
}

func (s *S2SProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain S2SProbe
	return unmarshal((*plain)(s))
}

func (s *PingProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain PingProbe
	return unmarshal((*plain)(s))
}

func (p *C2SProbe) Validate() error {
	return nil
}

func (p *S2SProbe) Validate() error {
	if p.From == "" {
		return fmt.Errorf("`from` is required")
	}
	jid, err := jid.Parse(p.From)
	if err != nil {
		return fmt.Errorf("invalid address (%s): %q", err.Error(), p.From)
	}
	if jid.Localpart() != "" {
		return fmt.Errorf("invalid address (Localpart must be empty for S2S checks): %q", p.From)
	}
	if jid.Resourcepart() != "" {
		return fmt.Errorf("invalid address (Resource must be empty for S2S checks): %q", p.From)
	}

	if p.RequireDialback && p.ForbidDialback {
		return fmt.Errorf("cannot both require and forbid dialback")
	}

	return nil
}

func (p *PingProbe) Validate(validAccounts map[string]bool) error {
	if p.Account == "" {
		return fmt.Errorf("invalid account name: %q", p.Account)
	}
	if _, ok := validAccounts[p.Account]; !ok {
		return fmt.Errorf("account not declared: %q", p.Account)
	}
	return nil
}

func (p *IBRProbe) Validate() error {
	if p.Prefix == "" {
		return fmt.Errorf("prefix must not be empty")
	}
	return nil
}

func (m *Module) Validate(validAccounts map[string]bool) error {
	switch m.Prober {
	case "c2s":
		return m.C2S.Validate()
	case "s2s":
		return m.S2S.Validate()
	case "ping":
		return m.Ping.Validate(validAccounts)
	case "ibr":
		return m.IBR.Validate()
	default:
		return fmt.Errorf("invalid prober: %s", m.Prober)
	}
}

func (a *Account) Validate() error {
	if _, err := jid.Parse(a.Address); err != nil {
		return fmt.Errorf("invalid address (%s): %q", err.Error(), a.Address)
	}
	return nil
}

func (c *Config) Validate() error {
	validAccounts := make(map[string]bool)
	for name, account := range c.Accounts {
		if err := account.Validate(); err != nil {
			return fmt.Errorf("failed to validate account %q: %s", name, err.Error())
		}
		validAccounts[name] = true
	}

	for name, mod := range c.Modules {
		if err := mod.Validate(validAccounts); err != nil {
			return fmt.Errorf("failed to validate module %q: %s", name, err.Error())
		}
	}
	return nil
}
