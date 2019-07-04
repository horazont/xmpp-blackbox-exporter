package config

import (
	"fmt"
	"os"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/prometheus/common/config"
)

type SafeConfig struct {
	sync.RWMutex

	C *Config
}

func (sc *SafeConfig) ReloadConfig(confFile string) (err error) {
	var c = &Config{}

	yamlReader, err := os.Open(confFile)
	if err != nil {
		return fmt.Errorf("error reading config file: %s", err)
	}
	defer yamlReader.Close()

	decoder := yaml.NewDecoder(yamlReader)
	decoder.SetStrict(true)

	if err = decoder.Decode(c); err != nil {
		return fmt.Errorf("error parsing config file: %s", err)
	}

	sc.Lock()
	sc.C = c
	sc.Unlock()

	return nil
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
}

type PingResult struct {
	Success        bool   `yaml:"success",omitempty"`
	ErrorType      string `yaml:"error_type,omitempty"`
	ErrorCondition string `yaml:"error_condition,omitempty"`
}

type PingProbe struct {
	DirectTLS       bool             `yaml:"directtls,omitempty"`
	TLSConfig       config.TLSConfig `yaml:"tls_config,omitempty"`
	Address         string           `yaml:"client_address,omitempty"`
	Password        string           `yaml:"client_password,omitempty"`
	PingTimeout     time.Duration    `yaml:"ping_timeout,omitempty"`
	ExpectedResults []PingResult     `yaml:"fail_if_not,omitempty"`
}

func (r PingResult) Matches(other PingResult) bool {
	if (r.Success) {
		return other.Success
	}
	if (r.ErrorType != "" && r.ErrorType != other.ErrorType) {
		return false
	}
	if (r.ErrorCondition != "" && r.ErrorCondition != other.ErrorCondition) {
		return false
	}
	return true
}

type Module struct {
	Prober  string        `yaml:"prober,omitempty"`
	Timeout time.Duration `yaml:"timeout,omitempty"`
	C2S     C2SProbe      `yaml:"c2s,omitempty"`
	S2S     S2SProbe      `yaml:"s2s,omitempty"`
	Ping    PingProbe     `yaml:"ping,omitempty"`
}

type Config struct {
	Modules map[string]Module `yaml:"modules"`
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
