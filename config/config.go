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

type Module struct {
	Prober  string        `yaml:"prober,omitempty"`
	Timeout time.Duration `yaml:"timeout,omitempty"`
	C2S     C2SProbe      `yaml:"c2s,omitempty"`
	S2S     S2SProbe      `yaml:"s2s,omitempty"`
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
