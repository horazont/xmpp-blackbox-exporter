package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"mellium.im/xmpp/jid"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/horazont/xmpp-blackbox-exporter/internal/config"
	"github.com/horazont/xmpp-blackbox-exporter/internal/prober"
)

type RuntimeState struct {
	sync.RWMutex

	C       *config.Config
	Clients prober.Clients
}

func NewRuntimeState() *RuntimeState {
	return &RuntimeState{
		sync.RWMutex{},
		&config.Config{},
		make(map[string]*prober.Client),
	}
}

func (st *RuntimeState) ReloadConfig(path string) error {
	cfg, err := config.LoadConfig(path)
	if err != nil {
		return err
	}

	newClients := make(map[string]*prober.Client)
	for name, accountCfg := range cfg.Accounts {
		clientAddress := jid.MustParse(accountCfg.Address)
		tlsConfig, err := prober.NewTLSConfig(
			&accountCfg.TLSConfig,
			clientAddress.Domainpart(),
		)
		if err != nil {
			return fmt.Errorf(
				"failed to configure TLS for account %q: %s",
				name,
				err,
			)
		}

		client := prober.NewClient(
			&prober.ClientConfig{
				TLS:           tlsConfig,
				ClientAddress: clientAddress,
				Password:      accountCfg.Password,
				DirectTLS:     accountCfg.DirectTLS,
			},
		)

		if accountCfg.HealthCheckTimeout != 0 {
			client.HealthCheckTimeout = accountCfg.HealthCheckTimeout
		}

		newClients[name] = client
	}

	st.Lock()
	defer st.Unlock()

	for _, client := range st.Clients {
		client.Close()
	}
	st.C = cfg
	st.Clients = newClients

	return nil
}

var (
	sc = NewRuntimeState()

	Probers = map[string]prober.ProbeFn{
		"c2s":  prober.ProbeC2S,
		"s2s":  prober.ProbeS2S,
		"ping": prober.ProbePing,
		"ibr":  prober.ProbeIBR,
	}
)

func probeHandler(w http.ResponseWriter, r *http.Request, conf *config.Config, clients prober.Clients) {
	moduleName := r.URL.Query().Get("module")
	module, ok := conf.Modules[moduleName]
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown module %q", moduleName), http.StatusBadRequest)
		return
	}

	timeoutSeconds, err := getTimeout(r, module, 0)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse timeout from Prometheus header: %s", err), http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds*float64(time.Second)))
	defer cancel()

	r = r.WithContext(ctx)

	probeSuccessGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_success",
		Help: "Displays whether or not the probe was a success",
	})
	probeDurationGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_duration_seconds",
		Help: "Returns how long the probe took to complete in seconds",
	})

	params := r.URL.Query()
	target := params.Get("target")
	if target == "" {
		http.Error(w, "Target parameter is missing", http.StatusBadRequest)
		return
	}

	prober, ok := Probers[module.Prober]
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown prober %q", module.Prober), http.StatusBadRequest)
		return
	}

	start := time.Now()
	registry := prometheus.NewRegistry()
	registry.MustRegister(probeSuccessGauge)
	registry.MustRegister(probeDurationGauge)

	success := prober(ctx, target, module, clients, registry)
	duration := time.Since(start).Seconds()
	probeDurationGauge.Set(duration)

	if success {
		probeSuccessGauge.Set(1)
	} else {
		log.Printf("probe failed")
	}

	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func run() int {
	config_file := flag.String("config.file", "", "")
	listen_address := flag.String("web.listen-address", "localhost:9604", "")

	flag.Parse()

	if err := sc.ReloadConfig(*config_file); err != nil {
		log.Printf("failed to load config file from %s: %s", *config_file, err)
		return 2
	}

	hup := make(chan os.Signal, 1)
	reloadCh := make(chan chan error)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-hup:
				if err := sc.ReloadConfig(*config_file); err != nil {
					log.Printf("failed to reload config file from %s: %s", *config_file, err)
					continue
				}
				log.Printf("reloaded configuration from %s", *config_file)
			case rc := <-reloadCh:
				if err := sc.ReloadConfig(*config_file); err != nil {
					log.Printf("failed to reload config file from %s: %s", *config_file, err)
					rc <- err
				} else {
					log.Printf("reloaded configuration from %s", *config_file)
					rc <- nil
				}
			}
		}
	}()

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		sc.RLock()
		conf := sc.C
		clients := sc.Clients
		sc.RUnlock()
		// worst that should be able to happen for us running this outside of
		// the lock is that a client is already disconnected when the prober
		// runs during a reload
		//
		// I think this is tolerable. If you think it is not, please file an
		// issue and we’ll pull the probeHandler into the RLock()/Unlock()
		// block
		probeHandler(w, r, conf, clients)
	})

	srv := http.Server{Addr: *listen_address}
	srvc := make(chan struct{})
	term := make(chan os.Signal, 1)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("listening on address %s", *listen_address)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("error starting http server: %s", err)
			close(srvc)
		}
	}()

	for {
		select {
		case <-term:
			log.Printf("received signal, stopping gracefully")
			return 0
		case <-srvc:
			return 1
		}
	}
}

func main() {
	os.Exit(run())
}

func getTimeout(r *http.Request, module config.Module, offset float64) (timeoutSeconds float64, err error) {
	// If a timeout is configured via the Prometheus header, add it to the request.
	if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
		var err error
		timeoutSeconds, err = strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, err
		}
	}
	if timeoutSeconds == 0 {
		timeoutSeconds = 10
	}

	var maxTimeoutSeconds = timeoutSeconds - offset
	if module.Timeout.Seconds() < maxTimeoutSeconds && module.Timeout.Seconds() > 0 {
		timeoutSeconds = module.Timeout.Seconds()
	} else {
		timeoutSeconds = maxTimeoutSeconds
	}

	return timeoutSeconds, nil
}
