package utils

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	// "github.com/lithammer/dedent"
	log "github.com/sirupsen/logrus"
)

type HAProxyManagerConfig struct {
	Certificates           CertificateProvider
	BinaryPath             string
	DefaultLocalServerPort int
}

type HAProxyManager struct {
	state       *HAProxyState
	config      HAProxyManagerConfig
	certManager CertificateProvider
	cfgPath     string
	proc        *exec.Cmd
}

func CreateHAProxyManager(config HAProxyManagerConfig) *HAProxyManager {
	return &HAProxyManager{
		state:       &HAProxyState{},
		config:      config,
		certManager: config.Certificates,
		cfgPath:     "/tmp/haproxy.conf",
		proc:        nil,
	}
}

func (h *HAProxyManager) haMonitor() {
	for h.proc != nil && h.proc.Process != nil {
		err := h.proc.Process.Signal(syscall.Signal(0))
		if err != nil {
			log.Warnf("HAProxy has died. Restarting")
			time.Sleep(5 * time.Second)
			h.proc = nil
			h.Start()
		}
		time.Sleep(5 * time.Second)
	}
}

func (h *HAProxyManager) Start() error {
	if h.proc != nil {
		return nil
	}

	err := h.writeConfig()
	if err != nil {
		return fmt.Errorf("Could not re-generate config: %s", err.Error())
	}

	log.Infof("Starting HAProxy")
	h.proc = exec.Command(h.config.BinaryPath, "-f", h.cfgPath)

	stdout, err := h.proc.StdoutPipe()
	if err != nil {
		return fmt.Errorf("Unable to open StdOut Pipe: %s", err.Error())
	}
	stderr, err := h.proc.StderrPipe()
	if err != nil {
		return fmt.Errorf("Unable to open StdErr Pipe: %s", err.Error())
	}
	err = h.proc.Start()
	if err != nil {
		h.proc = nil
		return fmt.Errorf("Could not start HAProxy: %s", err.Error())
	}

	// Async readers of the Stdout/Err
	go func() {
		_, _ = io.Copy(os.Stdout, stdout)
	}()
	go func() {
		_, _ = io.Copy(os.Stderr, stderr)
	}()

	// Start monitor
	go h.haMonitor()

	return nil
}

func (h *HAProxyManager) Stop() error {
	if h.proc == nil {
		return nil
	}

	log.Infof("Killing HAProxy")
	err := h.proc.Process.Kill()
	if err != nil {
		return fmt.Errorf("Could not kill process: %s", err.Error())
	}
	h.proc.Wait()

	h.proc = nil
	return nil
}

func (h *HAProxyManager) Reload() error {
	if h.proc == nil {
		return h.Start()
	}

	err := h.writeConfig()
	if err != nil {
		return fmt.Errorf("Could not re-generate config: %s", err.Error())
	}

	err = h.Stop()
	if err != nil {
		return err
	}
	err = h.Start()
	if err != nil {
		return err
	}

	return nil
}

func (h *HAProxyManager) SetState(cfg *HAProxyState) error {
	h.state = cfg
	return h.Reload()
}

func (h *HAProxyManager) writeConfig() error {
	contents, err := h.computeConfig()
	if err != nil {
		return err
	}

	log.Infof("Updating HAProxy configuration")
	return ioutil.WriteFile(h.cfgPath, contents, 0600)
}

func normalizePath(p string) string {
	// Black paths map always to root path
	if p == "" || p == "/" {
		return "/"
	}
	// Paths must always start with leading slash
	if p[0] != '/' {
		p = "/" + p
	}
	return p
}

func getBackend(list *[]*HAPBackendRecord, ep *ProxyEndpoint) *HAPBackendRecord {
	for _, r := range *list {
		if r.Host == ep.BackendIP && r.Port == ep.BackendPort &&
			r.PathBe == normalizePath(ep.BackendPath) &&
			r.PathFe == normalizePath(ep.FrontendPath) {
			return r
		}
	}

	var order int
	if ep.Order != -1 {
		order = ep.Order
	} else {
		// Unless explicitly overriden, the order the backends are processed depends
		// on the length of the path. Shorter paths get lower the order.
		pathLen := len(ep.FrontendPath)
		order = 500 - pathLen
	}

	rec := &HAPBackendRecord{
		Index:  len(*list) + 1,
		Host:   ep.BackendIP,
		Port:   ep.BackendPort,
		PathBe: normalizePath(ep.BackendPath),
		PathFe: normalizePath(ep.FrontendPath),
		Order:  order,
	}
	*list = append(*list, rec)
	return rec
}

func getFrontend(list *[]*HAPFrontendRecord, ep *ProxyEndpoint, ssl bool) *HAPFrontendRecord {
	for _, r := range *list {
		if r.Domain == ep.FrontendDomain && r.SSL == ssl {
			return r
		}
	}

	rec := &HAPFrontendRecord{
		Index:   len(*list) + 1,
		Domain:  ep.FrontendDomain,
		SSL:     ssl,
		Mapping: nil,
	}
	*list = append(*list, rec)
	return rec
}

func (f *HAPFrontendRecord) addMapping(path string, be *HAPBackendRecord) {
	f.Mapping = append(f.Mapping, &HAPMappingRecord{
		Index:   len(f.Mapping) + 1,
		Path:    normalizePath(path),
		Backend: be,
	})
}

func (h *HAProxyManager) computeConfig() ([]byte, error) {
	var (
		backends  []*HAPBackendRecord  = nil
		frontends []*HAPFrontendRecord = nil
		feCerts   []string
		feHttp    []string
		feHttps   []string
		feBeHttp  []string
		feBeHttps []string
		beAll     []string
	)

	// Map the endpoint state to frontends + backends
	for _, e := range h.state.Endpoints {
		be := getBackend(&backends, &e)

		// Add the non-SSL front-end
		fe := getFrontend(&frontends, &e, false)
		fe.addMapping(e.FrontendPath, be)

		// If this is an SSL-enabled endpoint, add the SSL frontend
		if e.SSLAutoCert {
			fe := getFrontend(&frontends, &e, true)
			fe.addMapping(e.FrontendPath, be)
		}
	}

	// Initial configuration for http backend that implements the
	// HTTP-01 challenge
	feHttp = append(feHttp,
		"frontend http-in",
		"  mode http",
		"  bind 0.0.0.0:80",
		"  acl url_challenge path_beg /.well-known/acme-challenge",
	)
	feBeHttp = append(feBeHttp,
		"  use_backend be_challenge_http if url_challenge",
	)

	// Initial configuration for https backend
	feHttps = append(feHttps,
		"frontend https-in",
		"  mode http",
	)
	for _, fe := range frontends {
		if fe.SSL {
			certPath, err := h.config.Certificates.GetCertificateForDomain(fe.Domain)
			if err != nil {
				return nil, err
			}
			feCerts = append(feCerts, fmt.Sprintf("crt %s", certPath))
		}
	}

	// Make sure we have a self-signed fallback certificates if there are no
	// certificates defined
	if len(feCerts) == 0 {
		certPath, err := h.config.Certificates.GetSelfSigned("")
		if err != nil {
			return nil, err
		}
		feCerts = append(feCerts, fmt.Sprintf("crt %s", certPath))
	}

	feHttps = append(feHttps,
		"  mode http",
		"  bind 0.0.0.0:443 ssl "+strings.Join(feCerts, " "),
	)

	// Process frontend records
	for fi, fe := range frontends {
		var (
			aclCommon  []string
			targetAcls *[]string
			targetBEs  *[]string
		)

		// Pick target where to add this rule
		if fe.SSL {
			targetAcls = &feHttps
			targetBEs = &feBeHttps
		} else {
			targetAcls = &feHttp
			targetBEs = &feBeHttp
		}

		// Add domain-specific routing
		if fe.Domain != "" {
			aclName := fmt.Sprintf("host_fe%d", fi)
			aclCommon = append(aclCommon, aclName)

			*targetAcls = append(*targetAcls,
				fmt.Sprintf("  acl %s req.hdr(Host),regsub(:[0-9]+$,) -i %s", aclName, fe.Domain),
			)
		}

		// Sort the mapping records by order
		sort.Sort(byOrder(fe.Mapping))

		// Process backend maps
		for mi, m := range fe.Mapping {
			aclList := make([]string, len(aclCommon))
			copy(aclList, aclCommon)

			log.Infof("Mapping [#%d] Backend 'be%d' for path '%s'", m.Backend.Order, m.Backend.Index, m.Path)

			// Add path-specific acl
			if m.Path != "/" {
				aclName := fmt.Sprintf("host_fe%d_url%d", fi, mi)
				aclList = append(aclList, aclName)

				*targetAcls = append(*targetAcls,
					fmt.Sprintf("  acl %s path_beg %s", aclName, m.Path),
				)
			}

			// Create the backend record to append after we are done with the ALCs
			if len(aclList) > 0 {
				*targetBEs = append(*targetBEs,
					fmt.Sprintf("  use_backend be%d if %s", m.Backend.Index, strings.Join(aclList, " ")),
				)
			} else {
				*targetBEs = append(*targetBEs,
					fmt.Sprintf("  use_backend be%d", m.Backend.Index),
				)
			}
		}
	}

	// Process backend records
	for idx, be := range backends {
		beAll = append(beAll,
			fmt.Sprintf("backend be%d", be.Index),
			"  mode http",
			"  option httpclose",
			"  option forwardfor",
			fmt.Sprintf("  server service%d %s:%d", idx, be.Host, be.Port),
		)

		// Add rewrite rule if paths mismatch
		if be.PathFe != be.PathBe {
			beAll = append(beAll,
				fmt.Sprintf(`  http-request replace-path %s(.*) %s\1`, be.PathFe, be.PathBe),
			)
		}

		beAll = append(beAll, "")
	}

	// Add a local server if enabled
	if h.config.DefaultLocalServerPort != 0 {
		// Setup backend
		beAll = append(beAll,
			"backend be_local",
			"  mode http",
			"  option httpclose",
			"  option forwardfor",
			fmt.Sprintf("  server local0 127.0.0.1:%d", h.config.DefaultLocalServerPort),
		)
		beAll = append(beAll, "")

		// Setup default sink front-end
		feBeHttp = append(feBeHttp,
			"  use_backend be_local",
		)
		feBeHttps = append(feBeHttps,
			"  use_backend be_local",
		)
	}

	// Compose final config
	config := []string{
		"global",
		"  log stdout local0 info",
		"  maxconn 4096",
		"  tune.ssl.default-dh-param 2048",
		"  stats socket /var/run/haproxy.sock mode 600 expose-fd listeners level user",
		"",
		"defaults",
		"  log     global",
		"  timeout connect          5s",
		"  timeout client          60s",
		"  timeout server          60s",
		"  timeout tunnel        3600s",
		"  timeout http-keep-alive  1s",
		"  timeout http-request    60s",
		"  timeout queue           80s",
		"  timeout tarpit          30s",
		"  option  httplog",
		"  option  dontlognull",
		"  option  http-server-close",
		"  option  forwardfor",
		"  backlog 10000",
		"  default-server inter 3s rise 2 fall 3",
		"  stats   enable",
		"  stats   auth  haproxy:st@tspassw0rd",
		"  stats   uri   /__ha_stats",
		"",
	}
	config = append(config, feHttp...)
	config = append(config, feBeHttp...)
	config = append(config, "")
	config = append(config, feHttps...)
	config = append(config, feBeHttps...)
	config = append(config, "")
	config = append(config, beAll...)
	config = append(config,
		"backend be_challenge_http",
		"  mode http",
		"  server local1 127.0.0.1:"+strconv.Itoa(h.config.Certificates.GetAuthServicePort(false)),
		"",
	)

	return []byte(strings.Join(config, "\n")), nil
}
