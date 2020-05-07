package utils

import (
  "fmt"
  "io"
  "io/ioutil"
  "os"
  "os/exec"
  "strings"
  "syscall"
  "time"

  "github.com/lithammer/dedent"
  log "github.com/sirupsen/logrus"
)

func CreateHAProxyManager(binPath string, certManager *CertificateProvider) *HAProxyManager {
  return &HAProxyManager{
    config:      &HAProxyConfig{},
    certManager: certManager,
    binPath:     binPath,
    cfgPath:     "/tmp/haproxy.conf",
    proc:        nil,
  }
}

func (h *HAProxyManager) haMonitor() {
  for h.proc != nil {
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
    return fmt.Errorf("Could not re-generate config")
  }

  log.Infof("Starting HAProxy")
  h.proc = exec.Command(h.binPath, "-f", h.cfgPath)

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
    return fmt.Errorf("Could not re-generate config")
  }

  err = h.Stop()
  if err != nil {
    return err
  }
  err = h.Start()
  if err != nil {
    return err
  }

  // log.Infof("Reloading HAProxy Configuration")
  // err = h.proc.Process.Signal(syscall.SIGUSR1)
  // if err != nil {
  //   return fmt.Errorf("Could not signal process: %s", err.Error())
  // }

  return nil
}

func (h *HAProxyManager) SetConfig(cfg *HAProxyConfig) error {
  h.config = cfg
  return h.Reload()
}

func (h *HAProxyManager) writeConfig() error {
  contents, err := h.createConfig()
  if err != nil {
    return err
  }

  log.Infof("Updating HAProxy configuration")
  return ioutil.WriteFile(h.cfgPath, contents, 0600)
}

func (h *HAProxyManager) createConfig() ([]byte, error) {
  var (
    sslCerts string = ""
  )

  // Configure front-ends
  var httpsFrontend = ""
  var httpFrontend = dedent.Dedent(`
    frontend http-in
      mode http
      bind 0.0.0.0:80
      acl url_challenge path_beg /.well-known/acme-challenge
  `)

  // Define host & path ACLs
  for num, e := range h.config.Endpoints {
    if e.FrontendDomain != "" {
      if strings.Contains(e.FrontendDomain, ":") {
        httpFrontend += fmt.Sprintf(
          "  acl host_fe%d hdr(host) -i %s\n",
          num, e.FrontendDomain,
        )
      } else {
        httpFrontend += fmt.Sprintf(
          "  acl host_fe%d req.hdr(Host),regsub(:[0-9]+$,) -i %s\n",
          num, e.FrontendDomain,
        )
      }

      if e.SSLAutoCert {
        certPath, err := h.certManager.GetCertificateForDomain(e.FrontendDomain)
        if err != nil {
          return nil, err
        }
        sslCerts += " ssl " + certPath
      }
    }
    if e.FrontendPath != "/" {
      httpFrontend += fmt.Sprintf(
        "  acl url_fe%d path_beg %s\n",
        num, e.FrontendPath,
      )
      httpsFrontend += fmt.Sprintf(
        "  acl url_fe%d path_beg %s\n",
        num, e.FrontendPath,
      )
    }
  }

  // Define usage instructions
  for num, e := range h.config.Endpoints {
    httpUse := ""
    httpsUse := ""

    if e.FrontendDomain != "" {
      httpUse += fmt.Sprintf("host_fe%d", num)
      if e.SSLAutoCert {
        httpsUse += fmt.Sprintf("{ ssl_fc_sni %s }", e.FrontendDomain)
      }
    }
    if e.FrontendPath != "/" {
      if httpUse != "" {
        httpUse += " and "
      }
      httpUse += fmt.Sprintf("url_fe%d", num)

      if e.SSLAutoCert {
        if httpsUse != "" {
          httpsUse += " and "
        }
        httpsUse += fmt.Sprintf("url_fe%d", num)
      }
    }

    if httpUse != "" {
      httpFrontend += fmt.Sprintf(
        "  use_backend be%d if %s\n",
        num, httpUse,
      )
    }
    if httpsUse != "" {
      httpsFrontend += fmt.Sprintf(
        "  use_backend be%d if %s\n",
        num, httpsUse,
      )
    }
  }

  // Define HTTPS frontend
  httpsFrontend = dedent.Dedent(fmt.Sprintf(`
    frontend https-in
        bind 0.0.0.0:443 ssl %s
        default_backend be_challenge_https
        acl url_challenge path_beg /.well-known/acme-challenge
  `, sslCerts)) + httpsFrontend

  // Add the default challenge backend routing
  httpFrontend += "  use_backend be_challenge_http if url_challenge"
  httpsFrontend += "  use_backend be_challenge_https if url_challenge"

  // Setup back-ends
  var backends = ""
  for num, e := range h.config.Endpoints {
    rewrite := ""
    if e.FrontendPath != e.BackendPath {
      rewrite = fmt.Sprintf(
        `  reqrep ^([^\ :]*)\ %s/(.*)     \1\ %s\2`,
        e.FrontendPath, e.BackendPath,
      )
    }

    backends += dedent.Dedent(fmt.Sprintf(`
      backend be%d
        mode http
        option httpclose
        option forwardfor
        server node1 %s:%d
      `,
      num, e.BackendIP, e.BackendPort,
    )) + rewrite + "\n"
  }

  // Configure globals
  var globals = dedent.Dedent(fmt.Sprintf(`
    global
      log stdout local0 info
      maxconn 4096

    defaults
      log     global
      timeout connect 5000ms
      timeout client 50000ms
      timeout server 50000ms
      option  httplog
      option  forwardfor
      option  http-server-close
      stats   enable
      stats   auth  admin:admin
      stats   uri   /haproxyStats

    backend be_challenge_http
      mode http
      server node1 127.0.0.1:%d

    backend be_challenge_https
      mode http
      server node1 127.0.0.1:%d
  `, h.certManager.config.AuthPortHTTP, h.certManager.config.AuthPortHTTPS))

  // Compose config
  contents := globals + "\n" + httpFrontend + "\n" + httpsFrontend + "\n"
  contents += backends

  log.Infof("Using config: %s", contents)

  return []byte(dedent.Dedent(contents)), nil
}
