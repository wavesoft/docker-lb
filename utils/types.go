package utils

import (
  "crypto"
  "os/exec"

  "github.com/docker/docker/client"
  "github.com/go-acme/lego/v3/registration"
)

type CertificateProviderConfig struct {
  ConfigDir     string
  Email         string
  AuthPortHTTP  int
  AuthPortHTTPS int
}

type CertificateProvider struct {
  config           CertificateProviderConfig
  userKey          crypto.PrivateKey
  userRegistration *registration.Resource
}

type Certificate struct {
  Domain            string `json:"domain"`
  CertURL           string `json:"certUrl"`
  CertStableURL     string `json:"certStableUrl"`
  PrivateKey        []byte `json:"-"`
  Certificate       []byte `json:"-"`
  IssuerCertificate []byte `json:"-"`
  CSR               []byte `json:"-"`
}

type ProxyEndpoint struct {
  FrontendDomain string `json:"frontend_domain"`
  FrontendPath   string `json:"frontend_path"`
  BackendIP      string `json:"backend_ip"`
  BackendPort    int    `json:"backend_port"`
  BackendPath    string `json:"backend_path"`
  SSLAutoCert    bool   `json:"ssl_autocert"`
}

type HAProxyConfig struct {
  Endpoints []ProxyEndpoint
}

type HAProxyManager struct {
  config      *HAProxyConfig
  certManager *CertificateProvider
  binPath     string
  cfgPath     string
  proc        *exec.Cmd
}

type DockerMonitor struct {
  client       *client.Client
  endpointHash uint64
}
