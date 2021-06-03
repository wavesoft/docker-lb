package utils

import (
	"github.com/docker/docker/client"
)

type CertificateProvider interface {
	GetSelfSigned(domain string) (string, error)
	GetCertificateForDomain(domain string) (string, error)
	GetAuthServicePort(ssl bool) int
	GetDomainsToReissue() []string
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

type HAProxyState struct {
	Endpoints []ProxyEndpoint
}

type DockerMonitor struct {
	client       *client.Client
	endpointHash uint64
}
