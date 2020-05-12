package utils

import (
	"fmt"
	"testing"
)

type TestCertificateProvider struct{}

func (p *TestCertificateProvider) GetSelfSigned(domain string) (string, error) {
	return fmt.Sprintf("<self:%s>", domain), nil
}

func (p *TestCertificateProvider) GetCertificateForDomain(domain string) (string, error) {
	return fmt.Sprintf("<letsencrypt:%s>", domain), nil
}

func (p *TestCertificateProvider) GetAuthServicePort(ssl bool) int {
	return 1234
}

func TestTemplateCreation(t *testing.T) {
	haCfg := HAProxyManagerConfig{
		Certificates:           &TestCertificateProvider{},
		BinaryPath:             "/usr/local/sbin/haproxy",
		DefaultLocalServerPort: 8080,
	}

	mgr := CreateHAProxyManager(haCfg)
	mgr.state = &HAProxyState{
		Endpoints: []ProxyEndpoint{
			ProxyEndpoint{
				FrontendDomain: "foo.com",
				FrontendPath:   "",
				BackendIP:      "1.2.3.4",
				BackendPort:    80,
				BackendPath:    "",
				SSLAutoCert:    true,
			},
			ProxyEndpoint{
				FrontendDomain: "foo.com",
				FrontendPath:   "service",
				BackendIP:      "1.2.3.4",
				BackendPort:    80,
				BackendPath:    "",
				SSLAutoCert:    true,
			},
		},
	}

	cfg, err := mgr.computeConfig()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Print(string(cfg))
}
