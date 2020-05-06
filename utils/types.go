package utils

import (
	"crypto"

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
