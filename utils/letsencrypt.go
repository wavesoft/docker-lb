package utils

import (
  "crypto"
  "fmt"

  "github.com/go-acme/lego/v3/certcrypto"
  "github.com/go-acme/lego/v3/certificate"
  "github.com/go-acme/lego/v3/challenge/http01"
  "github.com/go-acme/lego/v3/challenge/tlsalpn01"
  "github.com/go-acme/lego/v3/lego"
  "github.com/go-acme/lego/v3/registration"
)

// You'll need a user or account type that implements acme.User
type acmeUser struct {
  Email        string
  Registration *registration.Resource
  key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string {
  return u.Email
}
func (u acmeUser) GetRegistration() *registration.Resource {
  return u.Registration
}
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey {
  return u.key
}

func (p *CertificateProvider) getCertificateLetsEncrypt(domain string) (*Certificate, error) {
  myUser := acmeUser{
    Email:        p.config.Email,
    Registration: p.userRegistration,
    key:          p.userKey,
  }
  config := lego.NewConfig(&myUser)

  // This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
  config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
  // config.CADirURL = "https://acme-v02.api.letsencrypt.org/directory"
  config.Certificate.KeyType = certcrypto.RSA2048

  // A client facilitates communication with the CA server.
  client, err := lego.NewClient(config)
  if err != nil {
    return nil, fmt.Errorf("Could not create lego client: %s", err.Error())
  }

  // We specify an http port of 5002 and an tls port of 5001 on all interfaces
  // because we aren't running as root and can't bind a listener to port 80 and 443
  // (used later when we attempt to pass challenges). Keep in mind that you still
  // need to proxy challenge traffic to port 5002 and 5001.
  err = client.Challenge.SetHTTP01Provider(
    http01.NewProviderServer("", fmt.Sprintf("%d", p.config.AuthPortHTTP)))
  if err != nil {
    return nil, fmt.Errorf("Could not start HTTP server: %s", err.Error())
  }
  err = client.Challenge.SetTLSALPN01Provider(
    tlsalpn01.NewProviderServer("", fmt.Sprintf("%d", p.config.AuthPortHTTPS)))
  if err != nil {
    return nil, fmt.Errorf("Could not start HTTPS server: %s", err.Error())
  }

  // New users will need to register
  if p.userRegistration == nil {
    reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
    if err != nil {
      return nil, fmt.Errorf("Could not register: %s", err.Error())
    }
    p.userRegistration = reg

    // Save the registration snapshot on disk
    err = p.saveState()
    if err != nil {
      return nil, err
    }
  }

  request := certificate.ObtainRequest{
    Domains: []string{domain},
    Bundle:  true,
  }
  certificates, err := client.Certificate.Obtain(request)
  if err != nil {
    return nil, fmt.Errorf("Could not obtain certificate: %s", err.Error())
  }

  return &Certificate{
    Domain:            certificates.Domain,
    CertURL:           certificates.CertURL,
    CertStableURL:     certificates.CertStableURL,
    PrivateKey:        certificates.PrivateKey,
    Certificate:       certificates.Certificate,
    IssuerCertificate: certificates.IssuerCertificate,
    CSR:               certificates.CSR,
  }, nil
}
