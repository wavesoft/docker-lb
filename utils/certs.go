package utils

import (
  "crypto/ecdsa"
  "crypto/elliptic"
  "crypto/rand"
  "crypto/x509"
  "encoding/base64"
  "encoding/json"
  "fmt"
  "io/ioutil"
  "os"

  "github.com/go-acme/lego/v3/registration"
)

type persistenceFile struct {
  PrivateKey   string                 `json:"private_key"`
  Email        string                 `json:"email"`
  Registration *registration.Resource `json:"registration,omitempty"`
}

func CreateCertificateProvider(config CertificateProviderConfig) (*CertificateProvider, error) {
  inst := &CertificateProvider{config, nil, nil}

  // Create mssing directories
  if _, err := os.Stat(config.ConfigDir); os.IsNotExist(err) {
    os.MkdirAll(config.ConfigDir, 0700)
  }
  if _, err := os.Stat(config.ConfigDir + "/cert"); os.IsNotExist(err) {
    os.MkdirAll(config.ConfigDir+"/cert", 0700)
  }

  // Load state
  err := inst.loadState()
  if err != nil {
    return nil, err
  }
  return inst, nil
}

func (p *CertificateProvider) loadState() error {
  var (
    stateFilePath string = fmt.Sprintf("%s/state.json", p.config.ConfigDir)
    state         persistenceFile
  )

  // If we are missing persistence, generate new key
  if _, err := os.Stat(stateFilePath); os.IsNotExist(err) {
    return p.generateNewKey()
  }

  // Load state from persistence
  data, err := ioutil.ReadFile(stateFilePath)
  if err != nil {
    return fmt.Errorf("Could not read state file: %s", err.Error())
  }
  err = json.Unmarshal(data, &state)
  if err != nil {
    return fmt.Errorf("Could not parse state file: %s", err.Error())
  }

  // If the persisted e-mail is different, bail early
  if state.Email != p.config.Email {
    return fmt.Errorf("The persisted e-mail (%s) is different than the one given (%s)",
      state.Email, p.config.Email)
  }

  // Load the private key from the file
  data, err = base64.StdEncoding.DecodeString(state.PrivateKey)
  if err != nil {
    return fmt.Errorf("Could not load private key: %s", err.Error())
  }
  key, err := x509.ParseECPrivateKey(data)
  if err != nil {
    return fmt.Errorf("Could not parse private key: %s", err.Error())
  }

  p.userKey = key
  p.userRegistration = state.Registration

  return nil
}

func (p *CertificateProvider) saveState() error {
  var (
    stateFilePath string = fmt.Sprintf("%s/state.json", p.config.ConfigDir)
    state         persistenceFile
  )

  state.Email = p.config.Email
  state.Registration = p.userRegistration

  pKey, err := x509.MarshalECPrivateKey(p.userKey.(*ecdsa.PrivateKey))
  if err != nil {
    return fmt.Errorf("Could not marshal private key: %s", err.Error())
  }

  state.PrivateKey = base64.StdEncoding.EncodeToString(pKey)

  bt, err := json.Marshal(state)
  if err != nil {
    return fmt.Errorf("Could not marshal state: %s", err.Error())
  }
  err = ioutil.WriteFile(stateFilePath, bt, 0600)
  if err != nil {
    return fmt.Errorf("Could not write state file: %s", err.Error())
  }

  return nil
}

func (p *CertificateProvider) generateNewKey() error {
  privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  if err != nil {
    return fmt.Errorf("Could not generate private key: %s", err.Error())
  }

  p.userKey = privateKey
  return p.saveState()
}

func (p *CertificateProvider) GetCertificateForDomain(domain string) (string, error) {
  var (
    certFilePath string = fmt.Sprintf("%s/cert/%s.pem", p.config.ConfigDir, domain)
  )

  // Crate if missing
  if _, err := os.Stat(certFilePath); os.IsNotExist(err) {
    cert, err := p.getCertificateLetsEncrypt(domain)
    if err != nil {
      return "", fmt.Errorf("Could not create cert for %s: %s", domain, err.Error())
    }

    err = cert.WriteTo(certFilePath)
    if err != nil {
      return "", fmt.Errorf("Could not write cert for %s: %s", domain, err.Error())
    }
  }

  return certFilePath, nil
}

func (c *Certificate) WriteTo(filename string) error {
  var buf []byte

  buf = append(buf, c.PrivateKey...)
  buf = append(buf, c.Certificate...)

  return ioutil.WriteFile(filename, buf, 0600)
}
