package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/v3/registration"
	log "github.com/sirupsen/logrus"
)

type DefaultCertificateProviderConfig struct {
	ConfigDir     string
	Email         string
	Organization  string
	AuthPortHTTP  int
	AuthPortHTTPS int
}

type DefaultCertificateProvider struct {
	config           DefaultCertificateProviderConfig
	userKey          crypto.PrivateKey
	userRegistration *registration.Resource
	certificates     map[string]*issuedCertificate
}

type issuedCertificate struct {
	IssueDate   time.Time `json:"issue_date"`
	ExpireDate  time.Time `json:"expire_date"`
	ReissueDate time.Time `json:"reissue_date"`
}

type persistenceFile struct {
	PrivateKey   string                        `json:"private_key"`
	Email        string                        `json:"email"`
	Registration *registration.Resource        `json:"registration,omitempty"`
	Certificates map[string]*issuedCertificate `json:"certificates"`
}

func CreateDefaultCertificateProvider(config DefaultCertificateProviderConfig) (*DefaultCertificateProvider, error) {
	inst := &DefaultCertificateProvider{config, nil, nil, make(map[string]*issuedCertificate)}

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

func (p *DefaultCertificateProvider) loadState() error {
	var (
		stateFilePath string = fmt.Sprintf("%s/state.json", p.config.ConfigDir)
		state         persistenceFile
		certNames     []string = nil
	)

	// If we are missing persistence, generate new key
	if _, err := os.Stat(stateFilePath); os.IsNotExist(err) {
		log.Warnf("State file %s is missing, assuming new installation", stateFilePath)
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
	p.certificates = state.Certificates

	for domain := range p.certificates {
		certNames = append(certNames, domain)
	}

	log.Infof("Recovered state from %s (Known certificates: %s)",
		stateFilePath, strings.Join(certNames, ", "),
	)

	return nil
}

func (p *DefaultCertificateProvider) saveState() error {
	var (
		stateFilePath string = fmt.Sprintf("%s/state.json", p.config.ConfigDir)
		state         persistenceFile
	)

	state.Email = p.config.Email
	state.Registration = p.userRegistration
	state.Certificates = p.certificates

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

func (p *DefaultCertificateProvider) generateNewKey() error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("Could not generate private key: %s", err.Error())
	}

	p.userKey = privateKey
	return p.saveState()
}

func (p *DefaultCertificateProvider) GetDomainsToReissue() []string {
	var domains []string = nil

	for domain, cert := range p.certificates {
		if time.Now().After(cert.ReissueDate) {
			domains = append(domains, domain)
		}
	}

	return domains
}

func (p *DefaultCertificateProvider) GetAuthServicePort(ssl bool) int {
	if ssl {
		return p.config.AuthPortHTTPS
	}
	return p.config.AuthPortHTTP
}

func (p *DefaultCertificateProvider) GetSelfSigned(domain string) (string, error) {
	var (
		certFilePath string = fmt.Sprintf("%s/cert/selfsigned-%s.pem", p.config.ConfigDir, domain)
	)

	// Crate if missing
	if _, err := os.Stat(certFilePath); os.IsNotExist(err) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", fmt.Errorf("Could not generate private key: %s", err.Error())
		}

		validFor := 365 * 24 * time.Hour
		notBefore := time.Now()
		notAfter := notBefore.Add(validFor)

		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return "", fmt.Errorf("Failed to generate serial number: %s", err.Error())
		}

		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization: []string{p.config.Organization},
				CommonName:   domain,
			},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		// fmt.Printf("%+v (%s)\n", priv, reflect.TypeOf(priv))
		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
		if err != nil {
			return "", fmt.Errorf("Failed to create certificate: %s", err.Error())
		}

		certOut, err := os.OpenFile(certFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return "", fmt.Errorf("Failed to create %s: %s", certFilePath, err.Error())
		}

		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
			return "", fmt.Errorf("Failed to write %s: %s", certFilePath, err.Error())
		}

		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return "", fmt.Errorf("Unable to marshal private key: %v", err)
		}

		if err := pem.Encode(certOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
			return "", fmt.Errorf("Failed to write %s: %s", certFilePath, err.Error())
		}

		if err := certOut.Close(); err != nil {
			return "", fmt.Errorf("Error closing %s: %s", certFilePath, err.Error())
		}
	}

	return certFilePath, nil
}

func (p *DefaultCertificateProvider) GetCertificateForDomain(domain string) (string, error) {
	var (
		certFilePath string = fmt.Sprintf("%s/cert/%s.pem", p.config.ConfigDir, domain)
		isValid      bool   = true
	)

	// Check validity
	if _, err := os.Stat(certFilePath); os.IsNotExist(err) {
		log.Warnf("Certificate for domain %s is missing, going to re-issue", domain)
		isValid = false
	}
	if isValid {
		if cert, ok := p.certificates[domain]; ok {
			if time.Now().After(cert.ReissueDate) {
				isValid = false
				log.Warnf("Certificate for domain %s reached re-issue timestamp, re-issuing now", domain)
			}
		} else {
			isValid = false
			log.Warnf("Certificate timestamp for domain %s is missing, going to re-issue", domain)
		}
	}

	// Crate if missing
	if !isValid {
		cert, err := p.getCertificateLetsEncrypt(domain)
		if err != nil {
			return "", fmt.Errorf("Could not create cert for %s: %s", domain, err.Error())
		}

		err = cert.WriteTo(certFilePath)
		if err != nil {
			return "", fmt.Errorf("Could not write cert for %s: %s", domain, err.Error())
		}

		// Let's encrypt issues 90-day certificates, so cache this result for
		// future certificate re-issuing
		p.certificates[domain] = &issuedCertificate{
			IssueDate:   time.Now(),
			ExpireDate:  time.Now().Add(90 * 24 * time.Hour),
			ReissueDate: time.Now().Add(75 * 24 * time.Hour), // Leave 15 days to manually fix
		}
		err = p.saveState()
		if err != nil {
			return "", fmt.Errorf("Could not save state: %s", err.Error())
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
