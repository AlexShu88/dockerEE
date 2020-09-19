package tpm

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/docker/go-connections/tlsconfig"
)

type keyCfg struct {
	Interface string `json:"tpm_interface"`
	Handle    string `json:"tpm_key_handle"`
	Password  string `json:"tpm_key_password,omitempty"`
}

func parseConfigFile(filepath string) (*keyCfg, error) {
	keyData, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	cfg := &keyCfg{}
	err = json.Unmarshal(keyData, cfg)
	return cfg, err
}

// IsTPMKeyFile checks if a file is a valid handle
func IsTPMKeyFile(filepath string) bool {
	_, err := parseConfigFile(filepath)
	return err == nil
}

// NewTLSConfig creates a new TLS config
func NewTLSConfig(options tlsconfig.Options) (*tls.Config, error) {
	cfg, err := parseConfigFile(options.KeyFile)
	if err != nil {
		return nil, err
	}

	conn := &conn{path: cfg.Interface}
	key, err := conn.key(cfg.Handle, cfg.Password)
	if err != nil {
		return nil, err
	}

	tlsConfig := tlsconfig.ClientDefault()
	tlsConfig.ClientAuth = options.ClientAuth
	cert := tls.Certificate{}
	cert.PrivateKey = key
	certPEMBlock, err := ioutil.ReadFile(options.CertFile)
	if err != nil {
		return nil, err
	}
	certDERBlock, _ := pem.Decode(certPEMBlock)
	if certDERBlock == nil {
		return nil, errors.New("Failed to read certificate")
	}
	if certDERBlock.Type == "CERTIFICATE" {
		cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
	}
	tlsConfig.Certificates = []tls.Certificate{cert}

	if options.ClientAuth >= tls.VerifyClientCertIfGiven && options.CAFile != "" {
		pem, err := ioutil.ReadFile(options.CAFile)
		if err != nil {
			return nil, fmt.Errorf("could not read CA certificate %q: %v", options.CAFile, err)
		}
		tlsConfig.ClientCAs.AppendCertsFromPEM(pem)
	}

	return tlsConfig, err
}
