package main

import (
	"crypto/tls"

	"github.com/docker/docker/daemon/tpm"
	"github.com/docker/go-connections/tlsconfig"
	"github.com/sirupsen/logrus"
)

func newTLSConfig(tlsOptions tlsconfig.Options) (*tls.Config, error) {
	if tpm.IsTPMKeyFile(tlsOptions.KeyFile) {
		logrus.Info("TLS server using TPM key")
		return tpm.NewTLSConfig(tlsOptions)
	}
	return tlsconfig.Server(tlsOptions)
}
