package registry

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/daemon/tpm"
	"github.com/docker/go-connections/tlsconfig"
	"github.com/sirupsen/logrus"
)

func getTLSOptions(hostDir string) (*tlsconfig.Options, error) {
	tlsOptions := &tlsconfig.Options{}
	fs, err := ioutil.ReadDir(hostDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	for _, f := range fs {
		path := filepath.Join(hostDir, f.Name())
		if strings.HasSuffix(f.Name(), ".crt") {
			logrus.Debugf("crt: %s", path)
			tlsOptions.CAFile = path
		}
		if strings.HasSuffix(f.Name(), ".cert") {
			keyName := f.Name()[:len(f.Name())-5] + ".key"
			logrus.Debugf("cert: %s", path)
			if !hasFile(fs, keyName) {
				return nil, fmt.Errorf("missing key %s for client certificate %s. Note that CA certificates should use the extension .crt", keyName, path)
			}
			tlsOptions.CertFile = path
		}
		if strings.HasSuffix(f.Name(), ".key") {
			certName := f.Name()[:len(f.Name())-4] + ".cert"
			logrus.Debugf("key: %s", path)
			if !hasFile(fs, certName) {
				return nil, fmt.Errorf("Missing client certificate %s for key %s", certName, path)
			}
			tlsOptions.KeyFile = path
		}
	}
	return tlsOptions, nil
}

func newTLSCfg(hostDir string) (*tls.Config, error) {
	tlsOptions, err := getTLSOptions(hostDir)
	if err != nil {
		return nil, err
	}

	if tpm.IsTPMKeyFile(tlsOptions.KeyFile) {
		logrus.Info("Registry client using TPM key")
		return tpm.NewTLSConfig(*tlsOptions)
	}
	// PreferredServerCipherSuites should have no effect
	tlsConfig := tlsconfig.ServerDefault()
	// TODO redundant walk of certs directory alongside getTLSOptions here - we could refactor to consume tlsOptions instead of hostDir
	if err := ReadCertsDirectory(tlsConfig, hostDir); err != nil {
		return nil, err
	}
	return tlsConfig, nil
}
