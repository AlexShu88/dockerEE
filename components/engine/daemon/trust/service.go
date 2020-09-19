package trust // import "github.com/docker/docker/daemon/trust"

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/distribution/reference"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/docker/distribution/registry/client/transport"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/daemon/config"
	"github.com/docker/docker/dockerversion"
	"github.com/docker/docker/registry"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/notary/storage"
	"github.com/theupdateframework/notary/tuf/data"
)

// Service provides a backend for trust validation
type Service interface {
	VerifyImageSigned(ctx context.Context, ref reference.Named, authConfig *types.AuthConfig, headers map[string][]string) (reference.Canonical, error)
}

type service struct {
	ServiceConfig
	rootKeys map[string][]string
	logger   *logrus.Entry
}

// ServiceConfig is the configuration provided to create a new trust.Service
type ServiceConfig struct {
	ContentTrustConfig *config.ContentTrust
	TrustCachePath     string
	RegistryService    registry.Service
}

var officialImagesRootKeys = []string{
	"487731f3a9ef2a094d456b37ea7880def4ced3de6f7876ed6258527ac35bcca2",
	"c6faa6d9c53edc26a372c20875f24407584674b834c719aca8c2a781a3fab49d",
	"35ecc5282ec9e9571910bd6fddd7e3b676ef3a480011b4d6e2e7a9ba9d1af1c7",
	"8530a0b0ff0d2c4db50c990faa9ba15d3593292f66312df1cb510a769388ccfa",
	"178c56227f727505bc3181c7fd33af583a6bd5dabdec6c9b3b2faa104386168a",
	"5a740b368b3b71088472e55d17e3a9e7e4bc9ef338bbf3fff3b8475911d803f7",
	"b4147b452cbb17b56eeaca3600244082bb73b2a82f986c8d549eee92baa360a1",
	"26488584f9b21efa90d15e8865c6fa22876e1b3bfc87ec79ba0d7e8aad720a03",
	"6e6beebc7346e7e7320166407b940f4283c8acb0c4940fac8c6f5c0b8dbcf3bb",
	"993134909608be52c5d833a9c6fd4626dc5b78502b4bf74bfc9bc62d290f18a0",
	"93a7bb6c0b1e5c74a141f6e4612e6f2cca1c5e29ce86fd70c61ab2b302ac5275",
	"ee3512f3b31a4a2ac723f31acf1850c1e4a0da124766a3e89c474af6b5c828eb",
	"2f1e6afeea89d56c92ed39ce661f6b29d93b20a1f1b082bc18ff0913b6bb73b5",
	"ac05a3f109ffedf8460a16f287747b04a3db877603a259a31b6ac55cd2b4ff50",
	"99185eb2ab3ccb10f8fa9f354c8c6e7bae8101c4a01dc4021e7a0446e17a50ae",
	"ee3aafa9fec9d3e458dcf56e025e5ebdc99183bd82cbe812d0d55853adc85ff1",
	"00981ccd5e43972e8885e6363a0318d9a02cab371311cd23ffd459c4731b9530",
	"c15164663f80d58bf3d8d5a0cd08b8086cba02065feb00421fc2a5436c563210",
}

// NewTrustService creates a trust.Service object
func NewTrustService(cfg ServiceConfig) Service {
	rootKeys := make(map[string][]string)
	if cfg.ContentTrustConfig.TrustPinning.OfficialLibraryImages {
		rootKeys["docker.io/library/*"] = officialImagesRootKeys
	}
	// the provided root keys take precedence over the official pinned root keys
	for key, val := range cfg.ContentTrustConfig.TrustPinning.RootKeys {
		rootKeys[key] = val
	}
	logger := logrus.WithFields(logrus.Fields{"content-trust": nil})
	return &service{cfg, rootKeys, logger}
}

func (s *service) warnIfPermissive(err error) error {
	if err == nil {
		return nil
	}
	if s.ContentTrustConfig.Mode == config.TrustModePermissive {
		s.logger.Warn(err)
		return nil
	}
	return err
}

// VerifyImageSigned takes an image reference and converts it to a canonical reference, if the image is signed.
// Otherwise, returns an error.
func (s *service) VerifyImageSigned(ctx context.Context, ref reference.Named, authConfig *types.AuthConfig, headers map[string][]string) (reference.Canonical, error) {
	trustStore, trustStoreErr := s.getTrustStore(ctx, ref, authConfig, headers)
	logf := s.logger.Errorf

	if trustStoreErr != nil {
		// Just try to use the cache instead
		if s.ContentTrustConfig.Mode == config.TrustModePermissive {
			logf = s.logger.Warnf
		}
		logf("Error looking up trust server for %s: %v", ref.Name(), trustStoreErr)
	}

	cache, err := s.getTrustCache(ref)
	if err != nil {
		return nil, s.warnIfPermissive(errors.Wrapf(err, "unable to access trust cache for %s", ref.Name()))
	}

	v := &verifier{
		cache:        cache,
		keyIDs:       s.rootKeys,
		certIDs:      s.ContentTrustConfig.TrustPinning.CertIDs,
		ignoreExpiry: s.ContentTrustConfig.AllowExpiredCachedTrustData,
	}
	canonicalRef, err := v.VerifyImage(ref, trustStore)
	if err != nil {
		return nil, s.warnIfPermissive(err)
	}
	return canonicalRef, err
}

// getTrustCache takes an image ref, and returns the cache that will be used to store
// trust data for that image.  NewFileStore will create all the necessary directories.
// nolint: interfacer
func (s *service) getTrustCache(ref reference.Named) (*storage.FilesystemStore, error) {
	imagePath := filepath.Join(s.TrustCachePath, filepath.FromSlash(ref.Name()))
	return storage.NewFileStore(imagePath, "json")
}

// getTrustStore takes an auth config and an image ref, and returns a storage.RemoteStore
// that can be used to download new trust data.  Much of this comes from
// github.com/docker/cli/trust/trust.go's GetNotaryRepository code, with some info
// from distribution/registry.go
// Note that this assumes that the trust store matches the registry name - if we allow
// configuration of separate trust servers, then this function would need to be modified
func (s *service) getTrustStore(ctx context.Context, ref reference.Named, authConfig *types.AuthConfig, metaHeaders map[string][]string) (storage.RemoteStore, error) {

	repoInfo, err := s.RegistryService.ResolveRepository(ref)
	if err != nil {
		return nil, err
	}

	server := officialNotaryServer
	if !repoInfo.Index.Official {
		if repoInfo.Index.Secure {
			server = "https://" + repoInfo.Index.Name
		} else {
			server = "http://" + repoInfo.Index.Name
		}
	}
	server = strings.TrimRight(server, "/")

	tlsConfig, err := s.RegistryService.TLSConfig(repoInfo.Index.Name)
	if err != nil {
		return nil, err
	}

	// --- stolen from distribution/registry.go ---
	direct := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	base := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         direct.DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
		DisableKeepAlives:   true,
	}

	modifiers := registry.Headers(dockerversion.DockerUserAgent(ctx), metaHeaders)
	authTransport := transport.NewTransport(base, modifiers...)

	challengeManager, err := pingNotary(server, authTransport)
	if err != nil {
		return nil, err
	}

	if authConfig != nil && authConfig.RegistryToken != "" {
		passThruTokenHandler := &existingTokenHandler{token: authConfig.RegistryToken}
		modifiers = append(modifiers, auth.NewAuthorizer(challengeManager, passThruTokenHandler))
	} else {
		scope := auth.RepositoryScope{
			Repository: ref.Name(),
			Actions:    []string{"pull"}, // we only need read access
			Class:      repoInfo.Class,
		}

		creds := registry.NewStaticCredentialStore(authConfig)
		tokenHandlerOptions := auth.TokenHandlerOptions{
			Transport:   authTransport,
			Credentials: creds,
			Scopes:      []auth.Scope{scope},
			ClientID:    registry.AuthClientID,
		}
		tokenHandler := auth.NewTokenHandlerWithOptions(tokenHandlerOptions)
		basicHandler := auth.NewBasicHandler(creds)
		modifiers = append(modifiers, auth.NewAuthorizer(challengeManager, tokenHandler, basicHandler))
	}
	tr := transport.NewTransport(base, modifiers...)

	// -------- end stolen code --------

	// Note, the GUN includes the registry name
	return storage.NewNotaryServerStore(server, data.GUN(ref.Name()), tr)
}

// pingNotary is stolen from registry/auth.go - it's similar to pinging a v2
// registry, but we don't care about the version, only that we get a
// challenge manager for the supported authentication types.  We ignore actual
// ping errors, because trust can operate from cache.
func pingNotary(endpoint string, transport http.RoundTripper) (challenge.Manager, error) {
	pingClient := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}
	endpoint = endpoint + "/v2/"
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	challengeManager := challenge.NewSimpleManager()
	resp, err := pingClient.Do(req)
	// Ignore error on ping to operate in offline mode
	if err == nil {
		defer resp.Body.Close()
		if err := challengeManager.AddResponse(resp); err != nil {
			return nil, err
		}
	}

	return challengeManager, nil
}

// ---- This also comes from distribution/registry.go ----

type existingTokenHandler struct {
	token string
}

func (th *existingTokenHandler) Scheme() string {
	return "bearer"
}

func (th *existingTokenHandler) AuthorizeRequest(req *http.Request, params map[string]string) error {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", th.token))
	return nil
}
