package daemon

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/dockerversion"
	"github.com/docker/licensing"
	"github.com/docker/licensing/model"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	licenseNamePrefix       = "com.docker.license"
	licenseFilename         = "docker.lic"
	licensingDefaultBaseURI = "https://store.docker.com"
	defaultLicense          = "Unlicensed - not for production workloads"

	mirantisLicensePublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3WOM60JOLa4xBj8ZH91k
zEvvTWUOPyQNqF7PkR1oUx4VhiXBVi8wjlCxBE2KvITol69J9uB/PyJSeLKN1IXe
DYkmsNHRp+2nv5kh1hvptODQhhZC+gGV2wjQ76fNY8rCrVXN1NBwry8UPSbStOWG
a5WN59E+eBBslhehaeQL1vbrcWBfs6rA8wOHHvSc6zFbuPMVQF8T/FyLCwKFijvt
RNeeNsTQfGvXDPMkazRDo061K6UhPRWG01cBuqqOIudPdKqyPjKflKd05Ck4FCtO
SSvdB9xXgzfkCBt+Z/IRt9dEOatGVN7IN31iw6JgJGzxjQDRE/RDUQ7uoxL1c8vz
hQIDAQAB
-----END PUBLIC KEY-----
`
)

var (
	// licensingPublicKeys are the official public license key for store.docker.com
	// nolint: lll
	legacyLicensingPublicKeys = []string{
		"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0Ka2lkOiBKN0xEOjY3VlI6TDVIWjpVN0JBOjJPNEc6NEFMMzpPRjJOOkpIR0I6RUZUSDo1Q1ZROk1GRU86QUVJVAoKTUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FnOEFNSUlDQ2dLQ0FnRUF5ZEl5K2xVN283UGNlWSs0K3MrQwpRNU9FZ0N5RjhDeEljUUlXdUs4NHBJaVpjaVk2NzMweUNZbndMU0tUbHcrVTZVQy9RUmVXUmlvTU5ORTVEczVUCllFWGJHRzZvbG0ycWRXYkJ3Y0NnKzJVVUgvT2NCOVd1UDZnUlBIcE1GTXN4RHpXd3ZheThKVXVIZ1lVTFVwbTEKSXYrbXE3bHA1blEvUnhyVDBLWlJBUVRZTEVNRWZHd20zaE1PL2dlTFBTK2hnS1B0SUhsa2c2L1djb3hUR29LUAo3OWQvd2FIWXhHTmw3V2hTbmVpQlN4YnBiUUFLazIxbGc3OThYYjd2WnlFQVRETXJSUjlNZUU2QWRqNUhKcFkzCkNveVJBUENtYUtHUkNLNHVvWlNvSXUwaEZWbEtVUHliYncwMDBHTyt3YTJLTjhVd2dJSW0waTVJMXVXOUdrcTQKempCeTV6aGdxdVVYYkc5YldQQU9ZcnE1UWE4MUR4R2NCbEp5SFlBcCtERFBFOVRHZzR6WW1YakpueFpxSEVkdQpHcWRldlo4WE1JMHVrZmtHSUkxNHdVT2lNSUlJclhsRWNCZi80Nkk4Z1FXRHp4eWNaZS9KR1grTEF1YXlYcnlyClVGZWhWTlVkWlVsOXdYTmFKQitrYUNxejVRd2FSOTNzR3crUVNmdEQwTnZMZTdDeU9IK0U2dmc2U3QvTmVUdmcKdjhZbmhDaVhJbFo4SE9mSXdOZTd0RUYvVWN6NU9iUHlrbTN0eWxyTlVqdDBWeUFtdHRhY1ZJMmlHaWhjVVBybQprNGxWSVo3VkQvTFNXK2k3eW9TdXJ0cHNQWGNlMnBLRElvMzBsSkdoTy8zS1VtbDJTVVpDcXpKMXlFbUtweXNICjVIRFc5Y3NJRkNBM2RlQWpmWlV2TjdVQ0F3RUFBUT09Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=",
		"LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0Ka2V5SUQ6IFpGSjI6Q1c1Szo1M0tSOlo0NUg6NlpVQzpJNFhFOlpUS1A6TVQ1UjpQWFpMOlNTNE46RjQ0NDo0U1Q0CmtpZDogWkZKMjpDVzVLOjUzS1I6WjQ1SDo2WlVDOkk0WEU6WlRLUDpNVDVSOlBYWkw6U1M0TjpGNDQ0OjRTVDQKCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBd1FhVVRaUFhQZnloZFZVdkJkbXkKZlViYXZYL1pmdkNkMCtGREdNb0ZQazlUTlE1aVZPSkhaUVVNa2N2d2QrdVdaV3dvdWtEUGhZaWxEQTZ6Y3krQQowdERFQkF0Nmc5TGM3UFNXU1BZMTJpbWxnbC85RmJzQnZsSjFRc1RJNGlPUjQ1K0FsMHMxMWhaNG0wR1k4UXQ4CnpFN0RYU1BNUzVRTHlUcHlEemZkQURVcWFGRVcxNTVOQ3BaKzZ6N0lHZCt0V2xjalB3QzQwb3ppbWM1bXVUSWgKb2w1WG1hUFREYk45VzhDWGQ1ZWdUeEExZU43YTA3MWR0R1RialFMUEhvb0QxRURsbitvZjZ2VGFReUphWWJmQgpNRHF2NFdraG9QSzJPWWZ5OXVLR1lTNS9ieHIzUWVTUGRoWVFrQzl2YVZsRUtuTjFZaER6VXZVZGR1c3lyRUdICjd3SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=",
	}
)

// clusterAPI gives us access to the swarm APIs for the licensing library
// The daemon/cluster packaqe can't be imported directly due to circular
// imports so this defines just the set of APIs needed by the licensing
// library to retrieve the swarm config stored license shared by UCP
type clusterAPI interface {
	GetNodes(options types.NodeListOptions) ([]swarm.Node, error)
	GetConfig(input string) (swarm.Config, error)
	GetConfigs(options types.ConfigListOptions) ([]swarm.Config, error)
	CreateConfig(s swarm.ConfigSpec) (string, error)
	UpdateConfig(input string, version uint64, spec swarm.ConfigSpec) error
}

// MirantisLicenseClaims extends the standard JWT claims, adding in private claims
// for licensing details.
type MirantisLicenseClaims struct {
	jwt.Claims
	Legacy struct {
		Dev    bool `json:"dev"`
		Limits struct {
			Clusters          int `json:"clusters"`
			WorkersPerCluster int `json:"workers_per_cluster"`
		} `json:"limits"`
	} `json:"license"`
}

// Human-readable string representation of a license claim.
func (c MirantisLicenseClaims) String() string {
	if c.Expiry == nil {
		return "Invalid license - no valid expiration"
	}

	expiration := c.Expiry.Time()
	expirationString := expiration.Format("2006-01-02")

	now := time.Now()
	if now.After(expiration) {
		return fmt.Sprintf("Expired on %s", expirationString)
	}

	return fmt.Sprintf("Valid until %s", expirationString)
}

// fillEnterpriseLicense populates the product license field(s) in the provided info
// type based on the available licensing.
func (daemon *Daemon) fillEnterpriseLicense(v *types.Info) {
	v.ProductLicense = defaultLicense
	defer updateDockerVersionWithLicense(v)

	// Licenses can only be found on swarm managers.
	if daemon.cluster != nil && !daemon.cluster.IsManager() {
		v.ProductLicense = licensing.ErrWorkerNode.Error()
		return
	}

	// We just want a license -- doesn't matter from where.
	licenseData := loadLicense(
		loadLicenseCluster(daemon.cluster),
		loadLicenseLocal(v.DockerRootDir),
	)

	// No license available implies that the product is 'unlicensed'.
	if licenseData == nil {
		return
	}

	// Attempt as a Mirantis license first, falling back to legacy license processing on failure.
	if err := fillEnterpriseLicenseMirantis(licenseData, v); err != nil {
		logrus.WithError(err).Debug("Mirantis license failure - attempting as legacy")

		if err := fillEnterpriseLicenseLegacy(context.Background(), licenseData, v); err != nil {
			logrus.WithError(err).Error("Legacy license failure")
		}
	}
}

// loadMirantisLicensePublicKey loads a PKIX public key from a PEM slice.
func loadMirantisLicensePublicKey(keyPEM []byte) (interface{}, error) {
	pemBlock, _ := pem.Decode(keyPEM)
	if pemBlock == nil {
		return nil, errors.New("public key not in PEM format")
	}

	key, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse license public key")
	}

	return key, nil
}

// fillEnterpriseLicenseMirantis validates the provided licensing information as
// a JWT, and extracts the license details (JWT claims).  The details of the license
// are populated into the the provided Info type.
func fillEnterpriseLicenseMirantis(licenseData []byte, v *types.Info) error {
	token, err := jwt.ParseSigned(string(licenseData))
	if err != nil {
		return errors.Wrap(err, "failed to parse JWT")
	}

	loadedPublicKey, err := loadMirantisLicensePublicKey([]byte(mirantisLicensePublicKey))
	if err != nil {
		logrus.WithError(err).Error("Unable to parse static Mirantis public key")
	}

	// The Mirantis JWT claims are private alongside the standard/registered claims.
	claims := MirantisLicenseClaims{}
	if err := token.Claims(loadedPublicKey, &claims); err != nil {
		return errors.Wrap(err, "unable to process JWT license claims")
	}

	// NOTE: There is no enforcement of claims to runtime operation yet.  Only basic
	// license information is provided.

	v.ProductLicense = claims.String()

	return nil
}

// fillEnterpriseLicenseLegacy parses and validates licensing data according
// to the `docker/licensing` client library.  This functionality is considered
// 'legacy' and will be deprecated with the move towards Mirantis-JWT license
// support.
func fillEnterpriseLicenseLegacy(ctx context.Context, licenseData []byte, v *types.Info) error {
	baseURI, err := url.Parse(licensingDefaultBaseURI)
	if err != nil {
		return errors.Wrap(err, "failed to setup legacy licensing URL")
	}

	lclient, err := licensing.New(&licensing.Config{
		BaseURI:    *baseURI,
		HTTPClient: &http.Client{},
		PublicKeys: legacyLicensingPublicKeys,
	})
	if err != nil {
		return errors.Wrap(err, "failed to create legacy licensing client")
	}

	parsedLicense, err := lclient.ParseLicense(licenseData)
	if err != nil {
		return errors.Wrap(err, "unable to parse legacy license")
	}

	checkResponse, err := lclient.VerifyLicense(ctx, *parsedLicense)
	if err != nil {
		return errors.Wrap(err, "unable to verify legacy license")
	}

	v.ProductLicense = checkResponseToSubscription(checkResponse, parsedLicense.KeyID).String()

	return nil
}

// updateDockerVersionWithLicense updates the variables in the dockerversion package with
// details from licensing.
func updateDockerVersionWithLicense(v *types.Info) {
	dockerversion.PlatformName = fmt.Sprintf("%s (%s)", dockerversion.DefaultPlatformName, v.ProductLicense)
}

func checkResponseToSubscription(checkResponse *model.CheckResponse, keyID string) *model.Subscription {

	// TODO - this translation still needs some work
	// Primary missing piece is how to distinguish from basic, vs std/advanced
	var productID string
	var ratePlan string
	var state string
	switch strings.ToLower(checkResponse.Tier) {
	case "internal":
		productID = "docker-ee-trial"
		ratePlan = "free-trial"
	case "production":
		productID = "docker-ee"
		if checkResponse.ScanningEnabled {
			ratePlan = "nfr-advanced"
		} else {
			ratePlan = "nfr-standard"
		}
	}

	// Determine if the license has already expired
	if checkResponse.Expiration.Before(time.Now()) {
		state = "expired"
	} else {
		state = "active"
	}

	// Translate the legacy structure into the new Subscription fields
	return &model.Subscription{
		// Name
		ID: keyID, // This is not actually the same, but is unique
		// DockerID
		ProductID:       productID,
		ProductRatePlan: ratePlan,
		// ProductRatePlanID
		// Start
		Expires: &checkResponse.Expiration,
		State:   state,
		// Eusa
		PricingComponents: model.PricingComponents{
			{
				Name:  "Nodes",
				Value: checkResponse.MaxEngines,
			},
		},
	}
}

// getLatestNamedConfig looks for versioned instances of configs with the
// given name prefix which have a `-NUM` integer version suffix. Returns the
// config with the highest version number found or nil if no such configs exist
// along with its version number.
func getLatestNamedConfig(capi clusterAPI, namePrefix string) (int, error) {
	latestVersion := -1
	// List any/all existing configs so that we create a newer version than
	// any that already exist.
	filter := filters.NewArgs()
	filter.Add("name", namePrefix)
	existingConfigs, err := capi.GetConfigs(types.ConfigListOptions{Filters: filter})
	if err != nil {
		return latestVersion, errors.Wrap(err, "unable to list existing configs")
	}

	for _, existingConfig := range existingConfigs {
		existingConfigName := existingConfig.Spec.Name
		nameSuffix := strings.TrimPrefix(existingConfigName, namePrefix)
		if nameSuffix == "" || nameSuffix[0] != '-' {
			continue // No version specifier?
		}

		versionSuffix := nameSuffix[1:] // Trim the version separator.
		existingVersion, err := strconv.Atoi(versionSuffix)
		if err != nil {
			continue // Unable to parse version as integer.
		}
		if existingVersion > latestVersion {
			latestVersion = existingVersion
		}
	}

	return latestVersion, nil
}

// licenseLoader defines the loading of license bytes
type licenseLoader func() ([]byte, error)

// loadLicense will attempt to load a license from the collection of provided
// license loaders.  Any errors occurring during loading are logged, and processing
// continues to the next loader.  Processing ends when a license loader returns
// license bytes.
func loadLicense(loaders ...licenseLoader) []byte {
	for _, loader := range loaders {
		licenseData, err := loader()
		if licenseData != nil {
			return licenseData
		}

		if err != nil {
			logrus.WithError(err).Warn("Unable to load license")
		}
	}

	return nil
}

// loadLicenseCluster asserts various preconditions against the cluster/swarm prior to querying
// the cluster API for a license.
func loadLicenseCluster(c Cluster) licenseLoader {
	return func() ([]byte, error) {
		if c == nil {
			return nil, errors.New("unable to lookup licensing details without a daemon.cluster")
		}

		capi, ok := c.(clusterAPI)
		if !ok {
			return nil, errors.New("daemon.cluster type cast failure during license lookup")
		}

		// Load the latest license index
		latestVersion, err := getLatestNamedConfig(capi, licenseNamePrefix)
		if err != nil {
			return nil, errors.Wrap(err, "unable to get latest license version")
		}

		if latestVersion >= 0 {
			cfg, err := capi.GetConfig(fmt.Sprintf("%s-%d", licenseNamePrefix, latestVersion))
			if err != nil {
				return nil, errors.Wrap(err, "unable to load license from swarm config")
			}

			return cfg.Spec.Data, nil
		}

		return nil, nil
	}
}

// loadLicenseLocal loads a license from a filesystem path.
func loadLicenseLocal(licensePath string) licenseLoader {
	return func() ([]byte, error) {
		data, err := ioutil.ReadFile(filepath.Join(licensePath, licenseFilename))
		if err != nil {
			// The license file not existing is not something we need to error about - the
			// lack of a license is enough.
			if os.IsNotExist(err) {
				return nil, nil
			}

			return nil, err
		}

		return data, nil
	}
}
