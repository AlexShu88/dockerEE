package telemetry

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/dockerversion"
	"github.com/segmentio/analytics-go"
	"github.com/sirupsen/logrus"
)

var (
	pollPeriod = 24 * time.Hour

	// segmentToken is the API token we use for Segment.
	// The token set here is the staging-token, but will be replaced with the
	// production token at compile time using an -X compile flag, e.g.:
	// -ldflags "-X \"daemon.telemetry.segmentToken=<my-token>\""
	segmentToken = "MEMutJjWBF0qNOqd6pqTuDPvL07ZbHT1" // #nosec G101
)

// Telemetry is a handle to the telemetry sender
type Telemetry struct {
	ctx    context.Context
	cancel context.CancelFunc
	s      sysInfo
	client segmentClient
	ticker *time.Ticker
}

type segmentClient interface {
	Identify(*analytics.Identify) error
}

type sysInfo interface {
	SystemInfo() *types.Info
}

// Start will start sending telementry if not disabled
// Caller should call Stop on the returned object
func Start(ctx context.Context, s sysInfo) *Telemetry {
	ctx, cancel := context.WithCancel(ctx)
	client := analytics.New(segmentToken)
	t := &Telemetry{
		ctx:    ctx,
		cancel: cancel,
		s:      s,
		client: client,
		ticker: time.NewTicker(pollPeriod),
	}
	t.start()
	return t
}

func (t *Telemetry) start() {
	logrus.Debug("Docker daemon will send anonymous usage telemetry")
	go func() {
		for {
			select {
			case <-t.ctx.Done():
				return
			case <-t.ticker.C:
				t.send()
			}
		}
	}()
}

// Stop shuts down sending telemetry data
func (t *Telemetry) Stop() {
	t.cancel()
	t.ticker.Stop()
}

func (t *Telemetry) send() {
	info := t.s.SystemInfo()
	traits := map[string]interface{}{
		"architecture":    info.Architecture,
		"commit":          dockerversion.GitCommit,
		"edition_type":    "ee",
		"graphdriver":     info.Driver,
		"kernel":          info.KernelVersion,
		"os":              info.OperatingSystem,
		"os_type":         info.OSType,
		"version":         dockerversion.Version,
		"is_experimental": info.ExperimentalBuild,
		"isolation":       info.Isolation,
		"live_restore":    info.LiveRestoreEnabled,
	}
	identity := &analytics.Identify{
		AnonymousId: fmt.Sprintf("%x", sha256.Sum256([]byte(info.ID))),
		Traits:      traits,
	}
	t.client.Identify(identity)
}
