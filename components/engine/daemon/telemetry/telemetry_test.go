package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/dockerversion"
	"github.com/segmentio/analytics-go"
	"gotest.tools/v3/assert"
)

type testClient struct {
	segmentCB func(*analytics.Identify) error
	sysInfoCB func() *types.Info
}

func (c *testClient) Identify(identify *analytics.Identify) error {
	return c.segmentCB(identify)
}
func (c *testClient) SystemInfo() *types.Info {
	return c.sysInfoCB()
}

func TestTelemetryHappyPath(t *testing.T) {
	pollPeriod = 5 * time.Millisecond
	ticker := time.NewTicker(pollPeriod)
	info := &types.Info{
		Architecture:       "architecture",
		Driver:             "driver",
		KernelVersion:      "kernel version",
		OperatingSystem:    "operating system",
		OSType:             "os type",
		ExperimentalBuild:  true,
		Isolation:          "isolation",
		LiveRestoreEnabled: true,
	}
	expected := map[string]interface{}{
		"architecture":    info.Architecture,
		"graphdriver":     info.Driver,
		"kernel":          info.KernelVersion,
		"os":              info.OperatingSystem,
		"os_type":         info.OSType,
		"is_experimental": info.ExperimentalBuild,
		"isolation":       info.Isolation,
		"live_restore":    info.LiveRestoreEnabled,
		"version":         dockerversion.Version,
		"commit":          dockerversion.GitCommit,
		"edition_type":    "ee",
	}
	var actual map[string]interface{}

	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan struct{})
	tel := &Telemetry{
		ctx:    ctx,
		cancel: cancel,
		ticker: ticker,
	}
	tc := &testClient{
		segmentCB: func(identify *analytics.Identify) error {
			tel.Stop()
			actual = identify.Traits
			close(doneCh)
			return nil
		},
		sysInfoCB: func() *types.Info {
			return info
		},
	}
	tel.s = tc
	tel.client = tc
	tel.start()
	select {
	case <-ctx.Done():
	case <-doneCh:
	}
	assert.DeepEqual(t, actual, expected)
}
