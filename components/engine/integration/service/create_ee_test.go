package service // import "github.com/docker/docker/integration/service"

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	swarmtypes "github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/integration/internal/network"
	"github.com/docker/docker/integration/internal/swarm"
	"github.com/docker/docker/testutil/fixtures/load"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/poll"
)

func TestServiceCreateTrustPinning(t *testing.T) {
	defer setupTest(t)()

	testCases := []struct {
		desc              string
		daemonConfig      string
		expectedSuccess   bool
		goodTrustMetadata bool
	}{
		{
			desc: "enforced with valid key",
			daemonConfig: `{
					"content-trust": {
						"trust-pinning": {
							"official-library-images":false,
							"root-keys": {
								"*":["70eb123c834fd4d2a591fc9a50f4a6d26598fb64a2f37a845296ebbcceae5e24"]
							}
						},
						"mode":"enforced",
						"allow-expired-cached-trust-data": true
					}
				}`,
			expectedSuccess:   true,
			goodTrustMetadata: true,
		},
		{
			desc: "permissive mode",
			daemonConfig: `{
					"content-trust": {
						"trust-pinning": {
							"official-library-images":false,
							"root-keys": {
								"*":["abcd"]
							}
						},
						"mode":"permissive",
						"allow-expired-cached-trust-data": false
					}
				}`,
			expectedSuccess:   true,
			goodTrustMetadata: false,
		},
		{
			desc: "invalid trustdata",
			daemonConfig: `{
					"content-trust": {
						"trust-pinning": {
							"official-library-images":false,
							"root-keys": {
								"*":["abcd"]
							}
						},
						"mode":"enforced",
						"allow-expired-cached-trust-data": true
					}
				}`,
			expectedSuccess:   false,
			goodTrustMetadata: false,
		},
		{
			desc: "expired data",
			daemonConfig: `{
					"content-trust": {
						"trust-pinning": {
							"official-library-images":false,
							"root-keys": {
								"*":["70eb123c834fd4d2a591fc9a50f4a6d26598fb64a2f37a845296ebbcceae5e24"]
							}
						},
						"mode":"enforced",
						"allow-expired-cached-trust-data": false
					}
				}`,
			expectedSuccess:   false,
			goodTrustMetadata: true,
		},
	}

	d := swarm.NewSwarm(t, testEnv)
	client := d.NewClientT(t)

	defer d.Stop(t)
	defer client.Close()

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			configFile, err := load.WriteConfig(tc.daemonConfig)
			assert.NilError(t, err)

			d.Stop(t)
			d.StartWithBusybox(t, "--iptables=false")

			err = load.FrozenTrustImagesLinux(client, tc.goodTrustMetadata)
			assert.NilError(t, err)

			d.Stop(t)
			d.StartWithBusybox(t, "--iptables=false", "--config-file", configFile)

			var spec swarmtypes.ServiceSpec
			swarm.ServiceWithImage("dockertrusttest.docker.io/library/busybox:latest")(&spec)
			swarm.ServiceWithCommand([]string{"/bin/top"})(&spec)
			swarm.ServiceWithReplicas(1)(&spec)
			resp, err := client.ServiceCreate(context.Background(), spec, types.ServiceCreateOptions{})
			assert.NilError(t, err)
			if tc.expectedSuccess {
				poll.WaitOn(t, swarm.RunningTasksCount(client, resp.ID, 1), swarm.ServicePoll)
				i := inspectServiceContainer(t, client, resp.ID)
				// HostConfig.Init == nil means that it delegates to daemon configuration
				assert.Check(t, i.HostConfig.Init == nil)
			} else {
				time.Sleep(time.Second * 5)
				t.Helper()
				filter := filters.NewArgs()
				filter.Add("label", fmt.Sprintf("com.docker.swarm.service.id=%s", resp.ID))
				containers, err := client.ContainerList(context.Background(), types.ContainerListOptions{Filters: filter})
				assert.NilError(t, err)
				assert.Equal(t, len(containers), 0, "Container should not be running")
			}
			err = client.ServiceRemove(context.Background(), resp.ID)
			assert.NilError(t, err)
			poll.WaitOn(t, network.IsRemoved(context.Background(), client, resp.ID), swarm.ServicePoll)
		})
	}
}
