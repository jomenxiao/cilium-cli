// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tests

import (
	"context"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/filters"
)

type PodToExternalWorkload struct{}

func (t *PodToExternalWorkload) Name() string {
	return "pod-to-external-workload"
}

func (t *PodToExternalWorkload) Run(ctx context.Context, c check.TestContext) {
	for _, client := range c.ClientPods() {
		for _, ew := range c.ExternalWorkloads() {
			ewIP := ew.ExternalWorkload.Status.IP
			cmd := []string{"ping", "-c", "3", ewIP}
			run := check.NewTestRun(t.Name(), c, client, check.NetworkEndpointContext{Peer: ewIP})

			_, err := client.K8sClient.ExecInPod(ctx, client.Pod.Namespace, client.Pod.Name, check.ClientDeploymentName, cmd)
			if err != nil {
				run.Failure("ping command failed: %s", err)
			}

			run.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, []filters.Pair{
				{Filter: filters.Drop(), Expect: false, Msg: "Found drop"},
				{Filter: filters.And(filters.IP(client.Pod.Status.PodIP, ewIP), filters.ICMP(8)), Expect: true, Msg: "ICMP request"},
				{Filter: filters.And(filters.IP(ewIP, client.Pod.Status.PodIP), filters.ICMP(0)), Expect: true, Msg: "ICMP response"},
			})

			run.End()
		}
	}
}
