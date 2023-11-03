// Copyright Istio Authors
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

package kube

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"istio.io/istio/pkg/cluster"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/multicluster"
	"istio.io/istio/pkg/test"
)

var (
	genericSecret = makeSecret("generic", map[string]string{
		DefaultIstioGenericSecretKey: "my_generic_secret_value",
	}, corev1.SecretTypeOpaque)
	emptyGenericSecret = makeSecret("generic-empty", map[string]string{
		DefaultIstioGenericSecretKey: "",
	}, corev1.SecretTypeOpaque)
	genericSecretWrongKey = makeSecret("generic-wrong-key", map[string]string{
		"some_wrong_key": "my_generic_secret_value",
	}, corev1.SecretTypeOpaque)
)

func TestGenericSecretController(t *testing.T) {
	secrets := []runtime.Object{
		genericSecret,
		emptyGenericSecret,
		genericSecretWrongKey,
	}
	client := kube.NewFakeClient(secrets...)
	sc := NewCredentialsController(client)
	client.RunAndWait(test.NewStop(t))

	testCases := []struct {
		name        string
		namespace   string
		key         string
		value       string
		expectError bool
	}{
		{
			name:        "generic",
			namespace:   "default",
			value:       "my_generic_secret_value",
			expectError: false,
		},
		{
			name:        "generic-empty",
			namespace:   "default",
			value:       "",
			expectError: true,
		},
		{
			name:        "generic-wrong-key",
			namespace:   "default",
			value:       "",
			expectError: true,
		},
		{
			name:        "secret-not-found",
			namespace:   "default",
			value:       "",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			value, err := sc.GetIstioGenericSecretValue(tc.name, tc.namespace)
			if err != nil {
				if !tc.expectError {
					t.Fatalf("error occurred: %v", err)
				}
			} else if tc.expectError {
				t.Fatalf("expected error to have occurred, but it did not")
			}

			if !tc.expectError && tc.value != string(value) {
				t.Fatalf("secret value does not match, got %q, expected %q", value, tc.value)
			}
		})
	}
}

func TestGenericSecretsControllerMulticluster(t *testing.T) {
	secretsLocal := []runtime.Object{
		genericSecret,
	}

	genericSecretRemote := makeSecret("generic-remote", map[string]string{
		DefaultIstioGenericSecretKey: "my_generic_secret_value_remote",
	}, corev1.SecretTypeOpaque)
	secretsRemote := []runtime.Object{
		genericSecretRemote,
	}

	localClient := kube.NewFakeClient(secretsLocal...)
	remoteClient := kube.NewFakeClient(secretsRemote...)
	otherRemoteClient := kube.NewFakeClient()
	sc := NewMulticluster("local")
	sc.ClusterAdded(&multicluster.Cluster{ID: "local", Client: localClient}, nil)
	sc.ClusterAdded(&multicluster.Cluster{ID: "remote", Client: remoteClient}, nil)
	sc.ClusterAdded(&multicluster.Cluster{ID: "other", Client: otherRemoteClient}, nil)

	// normally the remote secrets controller would start these
	localClient.RunAndWait(test.NewStop(t))
	remoteClient.RunAndWait(test.NewStop(t))
	otherRemoteClient.RunAndWait(test.NewStop(t))

	cases := []struct {
		name      string
		namespace string
		cluster   cluster.ID
		value     string
	}{
		// From local cluster
		// These are only in remote cluster, we do not have access
		{"generic-remote", "default", "local", ""},
		// These are in local cluster, we can access
		{"generic", "default", "local", "my_generic_secret_value"},

		// From remote cluster
		// We can access all credentials - local and remote
		{"generic", "default", "remote", "my_generic_secret_value"},
		{"generic-remote", "default", "remote", "my_generic_secret_value_remote"},

		// From other remote cluster
		// We have no in cluster credentials; can only access those in config cluster
		{"generic", "default", "other", "my_generic_secret_value"},
		{"generic-remote", "default", "other", ""},
	}
	for _, tt := range cases {
		t.Run(fmt.Sprintf("%s-%v", tt.name, tt.cluster), func(t *testing.T) {
			con, err := sc.ForCluster(tt.cluster)
			if err != nil {
				t.Fatal(err)
			}
			value, _ := con.GetIstioGenericSecretValue(tt.name, tt.namespace)
			if tt.value != string(value) {
				t.Fatalf("got %q, wanted %q", string(value), tt.value)
			}
		})
	}
}
