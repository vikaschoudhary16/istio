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

package xds

import (
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoytls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	credscontroller "istio.io/istio/pilot/pkg/credentials"
	"istio.io/istio/pilot/pkg/util/protoconv"
)

func (s *SecretGen) mayBeGetEnvoyGenericSecret(secretController credscontroller.Controller, sr SecretResource) *discovery.Resource {
	value, err := secretController.GetIstioGenericSecretValue(sr.Name, sr.Namespace)
	if err != nil {
		log.Warnf("mayBeGetEnvoyGenericSecret failed to fetch value for %s: %v", sr.ResourceName, err)
		return nil
	}
	return toEnvoyGenericSecret(sr.ResourceName, value)
}

func toEnvoyGenericSecret(name string, value []byte) *discovery.Resource {
	res := protoconv.MessageToAny(&envoytls.Secret{
		Name: name,
		Type: &envoytls.Secret_GenericSecret{
			GenericSecret: &envoytls.GenericSecret{
				Secret: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: value,
					},
				},
			},
		},
	})
	return &discovery.Resource{
		Name:     name,
		Resource: res,
	}
}
