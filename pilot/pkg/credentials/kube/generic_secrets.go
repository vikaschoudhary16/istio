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

	v1 "k8s.io/api/core/v1"
)

const (
	DefaultIstioGenericSecretKey = "istio_generic_secret"
)

func (a *AggregateController) GetIstioGenericSecretValue(name, namespace string) (value []byte, err error) {
	// Search through all clusters, find first non-empty result
	var firstError error
	for _, c := range a.controllers {
		val, err := c.GetIstioGenericSecretValue(name, namespace)
		if err != nil {
			if firstError == nil {
				firstError = err
			}
		} else {
			return val, nil
		}
	}
	return nil, firstError
}

func (s *CredentialsController) GetIstioGenericSecretValue(name, namespace string) (value []byte, err error) {
	k8sSecret := s.secrets.Get(name, namespace)
	if k8sSecret == nil {
		return nil, fmt.Errorf("secret %v/%v not found", namespace, name)
	}

	return extractGenericSecretValue(k8sSecret)
}

// extractGenericSecretValue tries to get the value set for `istio_generic_secret` key in the secret.
func extractGenericSecretValue(scrt *v1.Secret) (value []byte, err error) {
	// For example:
	// ---
	// apiVersion: v1
	// data:
	//   istio_generic_secret: e2Jhc2U2NF9lbmNcDvZGVkX3Rva2VuX3sdfgfdldH0=
	// kind: Secret
	// metadata:
	//   name: bar
	//   namespace: foo
	// type: Opaque
	//
	value, found := scrt.Data[DefaultIstioGenericSecretKey]
	if !found {
		return nil, fmt.Errorf("found secret, but didn't have the expected key (%s); found: %s",
			DefaultIstioGenericSecretKey, truncatedKeysMessage(scrt.Data))
	}
	if len(value) > 0 {
		return value, nil
	}

	return nil, fmt.Errorf("found key %q but it was empty", DefaultIstioGenericSecretKey)
}
