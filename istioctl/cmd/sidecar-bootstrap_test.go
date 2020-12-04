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

package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/gomega"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kube "k8s.io/client-go/kubernetes"
	kubeFake "k8s.io/client-go/kubernetes/fake"
	kubeTesting "k8s.io/client-go/testing"

	clientnetworking "istio.io/client-go/pkg/apis/networking/v1alpha3"
	istioclient "istio.io/client-go/pkg/clientset/versioned"

	networking "istio.io/api/networking/v1alpha3"
)

type vmBootstrapTestcase struct {
	args              []string
	cannedIstioConfig []clientnetworking.WorkloadEntry
	cannedK8sConfig   []runtime.Object
	expectedString    string
	shouldFail        bool
}

var (
	emptyIstioConfig = make([]clientnetworking.WorkloadEntry, 0)
	emptyK8sConfig   = make([]runtime.Object, 0)

	istioStaticWorkspace = []clientnetworking.WorkloadEntry{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "workload",
				Namespace: "NS",
			},
			Spec: networking.WorkloadEntry{
				Address:        "127.0.0.1",
				ServiceAccount: "test",
			},
		},
	}

	// see `samples/certs` in the root of the repo
	caCert = `-----BEGIN CERTIFICATE-----
MIIDnzCCAoegAwIBAgIJAON1ifrBZ2/BMA0GCSqGSIb3DQEBCwUAMIGLMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJU3Vubnl2YWxl
MQ4wDAYDVQQKDAVJc3RpbzENMAsGA1UECwwEVGVzdDEQMA4GA1UEAwwHUm9vdCBD
QTEiMCAGCSqGSIb3DQEJARYTdGVzdHJvb3RjYUBpc3Rpby5pbzAgFw0xODAxMjQx
OTE1NTFaGA8yMTE3MTIzMTE5MTU1MVowWTELMAkGA1UEBhMCVVMxEzARBgNVBAgT
CkNhbGlmb3JuaWExEjAQBgNVBAcTCVN1bm55dmFsZTEOMAwGA1UEChMFSXN0aW8x
ETAPBgNVBAMTCElzdGlvIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAyzCxr/xu0zy5rVBiso9ffgl00bRKvB/HF4AX9/ytmZ6Hqsy13XIQk8/u/By9
iCvVwXIMvyT0CbiJq/aPEj5mJUy0lzbrUs13oneXqrPXf7ir3HzdRw+SBhXlsh9z
APZJXcF93DJU3GabPKwBvGJ0IVMJPIFCuDIPwW4kFAI7R/8A5LSdPrFx6EyMXl7K
M8jekC0y9DnTj83/fY72WcWX7YTpgZeBHAeeQOPTZ2KYbFal2gLsar69PgFS0Tom
ESO9M14Yit7mzB1WDK2z9g3r+zLxENdJ5JG/ZskKe+TO4Diqi5OJt/h8yspS1ck8
LJtCole9919umByg5oruflqIlQIDAQABozUwMzALBgNVHQ8EBAMCAgQwDAYDVR0T
BAUwAwEB/zAWBgNVHREEDzANggtjYS5pc3Rpby5pbzANBgkqhkiG9w0BAQsFAAOC
AQEAltHEhhyAsve4K4bLgBXtHwWzo6SpFzdAfXpLShpOJNtQNERb3qg6iUGQdY+w
A2BpmSkKr3Rw/6ClP5+cCG7fGocPaZh+c+4Nxm9suMuZBZCtNOeYOMIfvCPcCS+8
PQ/0hC4/0J3WJKzGBssaaMufJxzgFPPtDJ998kY8rlROghdSaVt423/jXIAYnP3Y
05n8TGERBj7TLdtIVbtUIx3JHAo3PWJywA6mEDovFMJhJERp9sDHIr1BbhXK1TFN
Z6HNH6gInkSSMtvC4Ptejb749PTaePRPF7ID//eq/3AH8UK50F3TQcLjEqWUsJUn
aFKltOc+RAjzDklcUPeG4Y6eMA==
-----END CERTIFICATE-----`

	baseTempdir, _ = ioutil.TempDir("", "vm_bootstrap_test_dir")

	fullK8sConfig = []runtime.Object{
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "istio-system",
			},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "istio-ca-root-cert",
				Namespace: "istio-system",
			},
			Data: map[string]string{
				"root-cert.pem": caCert,
			},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "istio",
				Namespace: "istio-system",
			},
			Data: map[string]string{
				"mesh":         "",
				"meshNetworks": "networks: {}",
			},
		},
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "istio-sidecar-injector",
				Namespace: "istio-system",
			},
			Data: map[string]string{
				"values": `{
				  "global": {
					"jwtPolicy": "third-party-jwt",
					"pilotCertProvider": "istiod"
				  }
				}`,
			},
		},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "default",
				Namespace: "istio-system",
			},
			Secrets: []corev1.ObjectReference{{
				Name: "default-token-6n2ql",
			}},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "default-token-6n2ql",
				Namespace: "istio-system",
			},
			Type: "kubernetes.io/service-account-token",
			Data: map[string][]byte{
				"ca.crt": []byte(base64.StdEncoding.EncodeToString([]byte(
					`-----BEGIN CERTIFICATE-----
MIICyDCCAbCgAwIBAgIBADANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwprdWJl
cm5ldGVzMB4XDTIwMTAyMjE1NTM1MVoXDTMwMTAyMDE1NTM1MVowFTETMBEGA1UE
AxMKa3ViZXJuZXRlczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALHj
8lB2a7cGe7DWdfUzVlxDYTN63UahoeJIOtqiMn4a9yXJJFUwedlRRiv+GDHVNJ4I
NSrhaH13dOGZWL6DRQRXBOPSEUZ/TJjXFPtS5y1Cxd6nAgPCa1I+eyFGU8e9pss9
/6uo7PyLx6zqcQDawtqZte90nJyYjsYuMTvRzMFbAAwBt1OTrNF2PboCEuuj3dTn
29ggev5mj8JOzHYOjWASAj/zqm706AwWv0y50IfNKR0j5t+fYI+1kj5Qfy09BuP5
kCHq9YT8LT4PddE05ztaTkSW2DSHIHt3aEdsvczD6VU633tDn5dQ64RCAZKnQAEB
1FZ3xHUppH9RuQyYyLkCAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgKkMA8GA1UdEwEB
/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAAllw6xJeu1+tp2m8NgPJuxpBvAf
Xo//ySR69jlDQxmCIafR/0lWMkzPDQy8gv+INhpeOK99gooEU/qC9pjs1m53MzmQ
kM3Ru/GM1uqMnUmTuwLptxFJxDjSKcmXcYn63k1BdriExs3Wl2IiFDHjUdfGaUo0
twjnHmtommvAAbMeGyMSoM1Wd8mIzJO9Bk0d5l4wEZeA4corbAIDyoAhM3pyNrxL
yFkHk8ul+CzDoZSdfQulovH/T0GShzE6WFVO7LzOVQwylI1qYMoV20/8e4cO/L0K
ewSti8ZCFKFSQcfSMCjKDzPB5mnXiec9m+qtnv+cNS7nZ8EmGYMsffP1rx4=
-----END CERTIFICATE-----`))),
			},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "istio-ingressgateway",
				Namespace: "istio-system",
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{Name: "tcp-istiod", Port: 15012},
					{Name: "tls", Port: 15443},
				},
			},
			Status: corev1.ServiceStatus{
				LoadBalancer: corev1.LoadBalancerStatus{
					Ingress: []corev1.LoadBalancerIngress{
						{Hostname: "x.y.z"},
						{IP: "1.2.3.4"},
					},
				},
			},
		},
	}
)

func TestVmBootstrap(t *testing.T) {
	cases := []vmBootstrapTestcase{
		// No all flag, or no workload entry.
		{
			args:              strings.Split("x sidecar-bootstrap", " "),
			cannedIstioConfig: emptyIstioConfig,
			cannedK8sConfig:   emptyK8sConfig,
			expectedString:    "sidecar-bootstrap command requires either a <workload-entry-name>[.<namespace>] argument or the --all flag",
			shouldFail:        true,
		},
		// Workload Entry + all flag
		{
			args:              strings.Split("x sidecar-bootstrap --all workload.NS", " "),
			cannedIstioConfig: emptyIstioConfig,
			cannedK8sConfig:   emptyK8sConfig,
			expectedString:    "sidecar-bootstrap command requires either a <workload-entry-name>[.<namespace>] argument or the --all flag but not both",
			shouldFail:        true,
		},
		// unknown workload entry, okay to have fake dumpDir here.
		{
			args:              strings.Split("x sidecar-bootstrap workload.fakeNS --local-dir /tmp/", " "),
			cannedIstioConfig: istioStaticWorkspace,
			cannedK8sConfig:   emptyK8sConfig,
			expectedString: `unable to find WorkloadEntry(s): failed to fetch WorkloadEntry ` +
				`kubernetes://apis/networking.istio.io/v1beta1/namespaces/fakeNS/workloadentries/workload: ` +
				`workloadentries.networking.istio.io "workload" not found`,
			shouldFail: true,
		},
		// known workload entry, known secret
		{
			args:              strings.Split("x sidecar-bootstrap workload.NS --local-dir "+path.Join(baseTempdir, "derived_output"), " "),
			cannedIstioConfig: istioStaticWorkspace,
			cannedK8sConfig:   fullK8sConfig,
			expectedString:    "",
			shouldFail:        false,
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case %d %s", i, strings.Join(c.args, " ")), func(t *testing.T) {
			verifyVMCommandCaseOutput(t, c)
		})
	}
}

func verifyVMCommandCaseOutput(t *testing.T, c vmBootstrapTestcase) {
	t.Helper()

	backupInterfaceFactory := interfaceFactory
	defer func() {
		interfaceFactory = backupInterfaceFactory
	}()

	configStoreFactory = mockClientFactoryGenerator(func(client istioclient.Interface) {
		for _, cfg := range c.cannedIstioConfig {
			_, err := client.NetworkingV1alpha3().WorkloadEntries(cfg.Namespace).Create(context.TODO(), &cfg, metav1.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}
		}
	})
	interfaceFactory = FakeKubeInterfaceGeneratorFunc(mockInterfaceFactoryGenerator(c.cannedK8sConfig)).
		Configure(func(clientset *kubeFake.Clientset) {
			clientset.PrependReactor("create", "serviceaccounts", func(action kubeTesting.Action) (handled bool, ret runtime.Object, err error) {
				if action.GetSubresource() == "token" {
					createAction := action.(kubeTesting.CreateAction)
					tokenRequest := createAction.GetObject().(*authenticationv1.TokenRequest)
					tokenRequest.Status.Token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" // nolint: lll
					tokenRequest.Status.ExpirationTimestamp = metav1.Date(2020, time.October, 16, 19, 50, 37, 123, time.UTC)
					return true, tokenRequest, nil
				}
				return false, nil, nil
			})
		})

	var out bytes.Buffer
	rootCmd := GetRootCmd(c.args)
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)

	fErr := rootCmd.Execute()
	output := out.String()

	if c.expectedString != "" && !strings.Contains(output, c.expectedString) {
		t.Fatalf("Output didn't match for 'istioctl %s'\n got %v\nwant: %v", strings.Join(c.args, " "), output, c.expectedString)
	}

	if c.shouldFail {
		if fErr == nil {
			t.Fatalf("Command should have failed for 'istioctl %s', didn't get one, output was %q",
				strings.Join(c.args, " "), output)
		}
	} else {
		if fErr != nil {
			t.Fatalf("Command should not have failed for 'istioctl %s': %v", strings.Join(c.args, " "), fErr)
		}
	}
}

type FakeKubeInterfaceGeneratorFunc func(kubeconfig string) (kube.Interface, error)

func (f FakeKubeInterfaceGeneratorFunc) Configure(fn func(clientset *kubeFake.Clientset)) FakeKubeInterfaceGeneratorFunc {
	return func(kubeconfig string) (kube.Interface, error) {
		clientset, err := f(kubeconfig)
		if err != nil {
			return nil, err
		}
		fn(clientset.(*kubeFake.Clientset))
		return clientset, nil
	}
}

func TestVmBundleCreate(t *testing.T) {
	var bundle BootstrapBundle

	testfunc := func(t *testing.T, remoteDir string) {
		items := processBundle(bundle, remoteDir)

		// Verify that all files should go remote directory
		for _, file := range items.filesToCopy {
			if file.dir != remoteDir {
				t.Fatal("Destination directory in bundle is not set properly")
			}
		}

		// Verify that docker run command contains proper mapping for files.
		filesToTest := []string{"istio-ca.pem", "istio-token", "k8s-ca.pem", "sidecar.env"}
		for _, execCmd := range items.cmdsToExec {
			if strings.Contains(execCmd.cmd, "docker run") {
				// check all files.
				for _, testFile := range filesToTest {
					if !strings.Contains(execCmd.cmd, remoteDir+"/"+testFile) {
						t.Fatalf("docker run command for file %s is not formatted properly: %s", testFile, execCmd.cmd)
					}
				}
			}
		}
	}

	// Now test with real directory
	testfunc(t, "/var/sshtest/dir")

	// and with shell env variable.
	testfunc(t, "$TEST_VM_DIR")

}

func TestVmBootstrap_GetK8sCaCertFromConfigMap(t *testing.T) {
	testCases := []struct {
		name                    string
		k8sConfig               []runtime.Object
		expectedK8sCaCert       []byte
		expectedOpenshiftCaCert []byte
		expectedErr             string
	}{
		{
			name: "Namespace w/o `sidecar-bootstrap.istio.io/k8s-ca-root-cert-configmap` annotation",
			k8sConfig: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "istio-system",
					},
				},
			},
			expectedErr: `k8s Namespace "istio-system" doesn't specify a ConfigMap that would hold root certs of a k8s CA and, ` +
				`if applicable, an OpenShift Service CA`,
		},
		{
			name: "Namespace w/ `sidecar-bootstrap.istio.io/k8s-ca-root-cert-configmap` annotation but no value",
			k8sConfig: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "istio-system",
						Annotations: map[string]string{
							"sidecar-bootstrap.istio.io/k8s-ca-root-cert-configmap": "",
						},
					},
				},
			},
			expectedErr: `k8s Namespace "istio-system" doesn't specify a ConfigMap that would hold root certs of a k8s CA and, ` +
				`if applicable, an OpenShift Service CA`,
		},
		{
			name: "Namespace w/ `sidecar-bootstrap.istio.io/k8s-ca-root-cert-configmap` annotation that points to a non-existing ConfigMap",
			k8sConfig: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "istio-system",
						Annotations: map[string]string{
							"sidecar-bootstrap.istio.io/k8s-ca-root-cert-configmap": "non-existing",
						},
					},
				},
			},
			expectedErr: `failed to read ConfigMap kubernetes://api/v1/namespaces/istio-system/configmaps/non-existing that was referenced to ` +
				`by means of "sidecar-bootstrap.istio.io/mesh-expansion-configmap" annotation on the "istio-system" Namespace: ` +
				`configmaps "non-existing" not found`,
		},
		{
			name: "ConfigMap w/o `ca.crt` key",
			k8sConfig: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "istio-system",
						Annotations: map[string]string{
							"sidecar-bootstrap.istio.io/k8s-ca-root-cert-configmap": "k8s-ca",
						},
					},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "k8s-ca",
						Namespace: "istio-system",
					},
					Data: map[string]string{},
				},
			},
			expectedErr: `ConfigMap kubernetes://api/v1/namespaces/istio-system/configmaps/k8s-ca has no value for a mandatory key "ca.crt"`,
		},
		{
			name: "ConfigMap w/ `ca.crt` key but no value",
			k8sConfig: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "istio-system",
						Annotations: map[string]string{
							"sidecar-bootstrap.istio.io/k8s-ca-root-cert-configmap": "k8s-ca",
						},
					},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "k8s-ca",
						Namespace: "istio-system",
					},
					Data: map[string]string{
						"ca.crt": "",
					},
				},
			},
			expectedErr: `ConfigMap kubernetes://api/v1/namespaces/istio-system/configmaps/k8s-ca has no value for a mandatory key "ca.crt"`,
		},
		{
			name: "ConfigMap w/ `ca.crt` key",
			k8sConfig: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "istio-system",
						Annotations: map[string]string{
							"sidecar-bootstrap.istio.io/k8s-ca-root-cert-configmap": "k8s-ca",
						},
					},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "k8s-ca",
						Namespace: "istio-system",
					},
					Data: map[string]string{
						"ca.crt": "ABCDEFGH",
					},
				},
			},
			expectedK8sCaCert: []byte("ABCDEFGH"),
		},
		{
			name: "ConfigMap w/ `ca.crt` and `service-ca.crt` keys",
			k8sConfig: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "istio-system",
						Annotations: map[string]string{
							"sidecar-bootstrap.istio.io/k8s-ca-root-cert-configmap": "k8s-ca",
						},
					},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "k8s-ca",
						Namespace: "istio-system",
					},
					Data: map[string]string{
						"ca.crt":         "ABCDEFGH",
						"service-ca.crt": "0123456789",
					},
				},
			},
			expectedK8sCaCert:       []byte("ABCDEFGH"),
			expectedOpenshiftCaCert: []byte("0123456789"),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			g := NewGomegaWithT(t)

			kubeClient, err := mockInterfaceFactoryGenerator(testCase.k8sConfig)("fake kube config")
			g.Expect(err).NotTo(HaveOccurred())

			k8sCaCert, openshiftCaCert, err := getK8sCaCertFromConfigMap(kubeClient, "istio-system")
			if testCase.expectedErr != "" {
				g.Expect(err).To(MatchError(testCase.expectedErr))
			} else {
				g.Expect(k8sCaCert).To(Equal(testCase.expectedK8sCaCert))
				g.Expect(openshiftCaCert).To(Equal(testCase.expectedOpenshiftCaCert))
			}
		})
	}
}

func TestVmBootstrap_GetK8sCaCertFromServiceAccountTokenSecret(t *testing.T) {
	testCases := []struct {
		name                    string
		k8sConfig               []runtime.Object
		expectedK8sCaCert       []byte
		expectedOpenshiftCaCert []byte
		expectedErr             string
	}{
		{
			name:      "ServiceAccount doesn't exist",
			k8sConfig: []runtime.Object{},
			expectedErr: `failed to read ServiceAccount kubernetes://api/v1/namespaces/istio-system/serviceaccounts/default: ` +
				`serviceaccounts "default" not found`,
		},
		{
			name: "ServiceAccount w/o secrets",
			k8sConfig: []runtime.Object{
				&corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default",
						Namespace: "istio-system",
					},
					Secrets: []corev1.ObjectReference{},
				},
			},
			expectedErr: `unable to find a Secret with the root cert of a k8s CA in the ServiceAccount ` +
				`kubernetes://api/v1/namespaces/istio-system/serviceaccounts/default`,
		},
		{
			name: "ServiceAccount w/ reference to a non-existing Secret",
			k8sConfig: []runtime.Object{
				&corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default",
						Namespace: "istio-system",
					},
					Secrets: []corev1.ObjectReference{{
						Name: "non-existing",
					}},
				},
			},
			expectedErr: `unable to find a Secret with the root cert of a k8s CA in the ServiceAccount ` +
				`kubernetes://api/v1/namespaces/istio-system/serviceaccounts/default`,
		},
		{
			name: "ServiceAccount w/ reference to a Secret of type other than `kubernetes.io/service-account-token`",
			k8sConfig: []runtime.Object{
				&corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default",
						Namespace: "istio-system",
					},
					Secrets: []corev1.ObjectReference{{
						Name: "wrong-secret-type",
					}},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "wrong-secret-type",
						Namespace: "istio-system",
					},
					Data: map[string][]byte{
						"ca.crt": []byte(`ABCDEFGH`),
					},
				},
			},
			expectedErr: `unable to find a Secret with the root cert of a k8s CA in the ServiceAccount ` +
				`kubernetes://api/v1/namespaces/istio-system/serviceaccounts/default`,
		},
		{
			name: "ServiceAccount w/ reference to a Secret of type `kubernetes.io/service-account-token` but no value for `ca.crt`",
			k8sConfig: []runtime.Object{
				&corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default",
						Namespace: "istio-system",
					},
					Secrets: []corev1.ObjectReference{{
						Name: "default-token-6n2ql",
					}},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name: "default-token-6n2ql",
					},
					Type: "kubernetes.io/service-account-token",
					Data: map[string][]byte{
						"ca.crt": {},
					},
				},
			},
			expectedErr: `unable to find a Secret with the root cert of a k8s CA in the ServiceAccount ` +
				`kubernetes://api/v1/namespaces/istio-system/serviceaccounts/default`,
		},
		{
			name: "ServiceAccount w/ reference to a Secret of type `kubernetes.io/service-account-token` and `ca.crt` key",
			k8sConfig: []runtime.Object{
				&corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default",
						Namespace: "istio-system",
					},
					Secrets: []corev1.ObjectReference{
						{
							Name: "non-existing",
						},
						{
							Name: "default-token-6n2ql",
						},
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default-token-6n2ql",
						Namespace: "istio-system",
					},
					Type: "kubernetes.io/service-account-token",
					Data: map[string][]byte{
						"ca.crt": []byte("ABCDEFGH"),
					},
				},
			},
			expectedK8sCaCert: []byte("ABCDEFGH"),
		},
		{
			name: "ServiceAccount w/ reference to a Secret of type `kubernetes.io/service-account-token` and `ca.crt` key",
			k8sConfig: []runtime.Object{
				&corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default",
						Namespace: "istio-system",
					},
					Secrets: []corev1.ObjectReference{
						{
							Name: "non-existing",
						},
						{
							Name: "default-token-6n2ql",
						},
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default-token-6n2ql",
						Namespace: "istio-system",
					},
					Type: "kubernetes.io/service-account-token",
					Data: map[string][]byte{
						"ca.crt":         []byte("ABCDEFGH"),
						"service-ca.crt": []byte("0123456789"),
					},
				},
			},
			expectedK8sCaCert:       []byte(`ABCDEFGH`),
			expectedOpenshiftCaCert: []byte("0123456789"),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			g := NewGomegaWithT(t)

			kubeClient, err := mockInterfaceFactoryGenerator(testCase.k8sConfig)("fake kube config")
			g.Expect(err).NotTo(HaveOccurred())

			k8sCaCert, openshiftCaCert, err := getK8sCaCertFromServiceAccountTokenSecret(kubeClient, "istio-system")
			if testCase.expectedErr != "" {
				g.Expect(err).To(MatchError(testCase.expectedErr))
			} else {
				g.Expect(k8sCaCert).To(Equal(testCase.expectedK8sCaCert))
				g.Expect(openshiftCaCert).To(Equal(testCase.expectedOpenshiftCaCert))
			}
		})
	}
}

func TestVmBootstrap_GetK8sCaCert(t *testing.T) {
	testCases := []struct {
		name                    string
		k8sConfig               []runtime.Object
		expectedK8sCaCert       []byte
		expectedOpenshiftCaCert []byte
		expectedErr             string
	}{
		{
			name:      "all supported strategies have failed",
			k8sConfig: []runtime.Object{},
			expectedErr: `all supported strategies to find k8s CA certs have failed.
To overcome this, either grant the user permissions to read k8s Secrets in one of the following Namespaces [istio-system bookinfo kube-public],
or create a ConfigMap with the root certs of a k8s CA (and, if applicable, an OpenShift Service CA)
in the "istio-system" Namespace and use "sidecar-bootstrap.istio.io/k8s-ca-root-cert-configmap" annotation
to give this command a hint where to find such a ConfigMap`,
		},
		{
			name: "ConfigMap wins over other strategies",
			k8sConfig: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "istio-system",
						Annotations: map[string]string{
							"sidecar-bootstrap.istio.io/k8s-ca-root-cert-configmap": "k8s-ca",
						},
					},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "k8s-ca",
						Namespace: "istio-system",
					},
					Data: map[string]string{
						"ca.crt":         "configmap.ca.crt",
						"service-ca.crt": "configmap.service-ca.crt",
					},
				},
				&corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default",
						Namespace: "istio-system",
					},
					Secrets: []corev1.ObjectReference{{
						Name: "default-token-6n2ql",
					}},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default-token-6n2ql",
						Namespace: "istio-system",
					},
					Type: "kubernetes.io/service-account-token",
					Data: map[string][]byte{
						"ca.crt":         []byte("secret.istio-system.ca.crt"),
						"service-ca.crt": []byte("secret.istio-system.service-ca.crt"),
					},
				},
			},
			expectedK8sCaCert:       []byte("configmap.ca.crt"),
			expectedOpenshiftCaCert: []byte("configmap.service-ca.crt"),
		},
		{
			name: "`istio-system` Namespace wins over other namespaces",
			k8sConfig: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "istio-system",
						Annotations: map[string]string{
							"sidecar-bootstrap.istio.io/k8s-ca-root-cert-configmap": "k8s-ca",
						},
					},
				},
				&corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default",
						Namespace: "istio-system",
					},
					Secrets: []corev1.ObjectReference{{
						Name: "default-token-6n2ql",
					}},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default-token-6n2ql",
						Namespace: "istio-system",
					},
					Type: "kubernetes.io/service-account-token",
					Data: map[string][]byte{
						"ca.crt":         []byte("secret.istio-system.ca.crt"),
						"service-ca.crt": []byte("secret.istio-system.service-ca.crt"),
					},
				},
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "bookinfo",
					},
				},
				&corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default",
						Namespace: "bookinfo",
					},
					Secrets: []corev1.ObjectReference{{
						Name: "default-token-8l84n",
					}},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default-token-8l84n",
						Namespace: "bookinfo",
					},
					Type: "kubernetes.io/service-account-token",
					Data: map[string][]byte{
						"ca.crt":         []byte("secret.bookinfo.ca.crt"),
						"service-ca.crt": []byte("secret.bookinfo.service-ca.crt"),
					},
				},
			},
			expectedK8sCaCert:       []byte("secret.istio-system.ca.crt"),
			expectedOpenshiftCaCert: []byte("secret.istio-system.service-ca.crt"),
		},
		{
			name: "WorkloadEntry Namespace wins over `kube-public`",
			k8sConfig: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "istio-system",
						Annotations: map[string]string{
							"sidecar-bootstrap.istio.io/k8s-ca-root-cert-configmap": "k8s-ca",
						},
					},
				},
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "bookinfo",
					},
				},
				&corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default",
						Namespace: "bookinfo",
					},
					Secrets: []corev1.ObjectReference{{
						Name: "default-token-8l84n",
					}},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default-token-8l84n",
						Namespace: "bookinfo",
					},
					Type: "kubernetes.io/service-account-token",
					Data: map[string][]byte{
						"ca.crt":         []byte("secret.bookinfo.ca.crt"),
						"service-ca.crt": []byte("secret.bookinfo.service-ca.crt"),
					},
				},
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "kube-public",
					},
				},
				&corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default",
						Namespace: "kube-public",
					},
					Secrets: []corev1.ObjectReference{{
						Name: "default-token-gxfbc",
					}},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default-token-gxfbc",
						Namespace: "kube-public",
					},
					Type: "kubernetes.io/service-account-token",
					Data: map[string][]byte{
						"ca.crt":         []byte("secret.kube-public.ca.crt"),
						"service-ca.crt": []byte("secret.kube-public.service-ca.crt"),
					},
				},
			},
			expectedK8sCaCert:       []byte("secret.bookinfo.ca.crt"),
			expectedOpenshiftCaCert: []byte("secret.bookinfo.service-ca.crt"),
		},
		{
			name: "`kube-public` Namespace is a last resort",
			k8sConfig: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "istio-system",
						Annotations: map[string]string{
							"sidecar-bootstrap.istio.io/k8s-ca-root-cert-configmap": "k8s-ca",
						},
					},
				},
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "kube-public",
					},
				},
				&corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default",
						Namespace: "kube-public",
					},
					Secrets: []corev1.ObjectReference{{
						Name: "default-token-gxfbc",
					}},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "default-token-gxfbc",
						Namespace: "kube-public",
					},
					Type: "kubernetes.io/service-account-token",
					Data: map[string][]byte{
						"ca.crt":         []byte("secret.kube-public.ca.crt"),
						"service-ca.crt": []byte("secret.kube-public.service-ca.crt"),
					},
				},
			},
			expectedK8sCaCert:       []byte("secret.kube-public.ca.crt"),
			expectedOpenshiftCaCert: []byte("secret.kube-public.service-ca.crt"),
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			g := NewGomegaWithT(t)

			kubeClient, err := mockInterfaceFactoryGenerator(testCase.k8sConfig)("fake kube config")
			g.Expect(err).NotTo(HaveOccurred())

			k8sCaCert, openshiftCaCert, err := getK8sCaCert(kubeClient, "bookinfo", "istio-system")
			if testCase.expectedErr != "" {
				g.Expect(err).To(MatchError(testCase.expectedErr))
			} else {
				g.Expect(k8sCaCert).To(Equal(testCase.expectedK8sCaCert))
				g.Expect(openshiftCaCert).To(Equal(testCase.expectedOpenshiftCaCert))
			}
		})
	}
}

func TestVmBootstrap_ProcessBundle(t *testing.T) {
	testCases := []struct {
		name          string
		bundle        BootstrapBundle
		expectedItems bootstrapItems
	}{
		{
			name: "w/o OpenShift Service CA certs",
			bundle: BootstrapBundle{
				/* k8s */
				K8sCaCert: []byte(`k8s CA certs`),
				/* mesh */
				IstioCaCert:                []byte(`Istio CA certs`),
				IstioIngressGatewayAddress: "1.2.3.4",
				/* workload */
				ServiceAccountToken: []byte(`k8s SA token`),
				/* sidecar */
				IstioProxyContainerName: "istio-proxy",
				IstioProxyImage:         "proxyv2:latest",
				IstioProxyArgs:          []string{"proxy", "sidecar"},
				IstioProxyEnvironment:   []byte(`KEY=VALUE`),
				IstioProxyHosts:         []string{"istiod.istio-system.svc", "zipkin.istio-monitoring.svc"},
			},
			expectedItems: bootstrapItems{
				filesToCopy: []fileToCopy{
					{
						name: "sidecar.env",
						dir:  "/etc/istio-proxy",
						perm: os.FileMode(0644),
						data: []byte("KEY=VALUE"),
					},
					{
						name: "k8s-ca.pem",
						dir:  "/etc/istio-proxy",
						perm: os.FileMode(0644),
						data: []byte("k8s CA certs"),
					},
					{
						name: "istio-ca.pem",
						dir:  "/etc/istio-proxy",
						perm: os.FileMode(0644),
						data: []byte("Istio CA certs"),
					},
					{
						name: "istio-token",
						dir:  "/etc/istio-proxy",
						perm: os.FileMode(0640),
						data: []byte("k8s SA token"),
					},
				},
				cmdsToExec: []cmdToExec{
					{
						cmd:      "docker rm --force istio-proxy",
						required: false,
					},
					{
						cmd: "docker run -d --name istio-proxy --restart unless-stopped --network host " +
							"-v /etc/istio-proxy/istio-ca.pem:/var/run/secrets/istio/root-cert.pem " +
							"-v /etc/istio-proxy/istio-token:/var/run/secrets/tokens/istio-token " +
							"-v /etc/istio-proxy/k8s-ca.pem:/var/run/secrets/kubernetes.io/serviceaccount/ca.crt " +
							"--env-file /etc/istio-proxy/sidecar.env " +
							"--add-host istiod.istio-system.svc:1.2.3.4 " +
							"--add-host zipkin.istio-monitoring.svc:1.2.3.4 " +
							"proxyv2:latest " +
							"proxy sidecar",
						required: true,
					},
				},
			},
		},
		{
			name: "w/ OpenShift Service CA certs",
			bundle: BootstrapBundle{
				/* k8s */
				K8sCaCert: []byte(`k8s CA certs`),
				/* OpenShift */
				OpenShiftCaCert: []byte(`OpenShift Service CA certs`),
				/* mesh */
				IstioCaCert:                []byte(`Istio CA certs`),
				IstioIngressGatewayAddress: "1.2.3.4",
				/* workload */
				ServiceAccountToken: []byte(`k8s SA token`),
				/* sidecar */
				IstioProxyContainerName: "istio-proxy",
				IstioProxyImage:         "proxyv2:latest",
				IstioProxyArgs:          []string{"proxy", "sidecar"},
				IstioProxyEnvironment:   []byte(`KEY=VALUE`),
				IstioProxyHosts:         []string{"istiod.istio-system.svc", "zipkin.istio-monitoring.svc"},
			},
			expectedItems: bootstrapItems{
				filesToCopy: []fileToCopy{
					{
						name: "sidecar.env",
						dir:  "/etc/istio-proxy",
						perm: os.FileMode(0644),
						data: []byte("KEY=VALUE"),
					},
					{
						name: "k8s-ca.pem",
						dir:  "/etc/istio-proxy",
						perm: os.FileMode(0644),
						data: []byte("k8s CA certs"),
					},
					{
						name: "istio-ca.pem",
						dir:  "/etc/istio-proxy",
						perm: os.FileMode(0644),
						data: []byte("Istio CA certs"),
					},
					{
						name: "istio-token",
						dir:  "/etc/istio-proxy",
						perm: os.FileMode(0640),
						data: []byte("k8s SA token"),
					},
					{
						name: "openshift-ca.pem",
						dir:  "/etc/istio-proxy",
						perm: os.FileMode(0644),
						data: []byte("OpenShift Service CA certs"),
					},
				},
				cmdsToExec: []cmdToExec{
					{
						cmd:      "docker rm --force istio-proxy",
						required: false,
					},
					{
						cmd: "docker run -d --name istio-proxy --restart unless-stopped --network host " +
							"-v /etc/istio-proxy/istio-ca.pem:/var/run/secrets/istio/root-cert.pem " +
							"-v /etc/istio-proxy/istio-token:/var/run/secrets/tokens/istio-token " +
							"-v /etc/istio-proxy/k8s-ca.pem:/var/run/secrets/kubernetes.io/serviceaccount/ca.crt " +
							"-v /etc/istio-proxy/openshift-ca.pem:/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt " +
							"--env-file /etc/istio-proxy/sidecar.env " +
							"--add-host istiod.istio-system.svc:1.2.3.4 " +
							"--add-host zipkin.istio-monitoring.svc:1.2.3.4 " +
							"proxyv2:latest " +
							"proxy sidecar",
						required: true,
					},
				},
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			g := NewGomegaWithT(t)

			items := processBundle(testCase.bundle, "/etc/istio-proxy")

			g.Expect(items).To(Equal(testCase.expectedItems))
		})
	}
}

func TestVmBootstrap_IstioIngressGatewayAddress(t *testing.T) {
	testCases := []struct {
		name            string
		k8sConfig       []runtime.Object
		expectedAddress string
	}{
		{
			name: "minial mesh expansion configuration (just `values.meshExpansion.enabled` flag)",
			k8sConfig: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "istio-system",
					},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "istio",
						Namespace: "istio-system",
					},
					Data: map[string]string{
						"mesh":         "",
						"meshNetworks": "networks: {}",
					},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "istio-sidecar-injector",
						Namespace: "istio-system",
					},
					Data: map[string]string{
						"values": `{}`,
					},
				},
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "istio-ingressgateway",
						Namespace: "istio-system",
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{Name: "tcp-istiod", Port: 15012},
							{Name: "tls", Port: 15443},
						},
					},
					Status: corev1.ServiceStatus{
						LoadBalancer: corev1.LoadBalancerStatus{
							Ingress: []corev1.LoadBalancerIngress{
								{Hostname: "x.y.z"},
								{IP: "1.2.3.4"},
							},
						},
					},
				},
			},
			expectedAddress: "x.y.z",
		},
		{
			name: "mesh expansion configuration with an alternative network Gateway Service",
			k8sConfig: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "istio-system",
					},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "istio",
						Namespace: "istio-system",
					},
					Data: map[string]string{
						"mesh": "",
						"meshNetworks": `
                          networks:
                            "":
                              endpoints:
                              - fromRegistry: example
                              gateways:
                              - port: 15443
                                registryServiceName: vmgateway.istio-system.svc.cluster.local
`,
					},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "istio-sidecar-injector",
						Namespace: "istio-system",
					},
					Data: map[string]string{
						"values": `{}`,
					},
				},
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "vmgateway",
						Namespace: "istio-system",
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{Name: "tcp-istiod", Port: 15012},
							{Name: "tls", Port: 15443},
						},
					},
					Status: corev1.ServiceStatus{
						LoadBalancer: corev1.LoadBalancerStatus{
							Ingress: []corev1.LoadBalancerIngress{
								{IP: "1.2.3.4"},
							},
						},
					},
				},
			},
			expectedAddress: "1.2.3.4",
		},
		{
			name: "mesh expansion configuration with a custom network gateway",
			k8sConfig: []runtime.Object{
				&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "istio-system",
					},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "istio",
						Namespace: "istio-system",
					},
					Data: map[string]string{
						"mesh": "",
						"meshNetworks": `
                          networks:
                            "vpc1":
                              gateways:
                              - port: 15443
                                address: a.b.c
                            "irrelevant":
                              endpoints:
                              - fromRegistry: example
                              gateways:
                              - port: 15443
                                registryServiceName: vmgateway.istio-system.svc.cluster.local
`,
					},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "istio-sidecar-injector",
						Namespace: "istio-system",
					},
					Data: map[string]string{
						"values": `{
                          "global": {
                            "network": "vpc1"
                          }
                        }`,
					},
				},
			},
			expectedAddress: "a.b.c",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			g := NewGomegaWithT(t)

			backupInterfaceFactory := interfaceFactory
			backupIstioNamespace := istioNamespace
			backupMeshConfigMapName := meshConfigMapName
			backupInjectConfigMapName := injectConfigMapName
			defer func() {
				interfaceFactory = backupInterfaceFactory
				istioNamespace = backupIstioNamespace
				meshConfigMapName = backupMeshConfigMapName
				injectConfigMapName = backupInjectConfigMapName
			}()

			interfaceFactory = mockInterfaceFactoryGenerator(testCase.k8sConfig)
			istioNamespace = "istio-system"
			meshConfigMapName = defaultMeshConfigMapName
			injectConfigMapName = defaultInjectConfigMapName

			meshConfig, err := getMeshConfigFromConfigMap("", "")
			g.Expect(err).NotTo(HaveOccurred())

			meshNetworksConfig, err := getMeshNetworksFromConfigMap("", "")
			g.Expect(err).NotTo(HaveOccurred())

			istioConfigValues, err := getConfigValuesFromConfigMap("")
			g.Expect(err).NotTo(HaveOccurred())

			kubeClient, err := interfaceFactory("")
			g.Expect(err).NotTo(HaveOccurred())

			address, err := getIstioIngressGatewayAddress(kubeClient, istioNamespace, meshConfig, meshNetworksConfig, istioConfigValues)
			g.Expect(err).NotTo(HaveOccurred())

			g.Expect(address).To(Equal(testCase.expectedAddress))
		})
	}
}
