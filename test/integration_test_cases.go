/*
Copyright 2022 The l7mp/stunner team.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	// "regexp"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	// meta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	// "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	// k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	// ctrlutil "sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	stnrv1a1 "github.com/l7mp/stunner/pkg/apis/v1alpha1"
	a12n "github.com/l7mp/stunner/pkg/authentication"

	opdefault "github.com/l7mp/stunner-gateway-operator/pkg/config"

	"github.com/l7mp/stunner-auth-service/pkg/client"
)

var (
	_         = fmt.Sprintf("%d", 1)
	turnAuth  *client.TurnAuthenticationToken
	iceConfig *client.IceConfig
	err       error
)

var _ = Describe("Integration test:", func() {
	Context("When no stunner ConfigMap is lodaded", func() {
		It("getTurnAuth should return an error", func() {
			// service=turn is optional
			param := client.GetTurnAuthParams{}

			// there is a good chance the HTTP server is not running yet
			Eventually(func() bool {
				_, err = clnt.GetTurnAuthToken(context.TODO(), &param)
				_, ok := err.(*client.TurnError)
				return err != nil && ok
			}, timeout, interval).Should(BeTrue())

			Expect(err).To(HaveOccurred())

			// fmt.Println("gggggggggggggggggggggggggggg")
			// fmt.Printf("%#v\n", err)

			terr, ok := err.(*client.TurnError)
			Expect(ok).To(BeTrue())

			r := terr.Response
			Expect(r).NotTo(BeNil())
			Expect(r.StatusCode()).To(Equal(http.StatusInternalServerError))

		})

		It("getIceConfig should return an error", func() {
			// service=turn is optional
			param := client.GetIceAuthParams{}
			_, err := clnt.GetIceConfig(context.TODO(), &param)
			Expect(err).To(HaveOccurred())

			terr, ok := err.(*client.IceError)
			Expect(ok).To(BeTrue())

			r := terr.Response
			Expect(r).NotTo(BeNil())
			Expect(r.StatusCode()).To(Equal(http.StatusInternalServerError))
		})
	})

	Context("When loading an empty ConfigMap", func() {
		It("getTurnAuth should return an error", func() {
			ctrl.Log.Info("loading empty ConfigMap")
			Expect(k8sClient.Create(ctx, testConfigMap)).Should(Succeed())

			// wait for K8s to reconcile the ConfigMap
			time.Sleep(time.Second)

			param := client.GetTurnAuthParams{}
			_, err := clnt.GetTurnAuthToken(context.TODO(), &param)
			Expect(err).To(HaveOccurred())

			terr, ok := err.(*client.TurnError)
			Expect(ok).To(BeTrue())

			r := terr.Response
			Expect(r).NotTo(BeNil())
			Expect(r.StatusCode()).To(Equal(http.StatusInternalServerError))
		})

		It("getIceConfig should return an error", func() {
			// service=turn is optional
			param := client.GetIceAuthParams{}
			_, err := clnt.GetIceConfig(context.TODO(), &param)
			Expect(err).To(HaveOccurred())

			terr, ok := err.(*client.IceError)
			Expect(ok).To(BeTrue())

			r := terr.Response
			Expect(r).NotTo(BeNil())
			Expect(r.StatusCode()).To(Equal(http.StatusInternalServerError))
		})
	})

	Context("When a single stunner config is lodaded", func() {
		It("should return a nonempty TURN auth token", func() {
			ctrl.Log.Info("loading nonempty ConfigMap")
			recreateOrUpdateConfigMap(func(current *corev1.ConfigMap) {
				s, _ := json.Marshal(plaintextAuthConfig)
				current.Data[opdefault.DefaultStunnerdConfigfileName] = string(s)
			})

			param := client.GetTurnAuthParams{}
			Eventually(func() bool {
				turnAuth, err = clnt.GetTurnAuthToken(context.TODO(), &param)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			Expect(err).NotTo(HaveOccurred())

			Expect(turnAuth).NotTo(BeNil())
			Expect(turnAuth.Username).NotTo(BeNil())
			Expect(*turnAuth.Username).To(Equal("user1"))
			Expect(turnAuth.Password).NotTo(BeNil())
			Expect(*turnAuth.Password).To(Equal("pass1"))
			Expect(turnAuth.Ttl).NotTo(BeNil())
			Expect(*turnAuth.Ttl).To(Equal(int64(86400)))
			Expect(turnAuth.Uris, "URIs nil")
			uris := *turnAuth.Uris
			Expect(uris).To(HaveLen(4))
			Expect(uris).To(ContainElement("turn:1.2.3.4:3478?transport=udp"))
			Expect(uris).To(ContainElement("turn:1.2.3.4:3478?transport=tcp"))
			Expect(uris).To(ContainElement("turns:127.0.0.1:3479?transport=tcp"))
			Expect(uris).To(ContainElement("turns:127.0.0.1:3479?transport=udp"))

		})

		It("should return a nonempty ICE config", func() {
			param := client.GetIceAuthParams{}
			Eventually(func() bool {
				iceConfig, err = clnt.GetIceConfig(context.TODO(), &param)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			Expect(err).NotTo(HaveOccurred())

			Expect(iceConfig).NotTo(BeNil())
			Expect(iceConfig.IceServers).NotTo(BeNil())
			iceServers := *iceConfig.IceServers
			Expect(iceServers).To(HaveLen(1))
			iceAuth := iceServers[0]
			Expect(iceAuth).NotTo(BeNil())
			Expect(iceAuth.Username).NotTo(BeNil())
			Expect(*iceAuth.Username).To(Equal("user1"))
			Expect(iceAuth.Credential).NotTo(BeNil())
			Expect(*iceAuth.Credential).To(Equal("pass1"))
			Expect(iceAuth.Urls).NotTo(BeNil())
			uris := *iceAuth.Urls
			Expect(uris).To(HaveLen(4))
			Expect(uris).To(ContainElement("turn:1.2.3.4:3478?transport=udp"))
			Expect(uris).To(ContainElement("turn:1.2.3.4:3478?transport=tcp"))
			Expect(uris).To(ContainElement("turns:127.0.0.1:3479?transport=tcp"))
			Expect(uris).To(ContainElement("turns:127.0.0.1:3479?transport=udp"))
		})
	})

	Context("When the stunner config is updated", func() {
		It("should return a new TURN auth token", func() {
			ctrl.Log.Info("updating ConfigMap")
			recreateOrUpdateConfigMap(func(current *corev1.ConfigMap) {
				s, _ := json.Marshal(longtermAuthConfig)
				current.Data[opdefault.DefaultStunnerdConfigfileName] = string(s)
			})

			ttl := 10
			param := client.GetTurnAuthParams{Ttl: &ttl}

			Eventually(func() bool {
				turnAuth, err = clnt.GetTurnAuthToken(context.TODO(), &param)
				return err == nil && turnAuth.Username != nil && *turnAuth.Username != "user1"
			}, timeout, interval).Should(BeTrue())

			Expect(err).NotTo(HaveOccurred())

			Expect(turnAuth).NotTo(BeNil())
			Expect(turnAuth.Username).NotTo(BeNil())
			Expect(*turnAuth.Username).To(MatchRegexp(`^\d+:$`))
			Expect(turnAuth.Password).NotTo(BeNil())

			passwd, err := a12n.GetLongTermCredential(*turnAuth.Username, "my-secret")
			Expect(err).NotTo(HaveOccurred())
			Expect(*turnAuth.Password).To(Equal(passwd))

			Expect(turnAuth.Ttl).NotTo(BeNil())
			Expect(*turnAuth.Ttl).To(Equal(int64(10)))
			Expect(turnAuth.Uris, "URIs nil")
			uris := *turnAuth.Uris
			Expect(uris).To(HaveLen(4))
			Expect(uris).To(ContainElement("turn:1.2.3.5:3478?transport=udp"))
			Expect(uris).To(ContainElement("turn:1.2.3.5:3478?transport=tcp"))
			Expect(uris).To(ContainElement("turns:127.0.0.2:3479?transport=tcp"))
			Expect(uris).To(ContainElement("turns:127.0.0.2:3479?transport=udp"))
		})

		It("should return a new ICE config", func() {
			param := client.GetIceAuthParams{Username: &testuser}
			Eventually(func() bool {
				iceConfig, err = clnt.GetIceConfig(context.TODO(), &param)
				return err == nil
			}, timeout, interval).Should(BeTrue())

			Expect(err).NotTo(HaveOccurred())

			Expect(iceConfig).NotTo(BeNil())
			Expect(iceConfig.IceServers).NotTo(BeNil())
			iceServers := *iceConfig.IceServers
			Expect(iceServers).To(HaveLen(1))
			iceAuth := iceServers[0]
			Expect(iceAuth).NotTo(BeNil())

			Expect(iceAuth.Username).NotTo(BeNil())
			Expect(*iceAuth.Username).To(MatchRegexp(`^\d+:dummy$`))
			Expect(iceAuth.Credential).NotTo(BeNil())

			passwd, err := a12n.GetLongTermCredential(*iceAuth.Username, "my-secret")
			Expect(err).NotTo(HaveOccurred())
			Expect(*iceAuth.Credential).To(Equal(passwd))

			Expect(iceAuth.Urls).NotTo(BeNil())
			uris := *iceAuth.Urls
			Expect(uris).To(HaveLen(4))
			Expect(uris).To(ContainElement("turn:1.2.3.5:3478?transport=udp"))
			Expect(uris).To(ContainElement("turn:1.2.3.5:3478?transport=tcp"))
			Expect(uris).To(ContainElement("turns:127.0.0.2:3479?transport=tcp"))
			Expect(uris).To(ContainElement("turns:127.0.0.2:3479?transport=udp"))
		})
	})

	Context("When using filters", func() {
		It("should return a TURN auth token with filtered URIs", func() {
			param := client.GetTurnAuthParams{Namespace: &testnamespace}

			turnAuth, err = clnt.GetTurnAuthToken(context.TODO(), &param)
			Expect(err).NotTo(HaveOccurred())

			Expect(turnAuth).NotTo(BeNil())
			Expect(turnAuth.Username).NotTo(BeNil())
			Expect(*turnAuth.Username).To(MatchRegexp(`^\d+:$`))
			Expect(turnAuth.Password).NotTo(BeNil())

			passwd, err := a12n.GetLongTermCredential(*turnAuth.Username, "my-secret")
			Expect(err).NotTo(HaveOccurred())
			Expect(*turnAuth.Password).To(Equal(passwd))

			Expect(turnAuth.Ttl).NotTo(BeNil())
			Expect(*turnAuth.Ttl).To(Equal(int64(86400)))
			Expect(turnAuth.Uris, "URIs nil")
			uris := *turnAuth.Uris
			Expect(uris).To(HaveLen(3))
			Expect(uris).To(ContainElement("turn:1.2.3.5:3478?transport=udp"))
			Expect(uris).To(ContainElement("turns:127.0.0.2:3479?transport=tcp"))
			Expect(uris).To(ContainElement("turns:127.0.0.2:3479?transport=udp"))
		})

		It("should return an ICE config with filtered URIs", func() {
			param := client.GetIceAuthParams{
				Username:  &testuser,
				Namespace: &testnamespace,
				Gateway:   &testgateway,
			}

			iceConfig, err = clnt.GetIceConfig(context.TODO(), &param)
			Expect(err).NotTo(HaveOccurred())

			Expect(iceConfig).NotTo(BeNil())
			Expect(iceConfig.IceServers).NotTo(BeNil())
			iceServers := *iceConfig.IceServers
			Expect(iceServers).To(HaveLen(1))
			iceAuth := iceServers[0]
			Expect(iceAuth).NotTo(BeNil())

			Expect(iceAuth.Username).NotTo(BeNil())
			Expect(*iceAuth.Username).To(MatchRegexp(`^\d+:dummy$`))
			Expect(iceAuth.Credential).NotTo(BeNil())

			passwd, err := a12n.GetLongTermCredential(*iceAuth.Username, "my-secret")
			Expect(err).NotTo(HaveOccurred())
			Expect(*iceAuth.Credential).To(Equal(passwd))

			Expect(iceAuth.Urls).NotTo(BeNil())
			uris := *iceAuth.Urls
			Expect(uris).To(HaveLen(2))
			Expect(uris).To(ContainElement("turn:1.2.3.5:3478?transport=udp"))
			Expect(uris).To(ContainElement("turns:127.0.0.2:3479?transport=udp"))
		})

		It("should correctly handle a maximally filtered ICE config as well", func() {
			param := client.GetIceAuthParams{
				Username:  &testuser,
				Namespace: &testnamespace,
				Gateway:   &testgateway,
				Listener:  &testlistener2,
			}

			iceConfig, err = clnt.GetIceConfig(context.TODO(), &param)
			Expect(err).NotTo(HaveOccurred())

			Expect(iceConfig).NotTo(BeNil())
			Expect(iceConfig.IceServers).NotTo(BeNil())
			iceServers := *iceConfig.IceServers
			Expect(iceServers).To(HaveLen(1))
			iceAuth := iceServers[0]
			Expect(iceAuth).NotTo(BeNil())

			Expect(iceAuth.Username).NotTo(BeNil())
			Expect(*iceAuth.Username).To(MatchRegexp(`^\d+:dummy$`))
			Expect(iceAuth.Credential).NotTo(BeNil())

			passwd, err := a12n.GetLongTermCredential(*iceAuth.Username, "my-secret")
			Expect(err).NotTo(HaveOccurred())
			Expect(*iceAuth.Credential).To(Equal(passwd))

			Expect(iceAuth.Urls).NotTo(BeNil())
			uris := *iceAuth.Urls
			Expect(uris).To(HaveLen(1))
			Expect(uris).To(ContainElement("turn:1.2.3.5:3478?transport=udp"))
		})

		It("should return 404 when there is no match", func() {
			dummyListener := "dummy"
			param := client.GetIceAuthParams{
				Username:  &testuser,
				Namespace: &testnamespace,
				Gateway:   &testgateway,
				Listener:  &dummyListener,
			}

			iceConfig, err = clnt.GetIceConfig(context.TODO(), &param)
			Expect(err).To(HaveOccurred())

			terr, ok := err.(*client.IceError)
			Expect(ok).To(BeTrue())

			r := terr.Response
			Expect(r).NotTo(BeNil())
			Expect(r.StatusCode()).To(Equal(http.StatusNotFound))
		})
	})

	Context("When loading multiple Stunner configs", func() {
		It("should return a new ICE config", func() {
			ctrl.Log.Info("loading a new ConfigMap")

			s, _ := json.Marshal(plaintextAuthConfig)
			cm := corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testconfigmap-2",
					Namespace: testnamespace,
					Labels: map[string]string{
						opdefault.OwnedByLabelKey: opdefault.OwnedByLabelValue,
					},
					Annotations: map[string]string{
						opdefault.RelatedGatewayKey: "testGatewayConfig-2",
					},
				},
				Data: map[string]string{
					opdefault.DefaultStunnerdConfigfileName: string(s),
				},
			}

			Expect(k8sClient.Create(ctx, &cm)).Should(Succeed())

			param := client.GetIceAuthParams{}
			Eventually(func() bool {
				iceConfig, err = clnt.GetIceConfig(context.TODO(), &param)
				return err == nil && iceConfig.IceServers != nil && len(*iceConfig.IceServers) == 2
			}, timeout, interval).Should(BeTrue())

			Expect(err).NotTo(HaveOccurred())

			Expect(iceConfig).NotTo(BeNil())
			Expect(iceConfig.IceServers).NotTo(BeNil())
			iceServers := *iceConfig.IceServers
			Expect(iceServers).To(HaveLen(2))

			// first the plaintext
			iceAuth := iceServers[0]
			Expect(iceAuth).NotTo(BeNil())
			Expect(iceAuth.Username).NotTo(BeNil())
			if *iceAuth.Username != "user1" {
				iceAuth = iceServers[1]
			}

			Expect(iceAuth).NotTo(BeNil())
			Expect(iceAuth.Username).NotTo(BeNil())
			Expect(*iceAuth.Username).To(Equal("user1"))
			Expect(iceAuth.Credential).NotTo(BeNil())
			Expect(*iceAuth.Credential).To(Equal("pass1"))
			Expect(iceAuth.Urls).NotTo(BeNil())

			uris := *iceAuth.Urls
			Expect(uris).To(HaveLen(4))
			Expect(uris).To(ContainElement("turn:1.2.3.4:3478?transport=udp"))
			Expect(uris).To(ContainElement("turn:1.2.3.4:3478?transport=tcp"))
			Expect(uris).To(ContainElement("turns:127.0.0.1:3479?transport=tcp"))
			Expect(uris).To(ContainElement("turns:127.0.0.1:3479?transport=udp"))

			iceAuth = iceServers[1]
			Expect(iceAuth).NotTo(BeNil())
			Expect(iceAuth.Username).NotTo(BeNil())
			if *iceAuth.Username == "user1" {
				iceAuth = iceServers[0]
			}

			Expect(iceAuth).NotTo(BeNil())
			Expect(iceAuth.Username).NotTo(BeNil())
			Expect(*iceAuth.Username).To(MatchRegexp(`^\d+:$`))
			Expect(iceAuth.Credential).NotTo(BeNil())

			passwd, err := a12n.GetLongTermCredential(*iceAuth.Username, "my-secret")
			Expect(err).NotTo(HaveOccurred())
			Expect(*iceAuth.Credential).To(Equal(passwd))

			Expect(iceAuth.Urls).NotTo(BeNil())
			uris = *iceAuth.Urls
			Expect(uris).To(HaveLen(4))
			Expect(uris).To(ContainElement("turn:1.2.3.5:3478?transport=udp"))
			Expect(uris).To(ContainElement("turn:1.2.3.5:3478?transport=tcp"))
			Expect(uris).To(ContainElement("turns:127.0.0.2:3479?transport=tcp"))
			Expect(uris).To(ContainElement("turns:127.0.0.2:3479?transport=udp"))
		})

		It("should return a single TURN auth token with filtered URIs", func() {
			param := client.GetTurnAuthParams{Namespace: &testnamespace}
			turnAuth, err = clnt.GetTurnAuthToken(context.TODO(), &param)
			Expect(err).NotTo(HaveOccurred())

			Expect(turnAuth).NotTo(BeNil())
			Expect(turnAuth.Username).NotTo(BeNil())

			if *turnAuth.Username == "user1" {
				// we loaded the plaintext
				Expect(*turnAuth.Username).To(Equal("user1"))
				Expect(turnAuth.Password).NotTo(BeNil())
				Expect(*turnAuth.Password).To(Equal("pass1"))
				Expect(turnAuth.Ttl).NotTo(BeNil())
				Expect(*turnAuth.Ttl).To(Equal(int64(86400)))
				Expect(turnAuth.Uris, "URIs nil")
				uris := *turnAuth.Uris
				Expect(uris).To(HaveLen(3))
				Expect(uris).To(ContainElement("turn:1.2.3.4:3478?transport=udp"))
				Expect(uris).To(ContainElement("turns:127.0.0.1:3479?transport=tcp"))
				Expect(uris).To(ContainElement("turns:127.0.0.1:3479?transport=udp"))
			} else {
				// we loaded the longterm
				Expect(*turnAuth.Username).To(MatchRegexp(`^\d+:$`))
				Expect(turnAuth.Password).NotTo(BeNil())

				passwd, err := a12n.GetLongTermCredential(*turnAuth.Username, "my-secret")
				Expect(err).NotTo(HaveOccurred())
				Expect(*turnAuth.Password).To(Equal(passwd))

				Expect(turnAuth.Ttl).NotTo(BeNil())
				Expect(*turnAuth.Ttl).To(Equal(int64(86400)))
				Expect(turnAuth.Uris, "URIs nil")
				uris := *turnAuth.Uris
				Expect(uris).To(HaveLen(3))
				Expect(uris).To(ContainElement("turn:1.2.3.5:3478?transport=udp"))
				Expect(uris).To(ContainElement("turns:127.0.0.2:3479?transport=tcp"))
				Expect(uris).To(ContainElement("turns:127.0.0.2:3479?transport=udp"))
			}
		})

		It("should return an ICE config with filtered URIs", func() {
			param := client.GetIceAuthParams{
				Username:  &testuser,
				Namespace: &testnamespace,
				Gateway:   &testgateway,
			}

			iceConfig, err = clnt.GetIceConfig(context.TODO(), &param)
			Expect(err).NotTo(HaveOccurred())

			Expect(iceConfig).NotTo(BeNil())
			Expect(iceConfig.IceServers).NotTo(BeNil())
			iceServers := *iceConfig.IceServers
			Expect(iceServers).To(HaveLen(2))

			// first the plaintext
			iceAuth := iceServers[0]
			Expect(iceAuth).NotTo(BeNil())
			Expect(iceAuth.Username).NotTo(BeNil())
			if *iceAuth.Username != "user1" {
				iceAuth = iceServers[1]
			}

			Expect(iceAuth).NotTo(BeNil())
			Expect(iceAuth.Username).NotTo(BeNil())
			Expect(*iceAuth.Username).To(Equal("user1"))
			Expect(iceAuth.Credential).NotTo(BeNil())
			Expect(*iceAuth.Credential).To(Equal("pass1"))
			Expect(iceAuth.Urls).NotTo(BeNil())

			uris := *iceAuth.Urls
			Expect(uris).To(HaveLen(2))
			Expect(uris).To(ContainElement("turn:1.2.3.4:3478?transport=udp"))
			Expect(uris).To(ContainElement("turns:127.0.0.1:3479?transport=udp"))

			iceAuth = iceServers[1]
			Expect(iceAuth).NotTo(BeNil())
			Expect(iceAuth.Username).NotTo(BeNil())
			if *iceAuth.Username == "user1" {
				iceAuth = iceServers[0]
			}

			Expect(iceAuth).NotTo(BeNil())
			Expect(iceAuth.Username).NotTo(BeNil())
			Expect(*iceAuth.Username).To(MatchRegexp(`^\d+:dummy$`))
			Expect(iceAuth.Credential).NotTo(BeNil())

			passwd, err := a12n.GetLongTermCredential(*iceAuth.Username, "my-secret")
			Expect(err).NotTo(HaveOccurred())
			Expect(*iceAuth.Credential).To(Equal(passwd))

			Expect(iceAuth.Urls).NotTo(BeNil())
			uris = *iceAuth.Urls
			Expect(uris).To(HaveLen(2))
			Expect(uris).To(ContainElement("turn:1.2.3.5:3478?transport=udp"))
			Expect(uris).To(ContainElement("turns:127.0.0.2:3479?transport=udp"))
		})

		It("should correctly handle a maximally filtered ICE config as well", func() {
			param := client.GetIceAuthParams{
				Username:  &testuser,
				Namespace: &testnamespace,
				Gateway:   &testgateway,
				Listener:  &testlistener,
			}

			iceConfig, err = clnt.GetIceConfig(context.TODO(), &param)
			Expect(err).NotTo(HaveOccurred())

			Expect(iceConfig).NotTo(BeNil())
			Expect(iceConfig.IceServers).NotTo(BeNil())
			iceServers := *iceConfig.IceServers
			// we filtered our the longterm stuff altogether
			Expect(iceServers).To(HaveLen(1))

			iceAuth := iceServers[0]
			Expect(iceAuth).NotTo(BeNil())
			Expect(iceAuth.Username).NotTo(BeNil())
			Expect(*iceAuth.Username).To(Equal("user1"))
			Expect(iceAuth.Credential).NotTo(BeNil())
			Expect(*iceAuth.Credential).To(Equal("pass1"))
			Expect(iceAuth.Urls).NotTo(BeNil())

			uris := *iceAuth.Urls
			Expect(uris).To(HaveLen(1))
			Expect(uris).To(ContainElement("turn:1.2.3.4:3478?transport=udp"))
		})

		It("should return 404 when there is no match", func() {
			dummyListener := "dummy"
			param := client.GetIceAuthParams{
				Username:  &testuser,
				Namespace: &testnamespace,
				Gateway:   &testgateway,
				Listener:  &dummyListener,
			}

			iceConfig, err = clnt.GetIceConfig(context.TODO(), &param)
			Expect(err).To(HaveOccurred())

			terr, ok := err.(*client.IceError)
			Expect(ok).To(BeTrue())

			r := terr.Response
			Expect(r).NotTo(BeNil())
			Expect(r.StatusCode()).To(Equal(http.StatusNotFound))
		})
	})

	Context("When deleting one of the stunner configs and updating the other", func() {
		It("should return a new ICE config", func() {
			ctrl.Log.Info("deleting ConfigMap")
			cm := corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "testconfigmap-2",
					Namespace: testnamespace,
				},
			}

			Expect(k8sClient.Delete(ctx, &cm)).Should(Succeed())

			ctrl.Log.Info("updating ConfigMap")
			recreateOrUpdateConfigMap(func(current *corev1.ConfigMap) {
				sc := stnrv1a1.StunnerConfig{}
				plaintextAuthConfig.DeepCopyInto(&sc)
				sc.Auth.Credentials["username"] = "user2"
				s, _ := json.Marshal(sc)
				current.Data[opdefault.DefaultStunnerdConfigfileName] = string(s)
			})

			param := client.GetIceAuthParams{}
			Eventually(func() bool {
				iceConfig, err = clnt.GetIceConfig(context.TODO(), &param)
				if iceConfig == nil || err != nil || iceConfig.IceServers == nil {
					return false
				}
				iceServers := *iceConfig.IceServers

				return len(iceServers) == 1 &&
					iceServers[0].Username != nil && *iceServers[0].Username == "user2"
			}, timeout, interval).Should(BeTrue())

			Expect(err).NotTo(HaveOccurred())

			Expect(iceConfig).NotTo(BeNil())
			Expect(iceConfig.IceServers).NotTo(BeNil())
			iceServers := *iceConfig.IceServers
			Expect(iceServers).To(HaveLen(1))

			// first the plaintext
			iceAuth := iceServers[0]
			Expect(iceAuth).NotTo(BeNil())
			Expect(iceAuth.Username).NotTo(BeNil())
			Expect(*iceAuth.Username).To(Equal("user2"))
			Expect(iceAuth.Credential).NotTo(BeNil())
			Expect(*iceAuth.Credential).To(Equal("pass1"))
			Expect(iceAuth.Urls).NotTo(BeNil())

			uris := *iceAuth.Urls
			Expect(uris).To(HaveLen(4))
			Expect(uris).To(ContainElement("turn:1.2.3.4:3478?transport=udp"))
			Expect(uris).To(ContainElement("turn:1.2.3.4:3478?transport=tcp"))
			Expect(uris).To(ContainElement("turns:127.0.0.1:3479?transport=tcp"))
			Expect(uris).To(ContainElement("turns:127.0.0.1:3479?transport=udp"))
		})

		It("should correctly handle a maximally filtered ICE config as well", func() {
			param := client.GetIceAuthParams{
				Username:  &testuser,
				Namespace: &testnamespace,
				Gateway:   &testgateway,
				Listener:  &testlistener,
			}

			iceConfig, err = clnt.GetIceConfig(context.TODO(), &param)
			Expect(err).NotTo(HaveOccurred())

			Expect(iceConfig).NotTo(BeNil())
			Expect(iceConfig.IceServers).NotTo(BeNil())
			iceServers := *iceConfig.IceServers
			// we filtered our the longterm stuff altogether
			Expect(iceServers).To(HaveLen(1))

			iceAuth := iceServers[0]
			Expect(iceAuth).NotTo(BeNil())
			Expect(iceAuth.Username).NotTo(BeNil())
			Expect(*iceAuth.Username).To(Equal("user2"))
			Expect(iceAuth.Credential).NotTo(BeNil())
			Expect(*iceAuth.Credential).To(Equal("pass1"))
			Expect(iceAuth.Urls).NotTo(BeNil())

			uris := *iceAuth.Urls
			Expect(uris).To(HaveLen(1))
			Expect(uris).To(ContainElement("turn:1.2.3.4:3478?transport=udp"))
		})
	})

	Context("When one of the stunner configs is updated again", func() {
		It("should return a new ICE config", func() {
			ctrl.Log.Info("updating ConfigMap")
			recreateOrUpdateConfigMap(func(current *corev1.ConfigMap) {
				sc := stnrv1a1.StunnerConfig{}
				plaintextAuthConfig.DeepCopyInto(&sc)
				sc.Auth.Credentials["username"] = "user3"
				s, _ := json.Marshal(sc)
				current.Data[opdefault.DefaultStunnerdConfigfileName] = string(s)
			})

			param := client.GetIceAuthParams{}
			Eventually(func() bool {
				iceConfig, err = clnt.GetIceConfig(context.TODO(), &param)
				if iceConfig == nil || err != nil || iceConfig.IceServers == nil {
					return false
				}
				iceServers := *iceConfig.IceServers

				return len(iceServers) == 1 &&
					iceServers[0].Username != nil && *iceServers[0].Username == "user3"
			}, timeout, interval).Should(BeTrue())

			Expect(err).NotTo(HaveOccurred())

			Expect(iceConfig).NotTo(BeNil())
			Expect(iceConfig.IceServers).NotTo(BeNil())
			iceServers := *iceConfig.IceServers
			Expect(iceServers).To(HaveLen(1))

			// first the plaintext
			iceAuth := iceServers[0]
			Expect(iceAuth).NotTo(BeNil())
			Expect(iceAuth.Username).NotTo(BeNil())
			Expect(*iceAuth.Username).To(Equal("user3"))
			Expect(iceAuth.Credential).NotTo(BeNil())
			Expect(*iceAuth.Credential).To(Equal("pass1"))
			Expect(iceAuth.Urls).NotTo(BeNil())

			uris := *iceAuth.Urls
			Expect(uris).To(HaveLen(4))
			Expect(uris).To(ContainElement("turn:1.2.3.4:3478?transport=udp"))
			Expect(uris).To(ContainElement("turn:1.2.3.4:3478?transport=tcp"))
			Expect(uris).To(ContainElement("turns:127.0.0.1:3479?transport=tcp"))
			Expect(uris).To(ContainElement("turns:127.0.0.1:3479?transport=udp"))
		})

		It("should correctly handle a maximally filtered ICE config as well", func() {
			param := client.GetIceAuthParams{
				Username:  &testuser,
				Namespace: &testnamespace,
				Gateway:   &testgateway,
				Listener:  &testlistener,
			}

			iceConfig, err = clnt.GetIceConfig(context.TODO(), &param)
			Expect(err).NotTo(HaveOccurred())

			Expect(iceConfig).NotTo(BeNil())
			Expect(iceConfig.IceServers).NotTo(BeNil())
			iceServers := *iceConfig.IceServers
			// we filtered our the longterm stuff altogether
			Expect(iceServers).To(HaveLen(1))

			iceAuth := iceServers[0]
			Expect(iceAuth).NotTo(BeNil())
			Expect(iceAuth.Username).NotTo(BeNil())
			Expect(*iceAuth.Username).To(Equal("user3"))
			Expect(iceAuth.Credential).NotTo(BeNil())
			Expect(*iceAuth.Credential).To(Equal("pass1"))
			Expect(iceAuth.Urls).NotTo(BeNil())

			uris := *iceAuth.Urls
			Expect(uris).To(HaveLen(1))
			Expect(uris).To(ContainElement("turn:1.2.3.4:3478?transport=udp"))
		})
	})

	Context("When deleting all stunner ConfigMaps", func() {
		It("getTurnAuth should return an error", func() {
			ctrl.Log.Info("deleting ConfigMap")
			Expect(k8sClient.Delete(ctx, testConfigMap)).Should(Succeed())

			param := client.GetTurnAuthParams{}
			Eventually(func() bool {
				_, err = clnt.GetTurnAuthToken(context.TODO(), &param)
				_, ok := err.(*client.TurnError)
				return err != nil && ok
			}, timeout, interval).Should(BeTrue())

			Expect(err).To(HaveOccurred())

			terr, ok := err.(*client.TurnError)
			Expect(ok).To(BeTrue())

			r := terr.Response
			Expect(r).NotTo(BeNil())
			Expect(r.StatusCode()).To(Equal(http.StatusInternalServerError))

		})

		It("getIceConfig should return an error", func() {
			param := client.GetIceAuthParams{}
			_, err := clnt.GetIceConfig(context.TODO(), &param)
			Expect(err).To(HaveOccurred())

			terr, ok := err.(*client.IceError)
			Expect(ok).To(BeTrue())

			r := terr.Response
			Expect(r).NotTo(BeNil())
			Expect(r.StatusCode()).To(Equal(http.StatusInternalServerError))
		})
	})
})
