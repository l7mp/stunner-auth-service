package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/pion/transport/v2/test"
	"github.com/stretchr/testify/assert"

	"github.com/l7mp/stunner"
	stnrv1 "github.com/l7mp/stunner/pkg/apis/v1"
	a12n "github.com/l7mp/stunner/pkg/authentication"

	"github.com/l7mp/stunner-auth-service/internal/store"
	// "github.com/l7mp/stunner-auth-service/pkg/client"
	"github.com/l7mp/stunner-auth-service/pkg/server"
	"github.com/l7mp/stunner-auth-service/pkg/types"
)

type iceAuthTestCase struct {
	name   string
	config []*stnrv1.StunnerConfig
	params string
	status int
	tester func(t *testing.T, iceAuth *types.IceConfig, authHandler a12n.AuthHandler)
}

var iceAuthTestCases = []iceAuthTestCase{
	{
		name:   "empty config",
		config: []*stnrv1.StunnerConfig{},
		params: "service=turn",
		status: http.StatusInternalServerError,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {},
	},
	{
		name:   "plaintext",
		config: []*stnrv1.StunnerConfig{&plaintextAuthConfig},
		params: "service=turn",
		status: 200,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {
			assert.NotNil(t, iceConfig, "ICE config nil")
			assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
			iceServers := *iceConfig.IceServers
			assert.Len(t, iceServers, 1, "ICE servers len")
			iceAuth := iceServers[0]
			assert.NotNil(t, iceAuth, "ICE auth token nil")
			assert.NotNil(t, iceAuth.Username, "username nil")
			assert.Equal(t, "user1", *iceAuth.Username, "username nil")
			assert.NotNil(t, iceAuth.Credential, "credential nil")
			assert.Equal(t, "pass1", *iceAuth.Credential, "credential ok")
			assert.NotNil(t, iceAuth.Urls, "URLs nil")
			uris := *iceAuth.Urls
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

			key, ok := authHandler(*iceAuth.Username, stnrv1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*iceAuth.Username,
				stnrv1.DefaultRealm, *iceAuth.Credential), "auth handler ok")
		},
	},
	{
		name:   "plaintext - dummy service",
		config: []*stnrv1.StunnerConfig{&plaintextAuthConfig},
		params: "service=dummy",
		status: http.StatusBadRequest,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {
		},
	},

	{
		name:   "plaintext - username set",
		config: []*stnrv1.StunnerConfig{&plaintextAuthConfig},
		params: "service=turn&username=dummy",
		status: 200,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {
			// useless: no username override in plaintext mode
			assert.NotNil(t, iceConfig, "ICE config nil")
			assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
			iceServers := *iceConfig.IceServers
			assert.Len(t, iceServers, 1, "ICE servers len")
			iceAuth := iceServers[0]
			assert.NotNil(t, iceAuth, "ICE auth token nil")
			assert.NotNil(t, iceAuth.Username, "username nil")
			assert.Equal(t, "user1", *iceAuth.Username, "username nil")
			assert.NotNil(t, iceAuth.Credential, "credential nil")
			assert.Equal(t, "pass1", *iceAuth.Credential, "credential ok")
			assert.NotNil(t, iceAuth.Urls, "URLs nil")
			uris := *iceAuth.Urls
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

			key, ok := authHandler(*iceAuth.Username, stnrv1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*iceAuth.Username,
				stnrv1.DefaultRealm, *iceAuth.Credential), "auth handler ok")
		},
	},
	{
		name:   "plaintext -- ttl set",
		config: []*stnrv1.StunnerConfig{&plaintextAuthConfig},
		params: "service=turn&username=dummy&ttl=1",
		status: 200,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {
			// useless: no ttl in response
			assert.NotNil(t, iceConfig, "ICE config nil")
			assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
			iceServers := *iceConfig.IceServers
			assert.Len(t, iceServers, 1, "ICE servers len")
			iceAuth := iceServers[0]
			assert.NotNil(t, iceAuth, "ICE auth token nil")
			assert.NotNil(t, iceAuth.Username, "username nil")
			assert.Equal(t, "user1", *iceAuth.Username, "username nil")
			assert.NotNil(t, iceAuth.Credential, "credential nil")
			assert.Equal(t, "pass1", *iceAuth.Credential, "credential ok")
			assert.NotNil(t, iceAuth.Urls, "URLs nil")
			uris := *iceAuth.Urls
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

			key, ok := authHandler(*iceAuth.Username, stnrv1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*iceAuth.Username,
				stnrv1.DefaultRealm, *iceAuth.Credential), "auth handler ok")
		},
	},
	{
		name:   "longterm -- basic",
		config: []*stnrv1.StunnerConfig{&longtermAuthConfig},
		params: "service=turn",
		status: 200,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {
			assert.NotNil(t, iceConfig, "ICE config nil")
			assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
			iceServers := *iceConfig.IceServers
			assert.Len(t, iceServers, 1, "ICE servers len")
			iceAuth := iceServers[0]
			assert.NotNil(t, iceAuth, "ICE auth token nil")
			assert.NotNil(t, iceAuth.Username, "username nil")
			assert.Regexp(t, regexp.MustCompile(`^\d+:`), *iceAuth.Username, "username ok")
			assert.NoError(t, a12n.CheckTimeWindowedUsername(*iceAuth.Username), "username valid")
			assert.NotNil(t, iceAuth.Credential, "credential nil")
			passwd, err := a12n.GetLongTermCredential(*iceAuth.Username, "my-secret")
			assert.NoError(t, err, "GetLongTermCredential")
			assert.Equal(t, passwd, *iceAuth.Credential, "credential ok")
			assert.NotNil(t, iceAuth.Urls, "URLs nil")
			uris := *iceAuth.Urls
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")

			key, ok := authHandler(*iceAuth.Username, stnrv1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*iceAuth.Username,
				stnrv1.DefaultRealm, *iceAuth.Credential), "auth handler ok")
		},
	},
	{
		name:   "longterm -- dummy service",
		config: []*stnrv1.StunnerConfig{&longtermAuthConfig},
		params: "service=dummy",
		status: 400,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {},
	},
	{
		name:   "longterm -- username set",
		config: []*stnrv1.StunnerConfig{&longtermAuthConfig},
		params: "service=turn&username=dummy",
		status: 200,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {
			assert.NotNil(t, iceConfig, "ICE config nil")
			assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
			iceServers := *iceConfig.IceServers
			assert.Len(t, iceServers, 1, "ICE servers len")
			iceAuth := iceServers[0]
			assert.NotNil(t, iceAuth, "ICE auth token nil")
			assert.NotNil(t, iceAuth.Username, "username nil")
			assert.Regexp(t, regexp.MustCompile(`^\d+:dummy`), *iceAuth.Username, "username ok")
			assert.NoError(t, a12n.CheckTimeWindowedUsername(*iceAuth.Username), "username valid")
			assert.NotNil(t, iceAuth.Credential, "credential nil")
			passwd, err := a12n.GetLongTermCredential(*iceAuth.Username, "my-secret")
			assert.NoError(t, err, "GetLongTermCredential")
			assert.Equal(t, passwd, *iceAuth.Credential, "credential ok")
			assert.NotNil(t, iceAuth.Urls, "URLs nil")
			uris := *iceAuth.Urls
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")

			key, ok := authHandler(*iceAuth.Username, stnrv1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*iceAuth.Username,
				stnrv1.DefaultRealm, *iceAuth.Credential), "auth handler ok")
		},
	},
	{
		name:   "longterm -- username, ttl set",
		config: []*stnrv1.StunnerConfig{&longtermAuthConfig},
		params: "service=turn&username=dummy&ttl=1",
		status: 200,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {
			// we must wait for the token to expire
			time.Sleep(time.Duration(2) * time.Second)

			assert.NotNil(t, iceConfig, "ICE config nil")
			assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
			iceServers := *iceConfig.IceServers
			assert.Len(t, iceServers, 1, "ICE servers len")
			iceAuth := iceServers[0]
			assert.NotNil(t, iceAuth, "ICE auth token nil")
			assert.NotNil(t, iceAuth.Username, "username nil")
			assert.Regexp(t, regexp.MustCompile(`^\d+:dummy`), *iceAuth.Username, "username ok")
			assert.Error(t, a12n.CheckTimeWindowedUsername(*iceAuth.Username), "username invalid")
			assert.NotNil(t, iceAuth.Credential, "credential nil")
			passwd, err := a12n.GetLongTermCredential(*iceAuth.Username, "my-secret")
			assert.NoError(t, err, "GetLongTermCredential")
			assert.Equal(t, passwd, *iceAuth.Credential, "credential ok")
			assert.NotNil(t, iceAuth.Urls, "URLs nil")
			uris := *iceAuth.Urls
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")

			_, ok := authHandler(*iceAuth.Username, stnrv1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 1234})
			assert.False(t, ok, "authHandler key ok")
		},
	},
	{
		name:   "plaintext - multiple configs, no filter",
		config: []*stnrv1.StunnerConfig{&plaintextAuthConfig, &longtermAuthConfig, &longtermAuthConfig},
		params: "service=turn&username=dummy",
		status: 200,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {
			assert.NotNil(t, iceConfig, "ICE config nil")
			assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
			iceServers := *iceConfig.IceServers
			assert.Len(t, iceServers, 3, "ICE servers len")

			// config 1
			iceAuth := iceServers[0]
			assert.NotNil(t, iceAuth, "ICE auth token nil")
			assert.NotNil(t, iceAuth.Username, "username nil")
			assert.Equal(t, "user1", *iceAuth.Username, "username nil")
			assert.NotNil(t, iceAuth.Credential, "credential nil")
			assert.Equal(t, "pass1", *iceAuth.Credential, "credential ok")
			assert.NotNil(t, iceAuth.Urls, "URLs nil")
			uris := *iceAuth.Urls
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

			// config 2
			iceAuth = iceServers[1]
			assert.NotNil(t, iceAuth, "ICE auth token nil")
			assert.NotNil(t, iceAuth.Username, "username nil")
			assert.Regexp(t, regexp.MustCompile(`^\d+:dummy`), *iceAuth.Username, "username ok")
			assert.NoError(t, a12n.CheckTimeWindowedUsername(*iceAuth.Username), "username valid")
			assert.NotNil(t, iceAuth.Credential, "credential nil")
			passwd, err := a12n.GetLongTermCredential(*iceAuth.Username, "my-secret")
			assert.NoError(t, err, "GetLongTermCredential")
			assert.Equal(t, passwd, *iceAuth.Credential, "credential ok")
			assert.NotNil(t, iceAuth.Urls, "URLs nil")
			uris = *iceAuth.Urls
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")

			// config 3 - same as 2
			iceAuth = iceServers[2]
			assert.NotNil(t, iceAuth, "ICE auth token nil")
			assert.NotNil(t, iceAuth.Username, "username nil")
			assert.Regexp(t, regexp.MustCompile(`^\d+:dummy`), *iceAuth.Username, "username ok")
			assert.NoError(t, a12n.CheckTimeWindowedUsername(*iceAuth.Username), "username valid")
			assert.NotNil(t, iceAuth.Credential, "credential nil")
			passwd, err = a12n.GetLongTermCredential(*iceAuth.Username, "my-secret")
			assert.NoError(t, err, "GetLongTermCredential")
			assert.Equal(t, passwd, *iceAuth.Credential, "credential ok")
			assert.NotNil(t, iceAuth.Urls, "URLs nil")
			uris = *iceAuth.Urls
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")
		},
	},
	// gateway filters
	{
		name:   "plaintext - single config, namespace filter",
		config: []*stnrv1.StunnerConfig{&plaintextAuthConfig},
		params: "service=turn&namespace=testnamespace",
		status: 200,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {
			assert.NotNil(t, iceConfig, "ICE config nil")
			assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
			iceServers := *iceConfig.IceServers
			assert.Len(t, iceServers, 1, "ICE servers len")
			iceAuth := iceServers[0]
			assert.NotNil(t, iceAuth, "ICE auth token nil")
			uris := *iceAuth.Urls
			assert.Len(t, uris, 3, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")
		},
	},
	{
		name:   "plaintext - single config, gateway filter",
		config: []*stnrv1.StunnerConfig{&plaintextAuthConfig},
		params: "service=turn&namespace=testnamespace&gateway=testgateway",
		status: 200,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {
			assert.NotNil(t, iceConfig, "ICE config nil")
			assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
			iceServers := *iceConfig.IceServers
			assert.Len(t, iceServers, 1, "ICE servers len")
			iceAuth := iceServers[0]
			assert.NotNil(t, iceAuth, "ICE auth token nil")
			uris := *iceAuth.Urls
			assert.Len(t, uris, 2, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")
		},
	},
	{
		name:   "plaintext - single config, listener filter",
		config: []*stnrv1.StunnerConfig{&plaintextAuthConfig},
		params: "service=turn&namespace=testnamespace&gateway=testgateway&listener=udp",
		status: 200,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {
			assert.NotNil(t, iceConfig, "ICE config nil")
			assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
			iceServers := *iceConfig.IceServers
			assert.Len(t, iceServers, 1, "ICE servers len")
			iceAuth := iceServers[0]
			assert.NotNil(t, iceAuth, "ICE auth token nil")
			uris := *iceAuth.Urls
			assert.Len(t, uris, 1, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
		},
	},
	{
		name:   "plaintext - single config, restrictive filter, no result errs",
		config: []*stnrv1.StunnerConfig{&plaintextAuthConfig},
		params: "service=turn&namespace=testnamespace&listener=dummy&gateway=testgateway",
		status: 404,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {},
	},
	{
		name:   "plaintext - multiple configs, namespace filter",
		config: []*stnrv1.StunnerConfig{&plaintextAuthConfig, &longtermAuthConfig},
		params: "service=turn&namespace=testnamespace",
		status: 200,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {
			assert.NotNil(t, iceConfig, "ICE config nil")
			assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
			iceServers := *iceConfig.IceServers
			assert.Len(t, iceServers, 2, "ICE servers len")

			iceAuth := iceServers[0]
			assert.NotNil(t, iceAuth, "ICE auth token nil")
			uris := *iceAuth.Urls
			assert.Len(t, uris, 3, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

			iceAuth = iceServers[1]
			assert.NotNil(t, iceAuth, "ICE auth token nil")
			uris = *iceAuth.Urls
			assert.Len(t, uris, 3, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")
		},
	},
	{
		name:   "plaintext - multiple configs, gateway filter",
		config: []*stnrv1.StunnerConfig{&plaintextAuthConfig, &longtermAuthConfig},
		params: "service=turn&namespace=testnamespace&gateway=testgateway",
		status: 200,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {
			assert.NotNil(t, iceConfig, "ICE config nil")
			assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
			iceServers := *iceConfig.IceServers
			assert.Len(t, iceServers, 2, "ICE servers len")

			iceAuth := iceServers[0]
			assert.NotNil(t, iceAuth, "ICE auth token nil")
			uris := *iceAuth.Urls
			assert.Len(t, uris, 2, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

			iceAuth = iceServers[1]
			assert.NotNil(t, iceAuth, "ICE auth token nil")
			uris = *iceAuth.Urls
			assert.Len(t, uris, 2, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")
		},
	},
	{
		name:   "plaintext - multiple configs, listener filter",
		config: []*stnrv1.StunnerConfig{&plaintextAuthConfig, &longtermAuthConfig},
		params: "service=turn&namespace=testnamespace&gateway=testgateway&listener=udp",
		status: 200,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {
			assert.NotNil(t, iceConfig, "ICE config nil")
			assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
			iceServers := *iceConfig.IceServers
			assert.Len(t, iceServers, 1, "ICE servers len")

			iceAuth := iceServers[0]
			assert.NotNil(t, iceAuth, "ICE auth token nil")
			uris := *iceAuth.Urls
			assert.Len(t, uris, 1, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
		},
	},
	{
		name:   "plaintext - multiple configs, restrictive filter, no result errs",
		config: []*stnrv1.StunnerConfig{&plaintextAuthConfig},
		params: "service=turn&namespace=testnamespace&gateway=testgateway&listener=dummy",
		status: 404,
		tester: func(t *testing.T, iceConfig *types.IceConfig, authHandler a12n.AuthHandler) {},
	},
}

func TestICEAuth(t *testing.T) { testICE(t, iceAuthTestCases) }

func testICE(t *testing.T, tests []iceAuthTestCase) {
	// <setup>
	lim := test.TimeOut(time.Second * 120)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	logger := setupLogger()
	log := logger.WithName("test")

	handler, err := NewHandler(logger)
	assert.NoError(t, err, "create handler")

	serv := server.ServerInterfaceWrapper{Handler: handler}

	// starting a Stunner instance to use its authenticator
	log.Info("creating a stunnerd")
	s := stunner.NewStunner(stunner.Options{
		DryRun:   true,
		LogLevel: authTestLoglevel,
	})
	defer s.Close()
	authHandler := s.NewAuthHandler()
	// </setup>

	for _, testCase := range tests {
		log.Info(fmt.Sprintf("---------------- Test: %s ----------------", testCase.name))

		log.Info("storing config")
		store.ConfigMaps.Reset(testCase.config)

		// we do not use the Stunner auth handler for multi-config tests: no need to reconcile
		if len(testCase.config) == 1 {
			assert.NoError(t, s.Reconcile(*testCase.config[0]), "starting server")
		}

		// wait so that the auth-server has comfortable time to start
		time.Sleep(time.Duration(5) * time.Millisecond)

		log.Info("calling ICE auth handler")
		url := fmt.Sprintf("http://example.com/ice?%s", testCase.params)
		req := httptest.NewRequest("GET", url, nil)
		w := httptest.NewRecorder()
		serv.GetIceAuth(w, req)

		log.Info("testing results")
		resp := w.Result()
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err, "read body")

		assert.Equal(t, testCase.status, resp.StatusCode, "HTTP status")

		iceConfig := types.IceConfig{}
		if testCase.status == 200 {
			assert.Equal(t, "application/json; charset=UTF-8", resp.Header.Get("Content-Type"), "HTTP Content-Type")
			assert.NoError(t, json.Unmarshal(body, &iceConfig))
		}
		testCase.tester(t, &iceConfig, authHandler)
	}
}

// }

// func TestWatcher(t *testing.T) {
// 	lim := test.TimeOut(time.Second * 120)
// 	defer lim.Stop()

// 	report := test.CheckRoutines(t)
// 	defer report()

// 	ctrl.SetLogger(zap.New(zap.WriteTo(os.Stdout), zap.UseDevMode(true), func(o *zap.Options) {
// 		o.TimeEncoder = zapcore.RFC3339NanoTimeEncoder
// 	}, zap.Level(zapcore.Level(loglevel))))

// 	loggerFactory := logger.NewLoggerFactory(authTestLoglevel)
// 	log := loggerFactory.NewLogger("test-watch")

// 	log.Debug("editing config file")
// 	watchTestConfig := stnrv1.StunnerConfig{}
// 	basicAuthTestConfig.DeepCopyInto(&watchTestConfig)

// 	// remove the last listener
// 	watchTestConfig.Listeners =
// 		watchTestConfig.Listeners[:len(watchTestConfig.Listeners)-1]

// 	log.Debug("writing config file")
// 	f, err := os.CreateTemp("", "stunner_conf_*.yaml")
// 	assert.NoError(t, err, "creating temp config file")
// 	defer os.Remove(f.Name())

// 	data, err := json.MarshalIndent(watchTestConfig, "", "  ")
// 	assert.NoError(t, err, "JSONify config file")

// 	_, err = f.Write(data)
// 	assert.NoError(t, err, "writing JSON config file")

// 	log.Debug("starting auth server")
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()

// 	// set watch=true
// 	handler, err := handler.NewHandler(ctrl.Log)
// 	assert.NoError(t, err, "create handler")

// 	router := server.HandlerWithOptions(handler, server.GorillaServerOptions{})
// 	httpServer := &http.Server{Addr: ":18088", Handler: router}
// 	defer httpServer.Close()

// 	go func() { _ = httpServer.ListenAndServe() }()

// 	log.Debug("starting auth client")
// 	authClient, err := client.NewClient("http://:18088")
// 	assert.NoError(t, err, "new client")

// 	// starting a Stunner instance to use its authenticator
// 	log.Debug("creating a stunnerd")
// 	s := stunner.NewStunner(stunner.Options{
// 		DryRun:   true,
// 		LogLevel: authTestLoglevel,
// 	})
// 	defer s.Close()
// 	assert.NoError(t, s.Reconcile(watchTestConfig), "reconcile")
// 	authHandler := s.NewAuthHandler()

// 	// wait so that the auth-server has comfortable time to start
// 	time.Sleep(time.Duration(50) * time.Millisecond)

// 	log.Debug("--------------------------------------")
// 	log.Debug("testing initial TURN auth with username and service set")
// 	u := "dummy"
// 	param := client.GetTurnAuthParams{Service: types.GetTurnAuthParamsServiceTurn, Username: &u}
// 	turnAuth, err := authClient.GetTurnAuthToken(ctx, &param)
// 	assert.NoError(t, err, "TURN auth get")

// 	assert.NotNil(t, turnAuth, "TURN token nil")
// 	assert.NotNil(t, turnAuth.Username, "username nil")
// 	// cannot override username for plaintext
// 	assert.Equal(t, "user1", *turnAuth.Username, "username nil")
// 	assert.NotNil(t, turnAuth.Password, "password nil")
// 	assert.Equal(t, "pass1", *turnAuth.Password, "password ok")
// 	assert.NotNil(t, turnAuth.Ttl, "ttl nil")
// 	assert.Equal(t, int64(86400), *turnAuth.Ttl, "ttl ok")
// 	assert.NotNil(t, turnAuth.Uris, "URIs nil")
// 	uris := *turnAuth.Uris
// 	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
// 	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
// 	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")

// 	key, ok := authHandler(*turnAuth.Username, stnrv1.DefaultRealm,
// 		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
// 	assert.True(t, ok, "authHandler key ok")
// 	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
// 		stnrv1.DefaultRealm, *turnAuth.Password), "auth handler ok")

// 	log.Debug("--------------------------------------")
// 	log.Debug("editing config file: change username")
// 	watchTestConfig.Auth.Credentials["username"] = "newuser"
// 	data, err = json.MarshalIndent(watchTestConfig, "", "  ")
// 	assert.NoError(t, err, "JSONify config file")

// 	assert.NoError(t, f.Truncate(0), "truncate temp file")
// 	_, err = f.Seek(0, 0)
// 	assert.NoError(t, err, "seek temp file")
// 	_, err = f.Write(data)
// 	assert.NoError(t, err, "writing JSON config file")

// 	// let STUNner pick up the config
// 	assert.NoError(t, s.Reconcile(watchTestConfig), "reconcile")

// 	// wait so that the auth-server has comfortable time to pick up the new config
// 	time.Sleep(time.Duration(100) * time.Millisecond)

// 	param = client.GetTurnAuthParams{Service: types.GetTurnAuthParamsServiceTurn, Username: &u}
// 	turnAuth, err = authClient.GetTurnAuthToken(ctx, &param)
// 	assert.NoError(t, err, "TURN auth get")

// 	assert.NotNil(t, turnAuth, "TURN token nil")
// 	assert.NotNil(t, turnAuth.Username, "username nil")
// 	assert.Equal(t, "newuser", *turnAuth.Username, "username nil")
// 	assert.NotNil(t, turnAuth.Password, "password nil")
// 	assert.Equal(t, "pass1", *turnAuth.Password, "password ok")
// 	assert.NotNil(t, turnAuth.Ttl, "ttl nil")
// 	assert.Equal(t, int64(86400), *turnAuth.Ttl, "ttl ok")
// 	assert.NotNil(t, turnAuth.Uris, "URIs nil")
// 	uris = *turnAuth.Uris
// 	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
// 	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
// 	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")

// 	key, ok = authHandler(*turnAuth.Username, stnrv1.DefaultRealm,
// 		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
// 	assert.True(t, ok, "authHandler key ok")
// 	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
// 		stnrv1.DefaultRealm, *turnAuth.Password), "auth handler ok")

// 	log.Debug("--------------------------------------")
// 	log.Debug("editing config file: change auth type")
// 	watchTestConfig.Auth = stnrv1.AuthConfig{
// 		Type: "longterm",
// 		Credentials: map[string]string{
// 			"secret": "my-secret",
// 		},
// 	}
// 	data, err = json.MarshalIndent(watchTestConfig, "", "  ")
// 	assert.NoError(t, err, "JSONify config file")

// 	assert.NoError(t, f.Truncate(0), "truncate temp file")
// 	_, err = f.Seek(0, 0)
// 	assert.NoError(t, err, "seek temp file")
// 	_, err = f.Write(data)
// 	assert.NoError(t, err, "writing JSON config file")

// 	// let STUNner pick up the config
// 	assert.NoError(t, s.Reconcile(watchTestConfig), "reconcile")

// 	// wait so that the auth-server has comfortable time to pick up the new config
// 	time.Sleep(time.Duration(100) * time.Millisecond)

// 	u = "dummy"
// 	param = client.GetTurnAuthParams{Username: &u}
// 	turnAuth, err = authClient.GetTurnAuthToken(ctx, &param)
// 	assert.NoError(t, err, "TURN auth get")

// 	assert.NotNil(t, turnAuth, "TURN token nil")
// 	assert.NotNil(t, turnAuth.Username, "username nil")
// 	// we do not know the username, only that it contains the timestamps plus a colon
// 	assert.Regexp(t, regexp.MustCompile(`^\d+:dummy$`), *turnAuth.Username, "username ok")
// 	assert.NoError(t, a12n.CheckTimeWindowedUsername(*turnAuth.Username), "username valid")
// 	assert.NotNil(t, turnAuth.Password, "password nil")
// 	passwd, err := a12n.GetLongTermCredential(*turnAuth.Username, "my-secret")
// 	assert.NoError(t, err, "GetLongTermCredential")
// 	assert.Equal(t, passwd, *turnAuth.Password, "password ok")
// 	assert.NotNil(t, turnAuth.Uris, "URIs nil")
// 	uris = *turnAuth.Uris
// 	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
// 	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
// 	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")

// 	key, ok = authHandler(*turnAuth.Username, stnrv1.DefaultRealm,
// 		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
// 	assert.True(t, ok, "authHandler ok")
// 	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
// 		stnrv1.DefaultRealm, *turnAuth.Password), "auth handler ok")

// 	log.Debug("--------------------------------------")
// 	log.Debug("editing config file: adding a new listener")
// 	l := stnrv1.ListenerConfig{}
// 	basicAuthTestConfig.Listeners[3].DeepCopyInto(&l)
// 	watchTestConfig.Listeners = append(watchTestConfig.Listeners, l)

// 	data, err = json.MarshalIndent(watchTestConfig, "", "  ")
// 	assert.NoError(t, err, "JSONify config file")

// 	assert.NoError(t, f.Truncate(0), "truncate temp file")
// 	_, err = f.Seek(0, 0)
// 	assert.NoError(t, err, "seek temp file")
// 	_, err = f.Write(data)
// 	assert.NoError(t, err, "writing JSON config file")

// 	// let STUNner pick up the config
// 	assert.NoError(t, s.Reconcile(watchTestConfig), "reconcile")

// 	// wait so that the auth-server has comfortable time to pick up the new config
// 	time.Sleep(time.Duration(100) * time.Millisecond)

// 	u = "dummy"
// 	param = client.GetTurnAuthParams{Username: &u}
// 	turnAuth, err = authClient.GetTurnAuthToken(ctx, &param)
// 	assert.NoError(t, err, "TURN auth get")

// 	assert.NotNil(t, turnAuth, "TURN token nil")
// 	assert.NotNil(t, turnAuth.Username, "username nil")
// 	// we do not know the username, only that it contains the timestamps plus a colon
// 	assert.Regexp(t, regexp.MustCompile(`^\d+:dummy$`), *turnAuth.Username, "username ok")
// 	assert.NoError(t, a12n.CheckTimeWindowedUsername(*turnAuth.Username), "username valid")
// 	assert.NotNil(t, turnAuth.Password, "password nil")
// 	passwd, err = a12n.GetLongTermCredential(*turnAuth.Username, "my-secret")
// 	assert.NoError(t, err, "GetLongTermCredential")
// 	assert.Equal(t, passwd, *turnAuth.Password, "password ok")
// 	assert.NotNil(t, turnAuth.Uris, "URIs nil")
// 	uris = *turnAuth.Uris
// 	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
// 	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
// 	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
// 	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

// 	key, ok = authHandler(*turnAuth.Username, stnrv1.DefaultRealm,
// 		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
// 	assert.True(t, ok, "authHandler ok")
// 	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
// 		stnrv1.DefaultRealm, *turnAuth.Password), "auth handler ok")

// 	log.Debug("--------------------------------------")
// 	log.Debug("editing config file: adding a new public IP/port to a listener")
// 	watchTestConfig.Listeners[3].PublicAddr = "4.3.2.1"
// 	watchTestConfig.Listeners[3].PublicPort = 12345

// 	data, err = json.MarshalIndent(watchTestConfig, "", "  ")
// 	assert.NoError(t, err, "JSONify config file")

// 	assert.NoError(t, f.Truncate(0), "truncate temp file")
// 	_, err = f.Seek(0, 0)
// 	assert.NoError(t, err, "seek temp file")
// 	_, err = f.Write(data)
// 	assert.NoError(t, err, "writing JSON config file")

// 	// let STUNner pick up the config
// 	assert.NoError(t, s.Reconcile(watchTestConfig), "reconcile")

// 	// wait so that the auth-server has comfortable time to pick up the new config
// 	time.Sleep(time.Duration(100) * time.Millisecond)

// 	u = "dummy"
// 	param = client.GetTurnAuthParams{Username: &u}
// 	turnAuth, err = authClient.GetTurnAuthToken(ctx, &param)
// 	assert.NoError(t, err, "TURN auth get")

// 	assert.NotNil(t, turnAuth, "TURN token nil")
// 	assert.NotNil(t, turnAuth.Username, "username nil")
// 	// we do not know the username, only that it contains the timestamps plus a colon
// 	assert.Regexp(t, regexp.MustCompile(`^\d+:dummy$`), *turnAuth.Username, "username ok")
// 	assert.NoError(t, a12n.CheckTimeWindowedUsername(*turnAuth.Username), "username valid")
// 	assert.NotNil(t, turnAuth.Password, "password nil")
// 	passwd, err = a12n.GetLongTermCredential(*turnAuth.Username, "my-secret")
// 	assert.NoError(t, err, "GetLongTermCredential")
// 	assert.Equal(t, passwd, *turnAuth.Password, "password ok")
// 	assert.NotNil(t, turnAuth.Uris, "URIs nil")
// 	uris = *turnAuth.Uris
// 	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
// 	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
// 	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
// 	assert.Contains(t, uris, "turns:4.3.2.1:12345?transport=udp", "DTLS URI")

// 	key, ok = authHandler(*turnAuth.Username, stnrv1.DefaultRealm,
// 		&net.UDPAddr{IP: net.ParseIP("4.3.2.1"), Port: 12345})
// 	assert.True(t, ok, "authHandler ok")
// 	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
// 		stnrv1.DefaultRealm, *turnAuth.Password), "auth handler ok")

// 	log.Debug("--------------------------------------")
// 	log.Debug("editing config file: changing the proto for a listener")
// 	watchTestConfig.Listeners[1].Protocol = "udp"

// 	data, err = json.MarshalIndent(watchTestConfig, "", "  ")
// 	assert.NoError(t, err, "JSONify config file")

// 	assert.NoError(t, f.Truncate(0), "truncate temp file")
// 	_, err = f.Seek(0, 0)
// 	assert.NoError(t, err, "seek temp file")
// 	_, err = f.Write(data)
// 	assert.NoError(t, err, "writing JSON config file")

// 	// let STUNner pick up the config -- will cause a restart!
// 	err = s.Reconcile(watchTestConfig)
// 	_, ok = err.(stnrv1.ErrRestarted)
// 	assert.True(t, ok, "reconcile")

// 	// wait so that the auth-server has comfortable time to pick up the new config
// 	time.Sleep(time.Duration(100) * time.Millisecond)

// 	u = "dummy"
// 	param = client.GetTurnAuthParams{Username: &u}
// 	turnAuth, err = authClient.GetTurnAuthToken(ctx, &param)
// 	assert.NoError(t, err, "TURN auth get")

// 	assert.NotNil(t, turnAuth, "TURN token nil")
// 	assert.NotNil(t, turnAuth.Username, "username nil")
// 	// we do not know the username, only that it contains the timestamps plus a colon
// 	assert.Regexp(t, regexp.MustCompile(`^\d+:dummy$`), *turnAuth.Username, "username ok")
// 	assert.NoError(t, a12n.CheckTimeWindowedUsername(*turnAuth.Username), "username valid")
// 	assert.NotNil(t, turnAuth.Password, "password nil")
// 	passwd, err = a12n.GetLongTermCredential(*turnAuth.Username, "my-secret")
// 	assert.NoError(t, err, "GetLongTermCredential")
// 	assert.Equal(t, passwd, *turnAuth.Password, "password ok")
// 	assert.NotNil(t, turnAuth.Uris, "URIs nil")
// 	uris = *turnAuth.Uris
// 	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
// 	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "TCP URI")
// 	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
// 	assert.Contains(t, uris, "turns:4.3.2.1:12345?transport=udp", "DTLS URI")

// 	key, ok = authHandler(*turnAuth.Username, stnrv1.DefaultRealm,
// 		&net.UDPAddr{IP: net.ParseIP("4.3.2.1"), Port: 12345})
// 	assert.True(t, ok, "authHandler ok")
// 	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
// 		stnrv1.DefaultRealm, *turnAuth.Password), "auth handler ok")
// }
