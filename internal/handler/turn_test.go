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
	stnrv1a1 "github.com/l7mp/stunner/pkg/apis/v1alpha1"
	a12n "github.com/l7mp/stunner/pkg/authentication"

	"github.com/l7mp/stunner-auth-service/internal/store"
	// "github.com/l7mp/stunner-auth-service/pkg/client"
	"github.com/l7mp/stunner-auth-service/pkg/server"
	"github.com/l7mp/stunner-auth-service/pkg/types"
)

type turnAuthTestCase struct {
	name   string
	config []*stnrv1a1.StunnerConfig
	params string
	status int
	tester func(t *testing.T, turnAuth *types.TurnAuthenticationToken, s a12n.AuthHandler)
}

var turnAuthTestCases = []turnAuthTestCase{
	{
		name:   "empty config",
		config: []*stnrv1a1.StunnerConfig{},
		params: "service=turn",
		status: http.StatusInternalServerError,
		tester: func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {},
	},
	{
		name:   "plaintext",
		config: []*stnrv1a1.StunnerConfig{&plaintextAuthConfig},
		params: "service=turn",
		status: 200,
		tester: func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuth, "TURN token nil")
			assert.NotNil(t, turnAuth.Username, "username nil")
			assert.Equal(t, "user1", *turnAuth.Username, "username nil")
			assert.NotNil(t, turnAuth.Password, "password nil")
			assert.Equal(t, "pass1", *turnAuth.Password, "password ok")
			assert.NotNil(t, turnAuth.Ttl, "ttl nil")
			assert.Equal(t, int64(86400), *turnAuth.Ttl, "ttl ok")
			assert.NotNil(t, turnAuth.Uris, "URIs nil")
			uris := *turnAuth.Uris
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

			key, ok := authHandler(*turnAuth.Username, stnrv1a1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
				stnrv1a1.DefaultRealm, *turnAuth.Password), "auth handler ok")

		},
	},
	{
		name:   "plaintext - wring service",
		config: []*stnrv1a1.StunnerConfig{&plaintextAuthConfig},
		params: "service=dummy",
		status: http.StatusBadRequest,
		tester: func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {},
	},
	{
		name:   "plaintext - username set",
		config: []*stnrv1a1.StunnerConfig{&plaintextAuthConfig},
		params: "service=turn&username=dummy",
		status: 200,
		tester: func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuth, "TURN token nil")
			assert.NotNil(t, turnAuth.Username, "username nil")
			assert.Equal(t, "user1", *turnAuth.Username, "username nil")
			assert.NotNil(t, turnAuth.Password, "password nil")
			assert.Equal(t, "pass1", *turnAuth.Password, "password ok")
			assert.NotNil(t, turnAuth.Ttl, "ttl nil")
			assert.Equal(t, int64(86400), *turnAuth.Ttl, "ttl ok")
			assert.NotNil(t, turnAuth.Uris, "URIs nil")
			uris := *turnAuth.Uris
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

			key, ok := authHandler(*turnAuth.Username, stnrv1a1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
				stnrv1a1.DefaultRealm, *turnAuth.Password), "auth handler ok")
		},
	},
	{
		name:   "plaintext - ttl set",
		config: []*stnrv1a1.StunnerConfig{&plaintextAuthConfig},
		params: "service=turn&ttl=1",
		status: 200,
		tester: func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuth, "TURN token nil")
			assert.NotNil(t, turnAuth.Username, "username nil")
			assert.Equal(t, "user1", *turnAuth.Username, "username nil")
			assert.NotNil(t, turnAuth.Password, "password nil")
			assert.Equal(t, "pass1", *turnAuth.Password, "password ok")
			assert.NotNil(t, turnAuth.Ttl, "ttl nil")
			assert.Equal(t, int64(1), *turnAuth.Ttl, "ttl ok")
			assert.NotNil(t, turnAuth.Uris, "URIs nil")
			uris := *turnAuth.Uris
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

			key, ok := authHandler(*turnAuth.Username, stnrv1a1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
				stnrv1a1.DefaultRealm, *turnAuth.Password), "auth handler ok")
		},
	},
	{
		name:   "longterm -- basic",
		config: []*stnrv1a1.StunnerConfig{&longtermAuthConfig},
		params: "service=turn",
		status: 200,
		tester: func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuth, "TURN token nil")
			assert.NotNil(t, turnAuth.Username, "username nil")
			// we do not know the username, only that it contains the timestamps plus a colon
			assert.Regexp(t, regexp.MustCompile(`^\d+:$`), *turnAuth.Username, "username ok")
			assert.NoError(t, a12n.CheckTimeWindowedUsername(*turnAuth.Username), "username valid")
			assert.NotNil(t, turnAuth.Password, "password nil")
			passwd, err := a12n.GetLongTermCredential(*turnAuth.Username, "my-secret")
			assert.NoError(t, err, "GetLongTermCredential")
			assert.Equal(t, passwd, *turnAuth.Password, "password ok")
			assert.NotNil(t, turnAuth.Uris, "URIs nil")
			uris := *turnAuth.Uris
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")

			key, ok := authHandler(*turnAuth.Username, stnrv1a1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 1234})
			assert.True(t, ok, "authHandler ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
				stnrv1a1.DefaultRealm, *turnAuth.Password), "auth handler ok")
		},
	},
	{
		name:   "longterm -- dummy service",
		config: []*stnrv1a1.StunnerConfig{&longtermAuthConfig},
		params: "service=dummy",
		status: 400,
		tester: func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {},
	},
	{
		name:   "longterm -- username set",
		config: []*stnrv1a1.StunnerConfig{&longtermAuthConfig},
		params: "service=turn&username=dummy",
		status: 200,
		tester: func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuth, "TURN token nil")
			assert.NotNil(t, turnAuth.Username, "username nil")
			// we do not know the username, only that it contains the timestamps plus a colon
			assert.Regexp(t, regexp.MustCompile(`^\d+:dummy$`), *turnAuth.Username, "username ok")
			assert.NoError(t, a12n.CheckTimeWindowedUsername(*turnAuth.Username), "username valid")
			assert.NotNil(t, turnAuth.Password, "password nil")
			passwd, err := a12n.GetLongTermCredential(*turnAuth.Username, "my-secret")
			assert.NoError(t, err, "GetLongTermCredential")
			assert.Equal(t, passwd, *turnAuth.Password, "password ok")
			assert.NotNil(t, turnAuth.Uris, "URIs nil")
			uris := *turnAuth.Uris
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")

			key, ok := authHandler(*turnAuth.Username, stnrv1a1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 1234})
			assert.True(t, ok, "authHandler ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
				stnrv1a1.DefaultRealm, *turnAuth.Password), "auth handler ok")
		},
	},
	{
		name:   "longterm -- ttl set",
		config: []*stnrv1a1.StunnerConfig{&longtermAuthConfig},
		params: "service=turn&username=dummy&ttl=1",
		status: 200,
		tester: func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			// try to invalidate stuff
			// we must wait for the token to expire
			time.Sleep(time.Duration(2) * time.Second)

			assert.NotNil(t, turnAuth, "TURN token nil")
			assert.NotNil(t, turnAuth.Username, "username nil")
			// we do not know the username, only that it contains the timestamps plus a colon
			assert.Regexp(t, regexp.MustCompile(`^\d+:dummy$`), *turnAuth.Username, "username ok")
			assert.Error(t, a12n.CheckTimeWindowedUsername(*turnAuth.Username), "username invalid")
			assert.NotNil(t, turnAuth.Uris, "URIs nil")
			uris := *turnAuth.Uris
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")

			_, ok := authHandler(*turnAuth.Username, stnrv1a1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 1234})
			assert.False(t, ok, "authHandler errs")
		},
	},
	// gateway filters
	{
		name:   "plaintext - single config, namespace filter",
		config: []*stnrv1a1.StunnerConfig{&plaintextAuthConfig},
		params: "service=turn&namespace=testnamespace",
		status: 200,
		tester: func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuth, "TURN token nil")
			assert.NotNil(t, turnAuth.Username, "username nil")
			assert.Equal(t, "user1", *turnAuth.Username, "username nil")
			assert.NotNil(t, turnAuth.Password, "password nil")
			assert.Equal(t, "pass1", *turnAuth.Password, "password ok")
			assert.NotNil(t, turnAuth.Ttl, "ttl nil")
			assert.Equal(t, int64(86400), *turnAuth.Ttl, "ttl ok")
			assert.NotNil(t, turnAuth.Uris, "URIs nil")
			uris := *turnAuth.Uris
			assert.Len(t, uris, 3, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

			key, ok := authHandler(*turnAuth.Username, stnrv1a1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
				stnrv1a1.DefaultRealm, *turnAuth.Password), "auth handler ok")
		},
	},
	{
		name:   "plaintext - single config, gateway filter",
		config: []*stnrv1a1.StunnerConfig{&plaintextAuthConfig},
		params: "service=turn&namespace=testnamespace&gateway=testgateway",
		status: 200,
		tester: func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuth, "TURN token nil")
			assert.NotNil(t, turnAuth.Username, "username nil")
			assert.Equal(t, "user1", *turnAuth.Username, "username nil")
			assert.NotNil(t, turnAuth.Password, "password nil")
			assert.Equal(t, "pass1", *turnAuth.Password, "password ok")
			assert.NotNil(t, turnAuth.Ttl, "ttl nil")
			assert.Equal(t, int64(86400), *turnAuth.Ttl, "ttl ok")
			assert.NotNil(t, turnAuth.Uris, "URIs nil")
			uris := *turnAuth.Uris
			assert.Len(t, uris, 2, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

			key, ok := authHandler(*turnAuth.Username, stnrv1a1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
				stnrv1a1.DefaultRealm, *turnAuth.Password), "auth handler ok")
		},
	},
	{
		name:   "plaintext - single config, listener filter",
		config: []*stnrv1a1.StunnerConfig{&plaintextAuthConfig},
		params: "service=turn&namespace=testnamespace&gateway=testgateway&listener=udp",
		status: 200,
		tester: func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuth, "TURN token nil")
			assert.NotNil(t, turnAuth.Username, "username nil")
			assert.Equal(t, "user1", *turnAuth.Username, "username nil")
			assert.NotNil(t, turnAuth.Password, "password nil")
			assert.Equal(t, "pass1", *turnAuth.Password, "password ok")
			assert.NotNil(t, turnAuth.Ttl, "ttl nil")
			assert.Equal(t, int64(86400), *turnAuth.Ttl, "ttl ok")
			assert.NotNil(t, turnAuth.Uris, "URIs nil")
			uris := *turnAuth.Uris
			assert.Len(t, uris, 1, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")

			key, ok := authHandler(*turnAuth.Username, stnrv1a1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
				stnrv1a1.DefaultRealm, *turnAuth.Password), "auth handler ok")
		},
	},
	{
		name:   "plaintext - single config, restrictive filter, no result errs",
		config: []*stnrv1a1.StunnerConfig{&plaintextAuthConfig},
		params: "service=turn&namespace=testnamespace&listener=dummy&gateway=testgateway",
		status: 404,
		tester: func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {},
	},
	{
		name:   "plaintext - multiple configs, namespace filter",
		config: []*stnrv1a1.StunnerConfig{&plaintextAuthConfig, &longtermAuthConfig},
		params: "service=turn&namespace=testnamespace",
		status: 200,
		tester: func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuth, "TURN token nil")
			assert.NotNil(t, turnAuth.Username, "username nil")
			if *turnAuth.Username == "user1" {
				// plaintext
				assert.Equal(t, "user1", *turnAuth.Username, "username nil")
				assert.NotNil(t, turnAuth.Password, "password nil")
				assert.Equal(t, "pass1", *turnAuth.Password, "password ok")
				assert.NotNil(t, turnAuth.Ttl, "ttl nil")
				assert.Equal(t, int64(86400), *turnAuth.Ttl, "ttl ok")
				assert.NotNil(t, turnAuth.Uris, "URIs nil")
				uris := *turnAuth.Uris
				assert.Len(t, uris, 3, "URI len")
				assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
				assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
				assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")
			} else {
				// longterm
				assert.Regexp(t, regexp.MustCompile(`^\d+:$`), *turnAuth.Username, "username ok")
				assert.NoError(t, a12n.CheckTimeWindowedUsername(*turnAuth.Username), "username valid")
				assert.NotNil(t, turnAuth.Password, "password nil")
				passwd, err := a12n.GetLongTermCredential(*turnAuth.Username, "my-secret")
				assert.NoError(t, err, "GetLongTermCredential")
				assert.Equal(t, passwd, *turnAuth.Password, "password ok")
				assert.NotNil(t, turnAuth.Uris, "URIs nil")
				uris := *turnAuth.Uris
				assert.Len(t, uris, 3, "URI len")
				assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
				assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=tcp", "TLS URI")
				assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")
			}
			key, ok := authHandler(*turnAuth.Username, stnrv1a1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
				stnrv1a1.DefaultRealm, *turnAuth.Password), "auth handler ok")
		},
	},
	{
		name:   "plaintext - multiple configs, gateway filter",
		config: []*stnrv1a1.StunnerConfig{&plaintextAuthConfig, &longtermAuthConfig},
		params: "service=turn&namespace=testnamespace&gateway=testgateway",
		status: 200,
		tester: func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuth, "TURN token nil")
			assert.NotNil(t, turnAuth.Username, "username nil")
			if *turnAuth.Username == "user1" {
				// plaintext
				assert.Equal(t, "user1", *turnAuth.Username, "username nil")
				assert.NotNil(t, turnAuth.Password, "password nil")
				assert.Equal(t, "pass1", *turnAuth.Password, "password ok")
				assert.NotNil(t, turnAuth.Ttl, "ttl nil")
				assert.Equal(t, int64(86400), *turnAuth.Ttl, "ttl ok")
				assert.NotNil(t, turnAuth.Uris, "URIs nil")
				uris := *turnAuth.Uris
				assert.Len(t, uris, 2, "URI len")
				assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
				assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")
			} else {
				// longterm
				assert.Regexp(t, regexp.MustCompile(`^\d+:$`), *turnAuth.Username, "username ok")
				assert.NoError(t, a12n.CheckTimeWindowedUsername(*turnAuth.Username), "username valid")
				assert.NotNil(t, turnAuth.Password, "password nil")
				passwd, err := a12n.GetLongTermCredential(*turnAuth.Username, "my-secret")
				assert.NoError(t, err, "GetLongTermCredential")
				assert.Equal(t, passwd, *turnAuth.Password, "password ok")
				assert.NotNil(t, turnAuth.Uris, "URIs nil")
				uris := *turnAuth.Uris
				assert.Len(t, uris, 2, "URI len")
				assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
				assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")
			}

			key, ok := authHandler(*turnAuth.Username, stnrv1a1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
				stnrv1a1.DefaultRealm, *turnAuth.Password), "auth handler ok")
		},
	},
	{
		name:   "plaintext - multiple configs, listener filter",
		config: []*stnrv1a1.StunnerConfig{&plaintextAuthConfig, &longtermAuthConfig},
		params: "service=turn&namespace=testnamespace&gateway=testgateway&listener=udp",
		status: 200,
		tester: func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuth, "TURN token nil")
			assert.NotNil(t, turnAuth.Username, "username nil")
			if *turnAuth.Username == "user1" {
				// plaintext
				assert.Equal(t, "user1", *turnAuth.Username, "username nil")
				assert.NotNil(t, turnAuth.Password, "password nil")
				assert.Equal(t, "pass1", *turnAuth.Password, "password ok")
				assert.NotNil(t, turnAuth.Ttl, "ttl nil")
				assert.Equal(t, int64(86400), *turnAuth.Ttl, "ttl ok")
				assert.NotNil(t, turnAuth.Uris, "URIs nil")
				uris := *turnAuth.Uris
				assert.Len(t, uris, 1, "URI len")
				assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			} else {
				// longterm
				assert.Regexp(t, regexp.MustCompile(`^\d+:$`), *turnAuth.Username, "username ok")
				assert.NoError(t, a12n.CheckTimeWindowedUsername(*turnAuth.Username), "username valid")
				assert.NotNil(t, turnAuth.Password, "password nil")
				passwd, err := a12n.GetLongTermCredential(*turnAuth.Username, "my-secret")
				assert.NoError(t, err, "GetLongTermCredential")
				assert.Equal(t, passwd, *turnAuth.Password, "password ok")
				assert.NotNil(t, turnAuth.Uris, "URIs nil")
				uris := *turnAuth.Uris
				assert.Len(t, uris, 1, "URI len")
				assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
			}

			key, ok := authHandler(*turnAuth.Username, stnrv1a1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
				stnrv1a1.DefaultRealm, *turnAuth.Password), "auth handler ok")
		},
	},
	{
		name:   "plaintext - multiple configs, restrictive filter, no result errs",
		config: []*stnrv1a1.StunnerConfig{&plaintextAuthConfig},
		params: "service=turn&namespace=testnamespace&listener=dummy&gateway=testgateway",
		status: 404,
		tester: func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {},
	},
}

func TestTURNAuth(t *testing.T) { testTURN(t, turnAuthTestCases) }

func testTURN(t *testing.T, tests []turnAuthTestCase) {
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

		log.Info("storing config file")
		store.ConfigMaps.Reset(testCase.config)

		// we do not use the Stunner auth handler for multi-config tests: no need to reconcile
		if len(testCase.config) == 1 {
			assert.NoError(t, s.Reconcile(*testCase.config[0]), "starting server")
		}

		// wait so that the auth-server has comfortable time to start
		time.Sleep(time.Duration(5) * time.Millisecond)

		log.Info("calling TURN auth handler")
		url := fmt.Sprintf("http://example.com/?%s", testCase.params)
		req := httptest.NewRequest("GET", url, nil)
		w := httptest.NewRecorder()
		serv.GetTurnAuth(w, req)

		log.Info("testing results")
		resp := w.Result()
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err, "read body")

		assert.Equal(t, testCase.status, resp.StatusCode, "HTTP status")

		turnAuth := types.TurnAuthenticationToken{}
		if testCase.status == 200 {
			assert.Equal(t, "application/json; charset=UTF-8", resp.Header.Get("Content-Type"), "HTTP Content-Type")
			assert.NoError(t, json.Unmarshal(body, &turnAuth))
		}
		testCase.tester(t, &turnAuth, authHandler)
	}
}
