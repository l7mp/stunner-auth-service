package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/pion/transport/v2/test"
	"github.com/stretchr/testify/assert"

	"github.com/l7mp/stunner"
	"github.com/l7mp/stunner/pkg/apis/v1alpha1"
	a12n "github.com/l7mp/stunner/pkg/authentication"
	"github.com/l7mp/stunner/pkg/logger"

	"github.com/l7mp/stunner-auth-service/internal/handler"
	"github.com/l7mp/stunner-auth-service/pkg/client"
	"github.com/l7mp/stunner-auth-service/pkg/server"
	"github.com/l7mp/stunner-auth-service/pkg/types"
)

var _ = fmt.Sprintf("%d", 1)

var authTestLoglevel string = "all:ERROR"

//var authTestLoglevel string = "all:TRACE"

// so that the TLS tests run
var certPem, keyPem, _ = stunner.GenerateSelfSignedKey()
var certPem64 = base64.StdEncoding.EncodeToString(certPem)
var keyPem64 = base64.StdEncoding.EncodeToString(keyPem)

// type authTestCase struct {
// 	stunnerConfig v1alpha1.StunnerConfig
// 	turnAuthToken types.TurnAuthenticationToken
// 	iceConfig     types.IceConfig
// }

// var authTestCases = []authTestCase{}

var basicAuthTestConfig = v1alpha1.StunnerConfig{
	ApiVersion: "v1alpha1",
	Admin: v1alpha1.AdminConfig{
		Name:     "stunnerd",
		LogLevel: authTestLoglevel,
	},
	Auth: v1alpha1.AuthConfig{
		Type:  "plaintext",
		Realm: "",
		Credentials: map[string]string{
			"username": "user1",
			"password": "pass1",
		}},
	Listeners: []v1alpha1.ListenerConfig{
		{
			Name:       "stunnerd-udp",
			Protocol:   "udp",
			PublicAddr: "1.2.3.4",
			PublicPort: 3478,
			Addr:       "127.0.0.1",
			Port:       23478,
			Routes:     []string{},
		}, {
			Name:       "stunnerd-tcp",
			Protocol:   "tcp",
			PublicAddr: "1.2.3.4",
			PublicPort: 3478,
			Addr:       "127.0.0.1",
			Port:       3478,
			Routes:     []string{},
		}, {
			Name:       "stunnerd-tls",
			Protocol:   "tls",
			PublicAddr: "",
			PublicPort: 0,
			Addr:       "127.0.0.1",
			Port:       3479,
			Cert:       certPem64,
			Key:        keyPem64,
			Routes:     []string{},
		}, {
			Name:       "stunnerd-dtls",
			Protocol:   "dtls",
			PublicAddr: "",
			PublicPort: 0,
			Addr:       "127.0.0.1",
			Port:       3479,
			Cert:       certPem64,
			Key:        keyPem64,
			Routes:     []string{},
		},
	},
	Clusters: []v1alpha1.ClusterConfig{},
}

func TestPlaintextAuth(t *testing.T) {
	lim := test.TimeOut(time.Second * 120)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	loggerFactory := logger.NewLoggerFactory(authTestLoglevel)
	log := loggerFactory.NewLogger("test-plaintext")

	log.Debug("writing config file")
	f, err := os.CreateTemp("", "stunner_conf_*.yaml")
	assert.NoError(t, err, "creating temp config file")
	defer os.Remove(f.Name())

	data, err := json.MarshalIndent(basicAuthTestConfig, "", "  ")
	assert.NoError(t, err, "JSONify config file")

	_, err = f.Write(data)
	assert.NoError(t, err, "writing JSON config file")

	log.Debug("starting auth server")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler, err := handler.NewHandler(ctx, f.Name(), authTestLoglevel, false)
	assert.NoError(t, err, "create handler")

	router := server.HandlerWithOptions(handler, server.GorillaServerOptions{})
	httpServer := &http.Server{Addr: ":18088", Handler: router}
	defer httpServer.Close()

	go func() { _ = httpServer.ListenAndServe() }()

	log.Debug("starting auth client")
	authClient, err := client.NewClient("http://:18088")
	assert.NoError(t, err, "new client")

	// starting a Stunner instance to use its authenticator
	log.Debug("creating a stunnerd")
	s := stunner.NewStunner(stunner.Options{
		DryRun:   true,
		LogLevel: authTestLoglevel,
	})
	defer s.Close()
	assert.NoError(t, s.Reconcile(basicAuthTestConfig), "starting server")
	authHandler := s.NewAuthHandler()

	// wait so that the auth-server has comfortable time to start
	time.Sleep(time.Duration(50) * time.Millisecond)

	log.Debug("testing basic TURN auth")
	param := client.GetTurnAuthParams{}
	turnAuth, err := authClient.GetTurnAuthToken(ctx, &param)
	assert.NoError(t, err, "TURN auth get")

	assert.NotNil(t, turnAuth, "TURN token nil")
	assert.NotNil(t, turnAuth.Username, "username nil")
	assert.Equal(t, "user1", *turnAuth.Username, "username nil")
	assert.NotNil(t, turnAuth.Password, "password nil")
	assert.Equal(t, "pass1", *turnAuth.Password, "password ok")
	assert.NotNil(t, turnAuth.Ttl, "ttl nil")
	assert.Equal(t, int64(86400), *turnAuth.Ttl, "ttl ok")
	assert.NotNil(t, turnAuth.Uris, "URIs nil")
	uris := *turnAuth.Uris
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

	key, ok := authHandler(*turnAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler key ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
		v1alpha1.DefaultRealm, *turnAuth.Password), "auth handler ok")

	log.Debug("testing TURN auth with service set")
	param = client.GetTurnAuthParams{Service: types.GetTurnAuthParamsServiceTurn}
	turnAuth, err = authClient.GetTurnAuthToken(ctx, &param)
	assert.NoError(t, err, "TURN auth get")

	assert.NotNil(t, turnAuth, "TURN token nil")
	assert.NotNil(t, turnAuth.Username, "username nil")
	assert.Equal(t, "user1", *turnAuth.Username, "username nil")
	assert.NotNil(t, turnAuth.Password, "password nil")
	assert.Equal(t, "pass1", *turnAuth.Password, "password ok")
	assert.NotNil(t, turnAuth.Ttl, "ttl nil")
	assert.Equal(t, int64(86400), *turnAuth.Ttl, "ttl ok")
	assert.NotNil(t, turnAuth.Uris, "URIs nil")
	uris = *turnAuth.Uris
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

	key, ok = authHandler(*turnAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler key ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
		v1alpha1.DefaultRealm, *turnAuth.Password), "auth handler ok")

	log.Debug("testing TURN auth with wrong service")
	param = client.GetTurnAuthParams{Service: client.GetTurnAuthParamsService("dummy")}
	_, err = authClient.GetTurnAuthToken(ctx, &param)
	assert.Error(t, err, "TURN error")

	// useless: no username override in plaintext mode!
	log.Debug("testing TURN auth with username set")
	u := "dummy"
	param = client.GetTurnAuthParams{Username: &u}
	turnAuth, err = authClient.GetTurnAuthToken(ctx, &param)
	assert.NoError(t, err, "TURN auth get")

	assert.NotNil(t, turnAuth, "TURN token nil")
	assert.NotNil(t, turnAuth.Username, "username nil")
	assert.Equal(t, "user1", *turnAuth.Username, "username nil")
	assert.NotNil(t, turnAuth.Password, "password nil")
	assert.Equal(t, "pass1", *turnAuth.Password, "password ok")
	assert.NotNil(t, turnAuth.Ttl, "ttl nil")
	assert.Equal(t, int64(86400), *turnAuth.Ttl, "ttl ok")
	assert.NotNil(t, turnAuth.Uris, "URIs nil")
	uris = *turnAuth.Uris
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

	key, ok = authHandler(*turnAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler key ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
		v1alpha1.DefaultRealm, *turnAuth.Password), "auth handler ok")

	log.Debug("testing TURN auth with ttl set")
	var ttl int = 1
	param = client.GetTurnAuthParams{Ttl: &ttl}
	turnAuth, err = authClient.GetTurnAuthToken(ctx, &param)
	assert.NoError(t, err, "TURN auth get")

	assert.NotNil(t, turnAuth, "TURN token nil")
	assert.NotNil(t, turnAuth.Username, "username nil")
	assert.Equal(t, "user1", *turnAuth.Username, "username nil")
	assert.NotNil(t, turnAuth.Password, "password nil")
	assert.Equal(t, "pass1", *turnAuth.Password, "password ok")
	assert.NotNil(t, turnAuth.Ttl, "ttl nil")
	assert.Equal(t, int64(1), *turnAuth.Ttl, "ttl ok")
	assert.NotNil(t, turnAuth.Uris, "URIs nil")
	uris = *turnAuth.Uris
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

	key, ok = authHandler(*turnAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler key ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
		v1alpha1.DefaultRealm, *turnAuth.Password), "auth handler ok")

	// fmt.Printf("%#v\n", err.Error())
	// fmt.Printf("%s\n", err.Error())

	log.Debug("testing basic ICE config")
	param2 := client.GetIceAuthParams{}
	iceConfig, err := authClient.GetIceConfig(ctx, &param2)
	assert.NoError(t, err, "ICE config get")

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
	uris = *iceAuth.Urls
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

	key, ok = authHandler(*iceAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler key ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*iceAuth.Username,
		v1alpha1.DefaultRealm, *iceAuth.Credential), "auth handler ok")

	log.Debug("testing ICE config")
	param2 = client.GetIceAuthParams{}
	iceConfig, err = authClient.GetIceConfig(ctx, &param2)
	assert.NoError(t, err, "ICE config get")

	assert.NotNil(t, iceConfig, "ICE config nil")
	assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
	iceServers = *iceConfig.IceServers
	assert.Len(t, iceServers, 1, "ICE servers len")
	iceAuth = iceServers[0]
	assert.NotNil(t, iceAuth, "ICE auth token nil")
	assert.NotNil(t, iceAuth.Username, "username nil")
	assert.Equal(t, "user1", *iceAuth.Username, "username nil")
	assert.NotNil(t, iceAuth.Credential, "credential nil")
	assert.Equal(t, "pass1", *iceAuth.Credential, "credential ok")
	assert.NotNil(t, iceAuth.Urls, "URLs nil")
	uris = *iceAuth.Urls
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

	key, ok = authHandler(*iceAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler key ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*iceAuth.Username,
		v1alpha1.DefaultRealm, *iceAuth.Credential), "auth handler ok")

	log.Debug("testing ICE config with service set")
	svc := types.GetIceAuthParamsServiceTurn
	param2 = client.GetIceAuthParams{Service: &svc}
	iceConfig, err = authClient.GetIceConfig(ctx, &param2)
	assert.NoError(t, err, "ICE config get")

	assert.NotNil(t, iceConfig, "ICE config nil")
	assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
	iceServers = *iceConfig.IceServers
	assert.Len(t, iceServers, 1, "ICE servers len")
	iceAuth = iceServers[0]
	assert.NotNil(t, iceAuth, "ICE auth token nil")
	assert.NotNil(t, iceAuth.Username, "username nil")
	assert.Equal(t, "user1", *iceAuth.Username, "username nil")
	assert.NotNil(t, iceAuth.Credential, "credential nil")
	assert.Equal(t, "pass1", *iceAuth.Credential, "credential ok")
	assert.NotNil(t, iceAuth.Urls, "URLs nil")
	uris = *iceAuth.Urls
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

	key, ok = authHandler(*iceAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler key ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*iceAuth.Username,
		v1alpha1.DefaultRealm, *iceAuth.Credential), "auth handler ok")

	log.Debug("testing ICE config with wrong service")
	svc = types.GetIceAuthParamsService("dummy")
	param2 = client.GetIceAuthParams{Service: &svc}
	_, err = authClient.GetIceConfig(ctx, &param2)
	assert.Error(t, err, "ICE config get fails")

	// useless: no username override in plaintext mode
	log.Debug("testing ICE config with username set")
	u = "dummy"
	param2 = client.GetIceAuthParams{Username: &u}
	iceConfig, err = authClient.GetIceConfig(ctx, &param2)
	assert.NoError(t, err, "ICE config get")

	assert.NotNil(t, iceConfig, "ICE config nil")
	assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
	iceServers = *iceConfig.IceServers
	assert.Len(t, iceServers, 1, "ICE servers len")
	iceAuth = iceServers[0]
	assert.NotNil(t, iceAuth, "ICE auth token nil")
	assert.NotNil(t, iceAuth.Username, "username nil")
	assert.Equal(t, "user1", *iceAuth.Username, "username nil")
	assert.NotNil(t, iceAuth.Credential, "credential nil")
	assert.Equal(t, "pass1", *iceAuth.Credential, "credential ok")
	assert.NotNil(t, iceAuth.Urls, "URLs nil")
	uris = *iceAuth.Urls
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

	key, ok = authHandler(*iceAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler key ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*iceAuth.Username,
		v1alpha1.DefaultRealm, *iceAuth.Credential), "auth handler ok")

	// useless: no ttl in response
	log.Debug("testing ICE config with ttl set")
	ttl = 1
	param2 = client.GetIceAuthParams{Ttl: &ttl}
	iceConfig, err = authClient.GetIceConfig(ctx, &param2)
	assert.NoError(t, err, "ICE config get")

	assert.NotNil(t, iceConfig, "ICE config nil")
	assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
	iceServers = *iceConfig.IceServers
	assert.Len(t, iceServers, 1, "ICE servers len")
	iceAuth = iceServers[0]
	assert.NotNil(t, iceAuth, "ICE auth token nil")
	assert.NotNil(t, iceAuth.Username, "username nil")
	assert.Equal(t, "user1", *iceAuth.Username, "username nil")
	assert.NotNil(t, iceAuth.Credential, "credential nil")
	assert.Equal(t, "pass1", *iceAuth.Credential, "credential ok")
	assert.NotNil(t, iceAuth.Urls, "URLs nil")
	uris = *iceAuth.Urls
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

	key, ok = authHandler(*iceAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler key ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*iceAuth.Username,
		v1alpha1.DefaultRealm, *iceAuth.Credential), "auth handler ok")
}

func TestLongtermAuth(t *testing.T) {
	lim := test.TimeOut(time.Second * 120)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	loggerFactory := logger.NewLoggerFactory(authTestLoglevel)
	log := loggerFactory.NewLogger("test-longterm")

	log.Debug("writing config file")
	f, err := os.CreateTemp("", "stunner_conf_*.yaml")
	assert.NoError(t, err, "creating temp config file")
	defer os.Remove(f.Name())

	longtermAuthTestConfig := v1alpha1.StunnerConfig{}
	basicAuthTestConfig.DeepCopyInto(&longtermAuthTestConfig)

	// overwrite auth
	longtermAuthTestConfig.Auth = v1alpha1.AuthConfig{
		Type: "longterm",
		Credentials: map[string]string{
			"secret": "my-secret",
		},
	}

	data, err := json.MarshalIndent(longtermAuthTestConfig, "", "  ")
	assert.NoError(t, err, "JSONify config file")

	_, err = f.Write(data)
	assert.NoError(t, err, "writing JSON config file")

	log.Debug("starting auth server")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	handler, err := handler.NewHandler(ctx, f.Name(), authTestLoglevel, false)
	assert.NoError(t, err, "create handler")

	router := server.HandlerWithOptions(handler, server.GorillaServerOptions{})
	httpServer := &http.Server{Addr: ":18088", Handler: router}
	defer httpServer.Close()

	go func() { _ = httpServer.ListenAndServe() }()

	log.Debug("starting auth client")
	authClient, err := client.NewClient("http://:18088")
	assert.NoError(t, err, "new client")

	// starting a Stunner instance to use its authenticator
	log.Debug("creating a stunnerd")
	s := stunner.NewStunner(stunner.Options{
		DryRun:   true,
		LogLevel: authTestLoglevel,
	})
	defer s.Close()
	assert.NoError(t, s.Reconcile(longtermAuthTestConfig), "starting server")
	authHandler := s.NewAuthHandler()

	// wait so that the auth-server has comfortable time to start
	time.Sleep(time.Duration(50) * time.Millisecond)

	log.Debug("testing basic TURN auth")
	param := client.GetTurnAuthParams{}
	turnAuth, err := authClient.GetTurnAuthToken(ctx, &param)
	assert.NoError(t, err, "TURN auth get")

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
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

	key, ok := authHandler(*turnAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
		v1alpha1.DefaultRealm, *turnAuth.Password), "auth handler ok")

	log.Debug("testing TURN auth with username set")
	u := "dummy"
	param = client.GetTurnAuthParams{Username: &u}
	turnAuth, err = authClient.GetTurnAuthToken(ctx, &param)
	assert.NoError(t, err, "TURN auth get")

	assert.NotNil(t, turnAuth, "TURN token nil")
	assert.NotNil(t, turnAuth.Username, "username nil")
	// we do not know the username, only that it contains the timestamps plus a colon
	assert.Regexp(t, regexp.MustCompile(`^\d+:dummy$`), *turnAuth.Username, "username ok")
	assert.NoError(t, a12n.CheckTimeWindowedUsername(*turnAuth.Username), "username valid")
	assert.NotNil(t, turnAuth.Password, "password nil")
	passwd, err = a12n.GetLongTermCredential(*turnAuth.Username, "my-secret")
	assert.NoError(t, err, "GetLongTermCredential")
	assert.Equal(t, passwd, *turnAuth.Password, "password ok")
	assert.NotNil(t, turnAuth.Uris, "URIs nil")
	uris = *turnAuth.Uris
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

	key, ok = authHandler(*turnAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
		v1alpha1.DefaultRealm, *turnAuth.Password), "auth handler ok")

	// try to invalidate stuff
	log.Debug("testing TURN auth with ttl set")
	var ttl int = 0
	param = client.GetTurnAuthParams{Ttl: &ttl, Username: &u}
	turnAuth, err = authClient.GetTurnAuthToken(ctx, &param)
	assert.NoError(t, err, "TURN auth get")

	// we must wait for the token to expire
	time.Sleep(time.Duration(2) * time.Second)

	assert.NotNil(t, turnAuth, "TURN token nil")
	assert.NotNil(t, turnAuth.Username, "username nil")
	// we do not know the username, only that it contains the timestamps plus a colon
	assert.Regexp(t, regexp.MustCompile(`^\d+:dummy$`), *turnAuth.Username, "username ok")
	assert.Error(t, a12n.CheckTimeWindowedUsername(*turnAuth.Username), "username invalid")
	assert.NotNil(t, turnAuth.Uris, "URIs nil")
	uris = *turnAuth.Uris
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

	_, ok = authHandler(*turnAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.False(t, ok, "authHandler errs")

	log.Debug("testing basic ICE config")
	param2 := client.GetIceAuthParams{}
	iceConfig, err := authClient.GetIceConfig(ctx, &param2)
	assert.NoError(t, err, "ICE config get")

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
	passwd, err = a12n.GetLongTermCredential(*iceAuth.Username, "my-secret")
	assert.NoError(t, err, "GetLongTermCredential")
	assert.Equal(t, passwd, *iceAuth.Credential, "credential ok")
	assert.NotNil(t, iceAuth.Urls, "URLs nil")
	uris = *iceAuth.Urls
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

	key, ok = authHandler(*iceAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler key ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*iceAuth.Username,
		v1alpha1.DefaultRealm, *iceAuth.Credential), "auth handler ok")

	log.Debug("testing ICE auth with service set")
	svc := types.GetIceAuthParamsServiceTurn
	param2 = client.GetIceAuthParams{Service: &svc}
	iceConfig, err = authClient.GetIceConfig(ctx, &param2)
	assert.NoError(t, err, "ICE config get")

	assert.NotNil(t, iceConfig, "ICE config nil")
	assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
	iceServers = *iceConfig.IceServers
	assert.Len(t, iceServers, 1, "ICE servers len")
	iceAuth = iceServers[0]
	assert.NotNil(t, iceAuth, "ICE auth token nil")
	assert.NotNil(t, iceAuth.Username, "username nil")
	assert.Regexp(t, regexp.MustCompile(`^\d+:`), *iceAuth.Username, "username ok")
	assert.NoError(t, a12n.CheckTimeWindowedUsername(*iceAuth.Username), "username valid")
	assert.NotNil(t, iceAuth.Credential, "credential nil")
	passwd, err = a12n.GetLongTermCredential(*iceAuth.Username, "my-secret")
	assert.NoError(t, err, "GetLongTermCredential")
	assert.Equal(t, passwd, *iceAuth.Credential, "credential ok")
	assert.NotNil(t, iceAuth.Urls, "URLs nil")
	uris = *iceAuth.Urls
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

	key, ok = authHandler(*iceAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler key ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*iceAuth.Username,
		v1alpha1.DefaultRealm, *iceAuth.Credential), "auth handler ok")

	log.Debug("testing ICE auth with username set")
	u = "dummy"
	param2 = client.GetIceAuthParams{Username: &u}
	iceConfig, err = authClient.GetIceConfig(ctx, &param2)
	assert.NoError(t, err, "ICE config get")

	assert.NotNil(t, iceConfig, "ICE config nil")
	assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
	iceServers = *iceConfig.IceServers
	assert.Len(t, iceServers, 1, "ICE servers len")
	iceAuth = iceServers[0]
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
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

	key, ok = authHandler(*iceAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler key ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*iceAuth.Username,
		v1alpha1.DefaultRealm, *iceAuth.Credential), "auth handler ok")

	log.Debug("testing ICE auth with ttl set")
	ttl = 0
	param2 = client.GetIceAuthParams{Ttl: &ttl, Username: &u}
	iceConfig, err = authClient.GetIceConfig(ctx, &param2)
	assert.NoError(t, err, "ICE config get")

	// we must wait for the token to expire
	time.Sleep(time.Duration(2) * time.Second)

	assert.NotNil(t, iceConfig, "ICE config nil")
	assert.NotNil(t, iceConfig.IceServers, "ICE servers nil")
	iceServers = *iceConfig.IceServers
	assert.Len(t, iceServers, 1, "ICE servers len")
	iceAuth = iceServers[0]
	assert.NotNil(t, iceAuth, "ICE auth token nil")
	assert.NotNil(t, iceAuth.Username, "username nil")
	assert.Regexp(t, regexp.MustCompile(`^\d+:dummy`), *iceAuth.Username, "username ok")
	assert.Error(t, a12n.CheckTimeWindowedUsername(*iceAuth.Username), "username invalid")
	assert.NotNil(t, iceAuth.Credential, "credential nil")
	passwd, err = a12n.GetLongTermCredential(*iceAuth.Username, "my-secret")
	assert.NoError(t, err, "GetLongTermCredential")
	assert.Equal(t, passwd, *iceAuth.Credential, "credential ok")
	assert.NotNil(t, iceAuth.Urls, "URLs nil")
	uris = *iceAuth.Urls
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

	_, ok = authHandler(*iceAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.False(t, ok, "authHandler key ok")
}

func TestWatcher(t *testing.T) {
	lim := test.TimeOut(time.Second * 120)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	loggerFactory := logger.NewLoggerFactory(authTestLoglevel)
	log := loggerFactory.NewLogger("test-watch")

	log.Debug("editing config file")
	watchTestConfig := v1alpha1.StunnerConfig{}
	basicAuthTestConfig.DeepCopyInto(&watchTestConfig)

	// remove the last listener
	watchTestConfig.Listeners =
		watchTestConfig.Listeners[:len(watchTestConfig.Listeners)-1]

	log.Debug("writing config file")
	f, err := os.CreateTemp("", "stunner_conf_*.yaml")
	assert.NoError(t, err, "creating temp config file")
	defer os.Remove(f.Name())

	data, err := json.MarshalIndent(watchTestConfig, "", "  ")
	assert.NoError(t, err, "JSONify config file")

	_, err = f.Write(data)
	assert.NoError(t, err, "writing JSON config file")

	log.Debug("starting auth server")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// set watch=true
	handler, err := handler.NewHandler(ctx, f.Name(), authTestLoglevel, true)
	assert.NoError(t, err, "create handler")

	router := server.HandlerWithOptions(handler, server.GorillaServerOptions{})
	httpServer := &http.Server{Addr: ":18088", Handler: router}
	defer httpServer.Close()

	go func() { _ = httpServer.ListenAndServe() }()

	log.Debug("starting auth client")
	authClient, err := client.NewClient("http://:18088")
	assert.NoError(t, err, "new client")

	// starting a Stunner instance to use its authenticator
	log.Debug("creating a stunnerd")
	s := stunner.NewStunner(stunner.Options{
		DryRun:   true,
		LogLevel: authTestLoglevel,
	})
	defer s.Close()
	assert.NoError(t, s.Reconcile(watchTestConfig), "reconcile")
	authHandler := s.NewAuthHandler()

	// wait so that the auth-server has comfortable time to start
	time.Sleep(time.Duration(50) * time.Millisecond)

	log.Debug("--------------------------------------")
	log.Debug("testing initial TURN auth with username and service set")
	u := "dummy"
	param := client.GetTurnAuthParams{Service: types.GetTurnAuthParamsServiceTurn, Username: &u}
	turnAuth, err := authClient.GetTurnAuthToken(ctx, &param)
	assert.NoError(t, err, "TURN auth get")

	assert.NotNil(t, turnAuth, "TURN token nil")
	assert.NotNil(t, turnAuth.Username, "username nil")
	// cannot override username for plaintext
	assert.Equal(t, "user1", *turnAuth.Username, "username nil")
	assert.NotNil(t, turnAuth.Password, "password nil")
	assert.Equal(t, "pass1", *turnAuth.Password, "password ok")
	assert.NotNil(t, turnAuth.Ttl, "ttl nil")
	assert.Equal(t, int64(86400), *turnAuth.Ttl, "ttl ok")
	assert.NotNil(t, turnAuth.Uris, "URIs nil")
	uris := *turnAuth.Uris
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")

	key, ok := authHandler(*turnAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler key ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
		v1alpha1.DefaultRealm, *turnAuth.Password), "auth handler ok")

	log.Debug("--------------------------------------")
	log.Debug("editing config file: change username")
	watchTestConfig.Auth.Credentials["username"] = "newuser"
	data, err = json.MarshalIndent(watchTestConfig, "", "  ")
	assert.NoError(t, err, "JSONify config file")

	assert.NoError(t, f.Truncate(0), "truncate temp file")
	_, err = f.Seek(0, 0)
	assert.NoError(t, err, "seek temp file")
	_, err = f.Write(data)
	assert.NoError(t, err, "writing JSON config file")

	// let STUNner pick up the config
	assert.NoError(t, s.Reconcile(watchTestConfig), "reconcile")

	// wait so that the auth-server has comfortable time to pick up the new config
	time.Sleep(time.Duration(100) * time.Millisecond)

	param = client.GetTurnAuthParams{Service: types.GetTurnAuthParamsServiceTurn, Username: &u}
	turnAuth, err = authClient.GetTurnAuthToken(ctx, &param)
	assert.NoError(t, err, "TURN auth get")

	assert.NotNil(t, turnAuth, "TURN token nil")
	assert.NotNil(t, turnAuth.Username, "username nil")
	assert.Equal(t, "newuser", *turnAuth.Username, "username nil")
	assert.NotNil(t, turnAuth.Password, "password nil")
	assert.Equal(t, "pass1", *turnAuth.Password, "password ok")
	assert.NotNil(t, turnAuth.Ttl, "ttl nil")
	assert.Equal(t, int64(86400), *turnAuth.Ttl, "ttl ok")
	assert.NotNil(t, turnAuth.Uris, "URIs nil")
	uris = *turnAuth.Uris
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")

	key, ok = authHandler(*turnAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler key ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
		v1alpha1.DefaultRealm, *turnAuth.Password), "auth handler ok")

	log.Debug("--------------------------------------")
	log.Debug("editing config file: change auth type")
	watchTestConfig.Auth = v1alpha1.AuthConfig{
		Type: "longterm",
		Credentials: map[string]string{
			"secret": "my-secret",
		},
	}
	data, err = json.MarshalIndent(watchTestConfig, "", "  ")
	assert.NoError(t, err, "JSONify config file")

	assert.NoError(t, f.Truncate(0), "truncate temp file")
	_, err = f.Seek(0, 0)
	assert.NoError(t, err, "seek temp file")
	_, err = f.Write(data)
	assert.NoError(t, err, "writing JSON config file")

	// let STUNner pick up the config
	assert.NoError(t, s.Reconcile(watchTestConfig), "reconcile")

	// wait so that the auth-server has comfortable time to pick up the new config
	time.Sleep(time.Duration(100) * time.Millisecond)

	u = "dummy"
	param = client.GetTurnAuthParams{Username: &u}
	turnAuth, err = authClient.GetTurnAuthToken(ctx, &param)
	assert.NoError(t, err, "TURN auth get")

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
	uris = *turnAuth.Uris
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")

	key, ok = authHandler(*turnAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
		v1alpha1.DefaultRealm, *turnAuth.Password), "auth handler ok")

	log.Debug("--------------------------------------")
	log.Debug("editing config file: adding a new listener")
	l := v1alpha1.ListenerConfig{}
	basicAuthTestConfig.Listeners[3].DeepCopyInto(&l)
	watchTestConfig.Listeners = append(watchTestConfig.Listeners, l)

	data, err = json.MarshalIndent(watchTestConfig, "", "  ")
	assert.NoError(t, err, "JSONify config file")

	assert.NoError(t, f.Truncate(0), "truncate temp file")
	_, err = f.Seek(0, 0)
	assert.NoError(t, err, "seek temp file")
	_, err = f.Write(data)
	assert.NoError(t, err, "writing JSON config file")

	// let STUNner pick up the config
	assert.NoError(t, s.Reconcile(watchTestConfig), "reconcile")

	// wait so that the auth-server has comfortable time to pick up the new config
	time.Sleep(time.Duration(100) * time.Millisecond)

	u = "dummy"
	param = client.GetTurnAuthParams{Username: &u}
	turnAuth, err = authClient.GetTurnAuthToken(ctx, &param)
	assert.NoError(t, err, "TURN auth get")

	assert.NotNil(t, turnAuth, "TURN token nil")
	assert.NotNil(t, turnAuth.Username, "username nil")
	// we do not know the username, only that it contains the timestamps plus a colon
	assert.Regexp(t, regexp.MustCompile(`^\d+:dummy$`), *turnAuth.Username, "username ok")
	assert.NoError(t, a12n.CheckTimeWindowedUsername(*turnAuth.Username), "username valid")
	assert.NotNil(t, turnAuth.Password, "password nil")
	passwd, err = a12n.GetLongTermCredential(*turnAuth.Username, "my-secret")
	assert.NoError(t, err, "GetLongTermCredential")
	assert.Equal(t, passwd, *turnAuth.Password, "password ok")
	assert.NotNil(t, turnAuth.Uris, "URIs nil")
	uris = *turnAuth.Uris
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

	key, ok = authHandler(*turnAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
	assert.True(t, ok, "authHandler ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
		v1alpha1.DefaultRealm, *turnAuth.Password), "auth handler ok")

	log.Debug("--------------------------------------")
	log.Debug("editing config file: adding a new public IP/port to a listener")
	watchTestConfig.Listeners[3].PublicAddr = "4.3.2.1"
	watchTestConfig.Listeners[3].PublicPort = 12345

	data, err = json.MarshalIndent(watchTestConfig, "", "  ")
	assert.NoError(t, err, "JSONify config file")

	assert.NoError(t, f.Truncate(0), "truncate temp file")
	_, err = f.Seek(0, 0)
	assert.NoError(t, err, "seek temp file")
	_, err = f.Write(data)
	assert.NoError(t, err, "writing JSON config file")

	// let STUNner pick up the config
	assert.NoError(t, s.Reconcile(watchTestConfig), "reconcile")

	// wait so that the auth-server has comfortable time to pick up the new config
	time.Sleep(time.Duration(100) * time.Millisecond)

	u = "dummy"
	param = client.GetTurnAuthParams{Username: &u}
	turnAuth, err = authClient.GetTurnAuthToken(ctx, &param)
	assert.NoError(t, err, "TURN auth get")

	assert.NotNil(t, turnAuth, "TURN token nil")
	assert.NotNil(t, turnAuth.Username, "username nil")
	// we do not know the username, only that it contains the timestamps plus a colon
	assert.Regexp(t, regexp.MustCompile(`^\d+:dummy$`), *turnAuth.Username, "username ok")
	assert.NoError(t, a12n.CheckTimeWindowedUsername(*turnAuth.Username), "username valid")
	assert.NotNil(t, turnAuth.Password, "password nil")
	passwd, err = a12n.GetLongTermCredential(*turnAuth.Username, "my-secret")
	assert.NoError(t, err, "GetLongTermCredential")
	assert.Equal(t, passwd, *turnAuth.Password, "password ok")
	assert.NotNil(t, turnAuth.Uris, "URIs nil")
	uris = *turnAuth.Uris
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:4.3.2.1:12345?transport=udp", "DTLS URI")

	key, ok = authHandler(*turnAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("4.3.2.1"), Port: 12345})
	assert.True(t, ok, "authHandler ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
		v1alpha1.DefaultRealm, *turnAuth.Password), "auth handler ok")

	log.Debug("--------------------------------------")
	log.Debug("editing config file: changing the proto for a listener")
	watchTestConfig.Listeners[1].Protocol = "udp"

	data, err = json.MarshalIndent(watchTestConfig, "", "  ")
	assert.NoError(t, err, "JSONify config file")

	assert.NoError(t, f.Truncate(0), "truncate temp file")
	_, err = f.Seek(0, 0)
	assert.NoError(t, err, "seek temp file")
	_, err = f.Write(data)
	assert.NoError(t, err, "writing JSON config file")

	// let STUNner pick up the config -- will cause a restart!
	err = s.Reconcile(watchTestConfig)
	_, ok = err.(v1alpha1.ErrRestarted)
	assert.True(t, ok, "reconcile")

	// wait so that the auth-server has comfortable time to pick up the new config
	time.Sleep(time.Duration(100) * time.Millisecond)

	u = "dummy"
	param = client.GetTurnAuthParams{Username: &u}
	turnAuth, err = authClient.GetTurnAuthToken(ctx, &param)
	assert.NoError(t, err, "TURN auth get")

	assert.NotNil(t, turnAuth, "TURN token nil")
	assert.NotNil(t, turnAuth.Username, "username nil")
	// we do not know the username, only that it contains the timestamps plus a colon
	assert.Regexp(t, regexp.MustCompile(`^\d+:dummy$`), *turnAuth.Username, "username ok")
	assert.NoError(t, a12n.CheckTimeWindowedUsername(*turnAuth.Username), "username valid")
	assert.NotNil(t, turnAuth.Password, "password nil")
	passwd, err = a12n.GetLongTermCredential(*turnAuth.Username, "my-secret")
	assert.NoError(t, err, "GetLongTermCredential")
	assert.Equal(t, passwd, *turnAuth.Password, "password ok")
	assert.NotNil(t, turnAuth.Uris, "URIs nil")
	uris = *turnAuth.Uris
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
	assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "TCP URI")
	assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
	assert.Contains(t, uris, "turns:4.3.2.1:12345?transport=udp", "DTLS URI")

	key, ok = authHandler(*turnAuth.Username, v1alpha1.DefaultRealm,
		&net.UDPAddr{IP: net.ParseIP("4.3.2.1"), Port: 12345})
	assert.True(t, ok, "authHandler ok")
	assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuth.Username,
		v1alpha1.DefaultRealm, *turnAuth.Password), "auth handler ok")
}
