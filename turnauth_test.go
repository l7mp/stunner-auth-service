package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/pion/transport/v2/test"
	"github.com/stretchr/testify/assert"

	"github.com/l7mp/stunner"
	stnrv1 "github.com/l7mp/stunner/pkg/apis/v1"
	a12n "github.com/l7mp/stunner/pkg/authentication"
	cdsclient "github.com/l7mp/stunner/pkg/config/client"
	cdsserver "github.com/l7mp/stunner/pkg/config/server"
	"github.com/l7mp/stunner/pkg/logger"

	// "github.com/l7mp/stunner-auth-service/pkg/client"
	"github.com/l7mp/stunner-auth-service/internal/handler"
	"github.com/l7mp/stunner-auth-service/pkg/server"
	"github.com/l7mp/stunner-auth-service/pkg/types"
)

type turnAuthTestCase struct {
	name   string
	config []*stnrv1.StunnerConfig
	params string
	status int
	tester func(t *testing.T, turnAuth *types.TurnAuthenticationToken, authHandler a12n.AuthHandler)
}

var turnAuthTestCases = []turnAuthTestCase{
	{
		name:   "empty config",
		config: []*stnrv1.StunnerConfig{},
		params: "service=turn",
		status: http.StatusInternalServerError,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {},
	},
	{
		name:   "static",
		config: []*stnrv1.StunnerConfig{&staticAuthConfig},
		params: "service=turn",
		status: 200,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuthToken, "TURN auth token nil")
			assert.NotNil(t, turnAuthToken.Username, "username nil")
			assert.Equal(t, "user1", *turnAuthToken.Username, "username nil")
			assert.NotNil(t, turnAuthToken.Password, "password nil")
			assert.Equal(t, "pass1", *turnAuthToken.Password, "password ok")
			assert.NotNil(t, turnAuthToken.Uris, "URIs nil")
			uris := *turnAuthToken.Uris
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

			key, ok := authHandler(*turnAuthToken.Username, stnrv1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuthToken.Username,
				stnrv1.DefaultRealm, *turnAuthToken.Password), "auth handler ok")
		},
	},
	{
		name:   "static - dummy service",
		config: []*stnrv1.StunnerConfig{&staticAuthConfig},
		params: "service=dummy",
		status: http.StatusBadRequest,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {},
	},
	{
		name:   "static - username set",
		config: []*stnrv1.StunnerConfig{&staticAuthConfig},
		params: "service=turn&username=dummy",
		status: 200,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			// useless: no username override in static mode
			assert.NotNil(t, turnAuthToken, "TURN auth token nil")
			assert.NotNil(t, turnAuthToken.Username, "username nil")
			assert.Equal(t, "user1", *turnAuthToken.Username, "username nil")
			assert.NotNil(t, turnAuthToken.Password, "credential nil")
			assert.Equal(t, "pass1", *turnAuthToken.Password, "credential ok")
			assert.NotNil(t, turnAuthToken.Uris, "URLs nil")
			uris := *turnAuthToken.Uris
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

			key, ok := authHandler(*turnAuthToken.Username, stnrv1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuthToken.Username,
				stnrv1.DefaultRealm, *turnAuthToken.Password), "auth handler ok")
		},
	},
	{
		name:   "static -- ttl set",
		config: []*stnrv1.StunnerConfig{&staticAuthConfig},
		params: "service=turn&username=dummy&ttl=1",
		status: 200,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			// useless: no ttl in response
			assert.NotNil(t, turnAuthToken, "TURN auth token nil")
			assert.NotNil(t, turnAuthToken.Username, "username nil")
			assert.Equal(t, "user1", *turnAuthToken.Username, "username nil")
			assert.NotNil(t, turnAuthToken.Password, "credential nil")
			assert.Equal(t, "pass1", *turnAuthToken.Password, "credential ok")
			assert.NotNil(t, turnAuthToken.Uris, "URLs nil")
			uris := *turnAuthToken.Uris
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")

			key, ok := authHandler(*turnAuthToken.Username, stnrv1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuthToken.Username,
				stnrv1.DefaultRealm, *turnAuthToken.Password), "auth handler ok")
		},
	},
	{
		name:   "ephemeral -- basic",
		config: []*stnrv1.StunnerConfig{&ephemeralAuthConfig},
		params: "service=turn",
		status: 200,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuthToken, "TURN auth token nil")
			assert.NotNil(t, turnAuthToken.Username, "username nil")
			assert.Regexp(t, regexp.MustCompile(`^\d+:`), *turnAuthToken.Username, "username ok")
			assert.NoError(t, a12n.CheckTimeWindowedUsername(*turnAuthToken.Username), "username valid")
			assert.NotNil(t, turnAuthToken.Password, "credential nil")
			passwd, err := a12n.GetLongTermCredential(*turnAuthToken.Username, "my-secret")
			assert.NoError(t, err, "GetLongTermCredential")
			assert.Equal(t, passwd, *turnAuthToken.Password, "credential ok")
			assert.NotNil(t, turnAuthToken.Uris, "URLs nil")
			uris := *turnAuthToken.Uris
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")

			key, ok := authHandler(*turnAuthToken.Username, stnrv1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuthToken.Username,
				stnrv1.DefaultRealm, *turnAuthToken.Password), "auth handler ok")
		},
	},
	{
		name:   "ephemeral -- dummy service",
		config: []*stnrv1.StunnerConfig{&ephemeralAuthConfig},
		params: "service=dummy",
		status: 400,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {},
	},
	{
		name:   "ephemeral -- username set",
		config: []*stnrv1.StunnerConfig{&ephemeralAuthConfig},
		params: "service=turn&username=dummy",
		status: 200,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuthToken, "TURN auth token nil")

			assert.NotNil(t, turnAuthToken.Username, "username nil")
			assert.Regexp(t, regexp.MustCompile(`^\d+:dummy`), *turnAuthToken.Username, "username ok")
			assert.NoError(t, a12n.CheckTimeWindowedUsername(*turnAuthToken.Username), "username valid")
			assert.NotNil(t, turnAuthToken.Password, "credential nil")
			passwd, err := a12n.GetLongTermCredential(*turnAuthToken.Username, "my-secret")
			assert.NoError(t, err, "GetLongTermCredential")
			assert.Equal(t, passwd, *turnAuthToken.Password, "credential ok")
			assert.NotNil(t, turnAuthToken.Uris, "URLs nil")
			uris := *turnAuthToken.Uris
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")

			key, ok := authHandler(*turnAuthToken.Username, stnrv1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 1234})
			assert.True(t, ok, "authHandler key ok")
			assert.Equal(t, key, a12n.GenerateAuthKey(*turnAuthToken.Username,
				stnrv1.DefaultRealm, *turnAuthToken.Password), "auth handler ok")
		},
	},
	{
		name:   "ephemeral -- username, ttl set",
		config: []*stnrv1.StunnerConfig{&ephemeralAuthConfig},
		params: "service=turn&username=dummy&ttl=1",
		status: 200,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			// we must wait for the token to expire
			time.Sleep(2 * time.Second)

			assert.NotNil(t, turnAuthToken, "TURN auth token nil")
			assert.NotNil(t, turnAuthToken.Username, "username nil")
			assert.Regexp(t, regexp.MustCompile(`^\d+:dummy`), *turnAuthToken.Username, "username ok")
			assert.Error(t, a12n.CheckTimeWindowedUsername(*turnAuthToken.Username), "username invalid")
			assert.NotNil(t, turnAuthToken.Password, "credential nil")
			passwd, err := a12n.GetLongTermCredential(*turnAuthToken.Username, "my-secret")
			assert.NoError(t, err, "GetLongTermCredential")
			assert.Equal(t, passwd, *turnAuthToken.Password, "credential ok")
			assert.NotNil(t, turnAuthToken.Uris, "URLs nil")
			uris := *turnAuthToken.Uris
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")

			_, ok := authHandler(*turnAuthToken.Username, stnrv1.DefaultRealm,
				&net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 1234})
			assert.False(t, ok, "authHandler key ok")
		},
	},
	{
		name:   "static - multiple configs, no filter",
		config: []*stnrv1.StunnerConfig{&staticAuthConfig, &ephemeralAuthConfig},
		params: "service=turn",
		status: 200,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuthToken, "TURN auth token nil")
			assert.NotNil(t, turnAuthToken.Username, "username nil")
			assert.NotNil(t, turnAuthToken.Password, "password nil")
			if *turnAuthToken.Username == "user1" {
				assert.Equal(t, "user1", *turnAuthToken.Username, "username nil")
				assert.Equal(t, "pass1", *turnAuthToken.Password, "password ok")
			} else {
				assert.Regexp(t, regexp.MustCompile(`^\d+:`), *turnAuthToken.Username, "username ok")
				assert.NoError(t, a12n.CheckTimeWindowedUsername(*turnAuthToken.Username), "username invalid")
				passwd, err := a12n.GetLongTermCredential(*turnAuthToken.Username, "my-secret")
				assert.NoError(t, err, "GetLongTermCredential")
				assert.Equal(t, passwd, *turnAuthToken.Password, "credential ok")
			}
			assert.NotNil(t, turnAuthToken.Uris, "URIs nil")
			uris := *turnAuthToken.Uris
			assert.Len(t, uris, 8, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=tcp", "TLS URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")
		},
	},
	// gateway filters
	{
		name:   "static - single config, namespace filter",
		config: []*stnrv1.StunnerConfig{&staticAuthConfig},
		params: "service=turn&namespace=testnamespace",
		status: 200,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuthToken, "TURN auth token nil")

			uris := *turnAuthToken.Uris
			assert.Len(t, uris, 3, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")
		},
	},
	{
		name:   "static - single config, gateway filter",
		config: []*stnrv1.StunnerConfig{&staticAuthConfig},
		params: "service=turn&namespace=testnamespace&gateway=testgateway",
		status: 200,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuthToken, "TURN auth token nil")

			uris := *turnAuthToken.Uris
			assert.Len(t, uris, 2, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")
		},
	},
	{
		name:   "static - single config, listener filter",
		config: []*stnrv1.StunnerConfig{&staticAuthConfig},
		params: "service=turn&namespace=testnamespace&gateway=testgateway&listener=udp",
		status: 200,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuthToken, "TURN auth token nil")

			uris := *turnAuthToken.Uris
			assert.Len(t, uris, 1, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
		},
	},
	{
		name:   "static - single config, restrictive filter, no result errs",
		config: []*stnrv1.StunnerConfig{&staticAuthConfig},
		params: "service=turn&namespace=testnamespace&listener=dummy&gateway=testgateway",
		status: 404,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {},
	},
	{
		name:   "static - multiple configs, namespace filter",
		config: []*stnrv1.StunnerConfig{&staticAuthConfig, &ephemeralAuthConfig},
		params: "service=turn&namespace=testnamespace",
		status: 200,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuthToken, "TURN auth token nil")
			uris := *turnAuthToken.Uris
			assert.Len(t, uris, 6, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=tcp", "TCP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")
		},
	},
	{
		name:   "static - multiple configs, gateway filter",
		config: []*stnrv1.StunnerConfig{&staticAuthConfig, &ephemeralAuthConfig},
		params: "service=turn&namespace=testnamespace&gateway=testgateway",
		status: 200,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuthToken, "TURN auth token nil")
			uris := *turnAuthToken.Uris
			assert.Len(t, uris, 4, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turns:127.0.0.1:3479?transport=udp", "DTLS URI")
			assert.Contains(t, uris, "turn:1.2.3.5:3478?transport=udp", "UDP URI")
			assert.Contains(t, uris, "turns:127.0.0.2:3479?transport=udp", "DTLS URI")
		},
	},
	{
		name:   "static - multiple configs, listener filter",
		config: []*stnrv1.StunnerConfig{&staticAuthConfig, &ephemeralAuthConfig},
		params: "service=turn&namespace=testnamespace&gateway=testgateway&listener=udp",
		status: 200,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {
			assert.NotNil(t, turnAuthToken, "TURN auth token nil")

			uris := *turnAuthToken.Uris
			assert.Len(t, uris, 1, "URI len")
			assert.Contains(t, uris, "turn:1.2.3.4:3478?transport=udp", "UDP URI")
		},
	},
	{
		name:   "static - multiple configs, restrictive filter, no result errs",
		config: []*stnrv1.StunnerConfig{&staticAuthConfig},
		params: "service=turn&namespace=testnamespace&gateway=testgateway&listener=dummy",
		status: 404,
		tester: func(t *testing.T, turnAuthToken *types.TurnAuthenticationToken, authHandler a12n.AuthHandler) {},
	},
}

func TestTURNAuth(t *testing.T)    { testTURNAuth(t, turnAuthTestCases) }
func TestTURNAuthCDS(t *testing.T) { testTurnAuthCDS(t, turnAuthTestCases) }

// test with manually injected configs
func testTURNAuth(t *testing.T, tests []turnAuthTestCase) {
	// <setup>
	lim := test.TimeOut(time.Second * 120)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	loggerFactory := logger.NewLoggerFactory(authTestLoglevel)
	log := loggerFactory.NewLogger("auth-test")

	// we don't Start() the handler so a nil channel should not be a problem
	handler, err := handler.NewHandler(nil, loggerFactory.NewLogger("auth-svc"))
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
		t.Run(testCase.name, func(t *testing.T) {
			log.Info(fmt.Sprintf("---------------- Test: %s ----------------", testCase.name))

			log.Info("storing config")
			handler.Reset()
			for _, c := range testCase.config {
				handler.SetConfig(c.Admin.Name, c)
			}

			// we do not use the Stunner auth handler for multi-config tests: no need to reconcile
			if len(testCase.config) == 1 {
				assert.NoError(t, s.Reconcile(testCase.config[0]), "starting server")
			}

			// wait so that the auth-server has comfortable time to start
			time.Sleep(50 * time.Millisecond)

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

			turnAuthToken := types.TurnAuthenticationToken{}
			if testCase.status == 200 {
				assert.Equal(t, "application/json; charset=UTF-8", resp.Header.Get("Content-Type"), "HTTP Content-Type")
				assert.NoError(t, json.Unmarshal(body, &turnAuthToken))
			}
			testCase.tester(t, &turnAuthToken, authHandler)
		})
	}
}

// test through the CDS client/server pipeline
func testTurnAuthCDS(t *testing.T, tests []turnAuthTestCase) {
	// <setup>
	lim := test.TimeOut(time.Second * 120)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	loggerFactory := logger.NewLoggerFactory(authTestLoglevel)
	log := loggerFactory.NewLogger("auth-test")

	// make config deletions superfast
	deleteDelay := cdsserver.ConfigDeletionUpdateDelay
	cdsserver.ConfigDeletionUpdateDelay = time.Millisecond
	defer func() { cdsserver.ConfigDeletionUpdateDelay = deleteDelay }()

	conf := make(chan *stnrv1.StunnerConfig, 10)
	defer close(conf)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Infof("Starting CDS server at %s", testCDSAddr)
	zapLogger := setupLogger()
	cdsServer := cdsserver.New(testCDSAddr, nil, zapLogger.WithName("cds-server"))
	assert.NoError(t, cdsServer.Start(ctx), "start CDS server")

	// wait for the server to start, otherwise the client will fail and many test fail until it
	// retries
	time.Sleep(50 * time.Millisecond)

	// make retries even faster
	cdsclient.RetryPeriod = 25 * time.Millisecond

	log.Infof("Starting CDS client to server at %s", testCDSAddr)
	client, err := cdsclient.NewAllConfigsAPI(testCDSAddr, loggerFactory.NewLogger("cds-client"))
	if err != nil {
		log.Errorf("Could not start CDS client: %s", err.Error())
		os.Exit(1)
	}

	if err := client.Watch(ctx, conf); err != nil {
		log.Errorf("Could not watch CDS server: %s", err.Error())
		os.Exit(1)
	}

	h, err := handler.NewHandler(conf, loggerFactory.NewLogger("auth-svc"))
	assert.NoError(t, err, "create handler")
	serv := server.ServerInterfaceWrapper{Handler: h}
	h.Start(ctx)

	// starting a Stunner instance to use its authenticator
	log.Info("creating a stunnerd")
	s := stunner.NewStunner(stunner.Options{
		DryRun:   true,
		LogLevel: authTestLoglevel,
	})
	defer s.Close()
	authHandler := s.NewAuthHandler()

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			log.Info(fmt.Sprintf("---------------- Test: %s ----------------", testCase.name))

			log.Info("storing config")
			cd := []cdsserver.Config{}
			for _, c := range testCase.config {
				cd = append(cd, cdsserver.Config{Id: c.Admin.Name, Config: c})
			}
			assert.NoError(t, cdsServer.UpdateConfig(cd), "updating CDS server")

			// we do not use the Stunner auth handler for multi-config tests: no need to reconcile
			if len(testCase.config) == 1 {
				assert.NoError(t, s.Reconcile(testCase.config[0]), "starting server")
			}

			// wait so that the auth-server has comfortable time to start
			time.Sleep(50 * time.Millisecond)

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

			turnAuthToken := types.TurnAuthenticationToken{}
			if testCase.status == 200 {
				assert.Equal(t, "application/json; charset=UTF-8", resp.Header.Get("Content-Type"), "HTTP Content-Type")
				assert.NoError(t, json.Unmarshal(body, &turnAuthToken))
			}
			testCase.tester(t, &turnAuthToken, authHandler)

			// remove all configs
			cd = []cdsserver.Config{}
			assert.NoError(t, cdsServer.UpdateConfig(cd), "delete all configs from CDS server")
			time.Sleep(50 * time.Millisecond)
		})
	}
}
