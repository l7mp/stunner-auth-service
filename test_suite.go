package main

import (
	"encoding/base64"
	"os"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/l7mp/stunner/v2"
	stnrv2 "github.com/l7mp/stunner/v2/pkg/apis/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

//nolint:unused
const (
	// normal error level
	authTestLoglevel = "all:ERROR"
	// authTestLoglevel = "all:TRACE"
	// authTestLoglevel = "all:INFO,cds-server:TRACE,cds-client:TRACE,auth-test:TRACE,auth-handler:TRACE"

	loglevel = zapcore.ErrorLevel
	// loglevel = zapcore.Level(-10)

	testCDSAddr = ":63487"
)

//nolint:unused
var (
	certPem, keyPem, _ = stunner.GenerateSelfSignedKey()
	certPem64          = base64.StdEncoding.EncodeToString(certPem)
	keyPem64           = base64.StdEncoding.EncodeToString(keyPem)
)

//nolint:unused
func setupLogger() logr.Logger {
	zapConfig := zap.NewProductionEncoderConfig()
	zapConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(zapConfig)
	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), loglevel),
	)
	return zapr.NewLogger(zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel)))
}

//nolint:unused
var staticAuthConfig = stnrv2.StunnerConfig{
	ApiVersion: stnrv2.ApiVersion,
	Admin: stnrv2.AdminConfig{
		Name:     "testnamespace/stunnerd-static",
		LogLevel: authTestLoglevel,
	},
	Auth: stnrv2.AuthConfig{
		Type:  "static",
		Realm: "",
		Credentials: map[string]string{
			"username": "user1",
			"password": "pass1",
		}},
	Listeners: []stnrv2.ListenerConfig{
		{
			Name:       "testnamespace/testgateway/udp",
			Protocol:   "UDP",
			PublicAddr: "1.2.3.4",
			PublicPort: 3478,
			Addr:       "127.0.0.1",
			Port:       23478,
			Servers:    []string{"testnamespace/turn-static"},
		}, {
			Name:       "dummynamespace/testgateway/tcp",
			Protocol:   "TCP",
			PublicAddr: "1.2.3.4",
			PublicPort: 3478,
			Addr:       "127.0.0.1",
			Port:       3478,
			Servers:    []string{"testnamespace/turn-static"},
		}, {
			Name:       "testnamespace/dummygateway/tls",
			Protocol:   "TLS",
			PublicAddr: "",
			PublicPort: 0,
			Addr:       "127.0.0.1",
			Port:       3479,
			Cert:       certPem64,
			Key:        keyPem64,
			Servers:    []string{"testnamespace/turn-static"},
		}, {
			Name:       "testnamespace/testgateway/dtls",
			Protocol:   "DTLS",
			PublicAddr: "",
			PublicPort: 0,
			Addr:       "127.0.0.1",
			Port:       3479,
			Cert:       certPem64,
			Key:        keyPem64,
			Servers:    []string{"testnamespace/turn-static"},
		},
	},
	Servers: []stnrv2.ServerConfig{{
		Name: "testnamespace/turn-static",
		Type: stnrv2.ServerTypeTURN.String(),
	}},
	Clusters: []stnrv2.ClusterConfig{},
}

//nolint:unused
var ephemeralAuthConfig = stnrv2.StunnerConfig{
	ApiVersion: stnrv2.ApiVersion,
	Admin: stnrv2.AdminConfig{
		Name:     "testnamespace/stunnerd-ephemeral",
		LogLevel: authTestLoglevel,
	},
	Auth: stnrv2.AuthConfig{
		Type:  "ephemeral",
		Realm: "",
		Credentials: map[string]string{
			"secret": "my-secret",
		}},
	Listeners: []stnrv2.ListenerConfig{
		{
			Name:       "testnamespace/testgateway/udp-2",
			Protocol:   "UDP",
			PublicAddr: "1.2.3.5",
			PublicPort: 3478,
			Addr:       "127.0.0.2",
			Port:       23478,
			Servers:    []string{"testnamespace/turn-ephemeral"},
		}, {
			Name:       "dummynamespace/testgateway/tcp-2",
			Protocol:   "TCP",
			PublicAddr: "1.2.3.5",
			PublicPort: 3478,
			Addr:       "127.0.0.2",
			Port:       3478,
			Servers:    []string{"testnamespace/turn-ephemeral"},
		}, {
			Name:       "testnamespace/dummygateway/tls-2",
			Protocol:   "TLS",
			PublicAddr: "",
			PublicPort: 0,
			Addr:       "127.0.0.2",
			Port:       3479,
			Cert:       certPem64,
			Key:        keyPem64,
			Servers:    []string{"testnamespace/turn-ephemeral"},
		}, {
			Name:       "testnamespace/testgateway/dtls-2",
			Protocol:   "DTLS",
			PublicAddr: "",
			PublicPort: 0,
			Addr:       "127.0.0.2",
			Port:       3479,
			Cert:       certPem64,
			Key:        keyPem64,
			Servers:    []string{"testnamespace/turn-ephemeral"},
		},
	},
	Servers: []stnrv2.ServerConfig{{
		Name: "testnamespace/turn-ephemeral",
		Type: stnrv2.ServerTypeTURN.String(),
	}},
	Clusters: []stnrv2.ClusterConfig{},
}
