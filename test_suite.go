package main

import (
	"encoding/base64"
	"os"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/l7mp/stunner"
	stnrv1 "github.com/l7mp/stunner/pkg/apis/v1"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	// normal error level
	authTestLoglevel = "all:ERROR"
	// authTestLoglevel = "all:TRACE"
	// authTestLoglevel = "all:INFO,cds-server:TRACE,cds-client:TRACE,auth-test:TRACE,auth-handler:TRACE"

	loglevel = zapcore.ErrorLevel
	// loglevel = zapcore.Level(-10)

	testCDSAddr = ":63487"
)

var (
	certPem, keyPem, _ = stunner.GenerateSelfSignedKey()
	certPem64          = base64.StdEncoding.EncodeToString(certPem)
	keyPem64           = base64.StdEncoding.EncodeToString(keyPem)
)

func setupLogger() logr.Logger {
	zapConfig := zap.NewProductionEncoderConfig()
	zapConfig.EncodeTime = zapcore.RFC3339NanoTimeEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(zapConfig)
	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), loglevel),
	)
	return zapr.NewLogger(zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel)))
}

var staticAuthConfig = stnrv1.StunnerConfig{
	ApiVersion: "v1",
	Admin: stnrv1.AdminConfig{
		Name:     "testnamespace/stunnerd-static",
		LogLevel: authTestLoglevel,
	},
	Auth: stnrv1.AuthConfig{
		Type:  "static",
		Realm: "",
		Credentials: map[string]string{
			"username": "user1",
			"password": "pass1",
		}},
	Listeners: []stnrv1.ListenerConfig{
		{
			Name:       "testnamespace/testgateway/udp",
			Protocol:   "turn-udp",
			PublicAddr: "1.2.3.4",
			PublicPort: 3478,
			Addr:       "127.0.0.1",
			Port:       23478,
			Routes:     []string{},
		}, {
			Name:       "dummynamespace/testgateway/tcp",
			Protocol:   "turn-tcp",
			PublicAddr: "1.2.3.4",
			PublicPort: 3478,
			Addr:       "127.0.0.1",
			Port:       3478,
			Routes:     []string{},
		}, {
			Name:       "testnamespace/dummygateway/tls",
			Protocol:   "turn-tls",
			PublicAddr: "",
			PublicPort: 0,
			Addr:       "127.0.0.1",
			Port:       3479,
			Cert:       certPem64,
			Key:        keyPem64,
			Routes:     []string{},
		}, {
			Name:       "testnamespace/testgateway/dtls",
			Protocol:   "turn-dtls",
			PublicAddr: "",
			PublicPort: 0,
			Addr:       "127.0.0.1",
			Port:       3479,
			Cert:       certPem64,
			Key:        keyPem64,
			Routes:     []string{},
		},
	},
	Clusters: []stnrv1.ClusterConfig{},
}

var ephemeralAuthConfig = stnrv1.StunnerConfig{
	ApiVersion: "v1",
	Admin: stnrv1.AdminConfig{
		Name:     "testnamespace/stunnerd-ephemeral",
		LogLevel: authTestLoglevel,
	},
	Auth: stnrv1.AuthConfig{
		Type:  "ephemeral",
		Realm: "",
		Credentials: map[string]string{
			"secret": "my-secret",
		}},
	Listeners: []stnrv1.ListenerConfig{
		{
			Name:       "testnamespace/testgateway/udp-2",
			Protocol:   "turn-udp",
			PublicAddr: "1.2.3.5",
			PublicPort: 3478,
			Addr:       "127.0.0.2",
			Port:       23478,
			Routes:     []string{},
		}, {
			Name:       "dummynamespace/testgateway/tcp-2",
			Protocol:   "turn-tcp",
			PublicAddr: "1.2.3.5",
			PublicPort: 3478,
			Addr:       "127.0.0.2",
			Port:       3478,
			Routes:     []string{},
		}, {
			Name:       "testnamespace/dummygateway/tls-2",
			Protocol:   "turn-tls",
			PublicAddr: "",
			PublicPort: 0,
			Addr:       "127.0.0.2",
			Port:       3479,
			Cert:       certPem64,
			Key:        keyPem64,
			Routes:     []string{},
		}, {
			Name:       "testnamespace/testgateway/dtls-2",
			Protocol:   "turn-dtls",
			PublicAddr: "",
			PublicPort: 0,
			Addr:       "127.0.0.2",
			Port:       3479,
			Cert:       certPem64,
			Key:        keyPem64,
			Routes:     []string{},
		},
	},
	Clusters: []stnrv1.ClusterConfig{},
}
