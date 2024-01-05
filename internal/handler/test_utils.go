package handler

import (
	"encoding/base64"
	"os"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/l7mp/stunner"
	stnrv1 "github.com/l7mp/stunner/pkg/apis/v1"
)

const (
	// normal error level
	loglevel         = zapcore.ErrorLevel
	authTestLoglevel = "all:ERROR"

	// trace
	// loglevel         = zapcore.DebugLevel
	// authTestLoglevel = "all:TRACE"
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

var plaintextAuthConfig = stnrv1.StunnerConfig{
	ApiVersion: "v1",
	Admin: stnrv1.AdminConfig{
		Name:     "stunnerd",
		LogLevel: authTestLoglevel,
	},
	Auth: stnrv1.AuthConfig{
		Type:  "plaintext",
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

var longtermAuthConfig = stnrv1.StunnerConfig{
	ApiVersion: "v1",
	Admin: stnrv1.AdminConfig{
		Name:     "stunnerd",
		LogLevel: authTestLoglevel,
	},
	Auth: stnrv1.AuthConfig{
		Type:  "longterm",
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
