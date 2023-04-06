package handler

import (
	"encoding/base64"
	"os"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/l7mp/stunner"
	"github.com/l7mp/stunner/pkg/apis/v1alpha1"

	"github.com/l7mp/stunner-auth-service/pkg/types"
)

const (
	// normal error level
	//loglevel = 0
	loglevel         = zapcore.ErrorLevel
	authTestLoglevel = "all:ERROR"

	// trace
	// loglevel = zapcore.DebugLevel
	// authTestLoglevel = "all:TRACE"
)

var (
	testUsername           = "dummy"
	testTtl            int = 1
	svc                    = types.GetIceAuthParamsServiceTurn
	dummySvc               = types.GetIceAuthParamsService("dummy")
	certPem, keyPem, _     = stunner.GenerateSelfSignedKey()
	certPem64              = base64.StdEncoding.EncodeToString(certPem)
	keyPem64               = base64.StdEncoding.EncodeToString(keyPem)
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

var plaintextAuthConfig = v1alpha1.StunnerConfig{
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
			Name:       "testnamespace/testgateway/udp",
			Protocol:   "udp",
			PublicAddr: "1.2.3.4",
			PublicPort: 3478,
			Addr:       "127.0.0.1",
			Port:       23478,
			Routes:     []string{},
		}, {
			Name:       "dummynamespace/testgateway/tcp",
			Protocol:   "tcp",
			PublicAddr: "1.2.3.4",
			PublicPort: 3478,
			Addr:       "127.0.0.1",
			Port:       3478,
			Routes:     []string{},
		}, {
			Name:       "testnamespace/dummygateway/tls",
			Protocol:   "tls",
			PublicAddr: "",
			PublicPort: 0,
			Addr:       "127.0.0.1",
			Port:       3479,
			Cert:       certPem64,
			Key:        keyPem64,
			Routes:     []string{},
		}, {
			Name:       "testnamespace/testgateway/dtls",
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

var longtermAuthConfig = v1alpha1.StunnerConfig{
	ApiVersion: "v1alpha1",
	Admin: v1alpha1.AdminConfig{
		Name:     "stunnerd",
		LogLevel: authTestLoglevel,
	},
	Auth: v1alpha1.AuthConfig{
		Type:  "longterm",
		Realm: "",
		Credentials: map[string]string{
			"secret": "my-secret",
		}},
	Listeners: []v1alpha1.ListenerConfig{
		{
			Name:       "testnamespace/testgateway/udp-2",
			Protocol:   "udp",
			PublicAddr: "1.2.3.5",
			PublicPort: 3478,
			Addr:       "127.0.0.2",
			Port:       23478,
			Routes:     []string{},
		}, {
			Name:       "dummynamespace/testgateway/tcp-2",
			Protocol:   "tcp",
			PublicAddr: "1.2.3.5",
			PublicPort: 3478,
			Addr:       "127.0.0.2",
			Port:       3478,
			Routes:     []string{},
		}, {
			Name:       "testnamespace/dummygateway/tls-2",
			Protocol:   "tls",
			PublicAddr: "",
			PublicPort: 0,
			Addr:       "127.0.0.2",
			Port:       3479,
			Cert:       certPem64,
			Key:        keyPem64,
			Routes:     []string{},
		}, {
			Name:       "testnamespace/testgateway/dtls-2",
			Protocol:   "dtls",
			PublicAddr: "",
			PublicPort: 0,
			Addr:       "127.0.0.2",
			Port:       3479,
			Cert:       certPem64,
			Key:        keyPem64,
			Routes:     []string{},
		},
	},
	Clusters: []v1alpha1.ClusterConfig{},
}
