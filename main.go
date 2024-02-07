package main

import (
	"context"
	"fmt"
	golog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/pion/logging"
	flag "github.com/spf13/pflag"
	cliopt "k8s.io/cli-runtime/pkg/genericclioptions"

	stnrv1 "github.com/l7mp/stunner/pkg/apis/v1"
	cdsclient "github.com/l7mp/stunner/pkg/config/client"
	"github.com/l7mp/stunner/pkg/logger"

	"github.com/l7mp/stunner-auth-service/internal/handler"
	"github.com/l7mp/stunner-auth-service/pkg/server"
)

type httpLogWriter struct {
	logger logging.LeveledLogger
}

func (l *httpLogWriter) Write(p []byte) (int, error) {
	l.logger.Info(string(p))
	return len(p), nil
}

func main() {
	os.Args[0] = "authd"
	port := flag.IntP("port", "p", 8088, "HTTP port (defualt: 8088)")
	level := flag.StringP("log", "l", "", "Log level (format: <scope>:<level>, overrides: PION_LOG_*, default: all:INFO)")
	verbose := flag.BoolP("verbose", "v", false, "Verbose logging, identical to <-l all:DEBUG>")

	// Kubernetes config flags
	k8sFlags := cliopt.NewConfigFlags(true)
	k8sFlags.AddFlags(flag.CommandLine)

	// CDS server discovery flags
	cdsFlags := cdsclient.NewCDSConfigFlags()
	cdsFlags.AddFlags(flag.CommandLine)

	flag.Parse()

	logLevel := stnrv1.DefaultLogLevel
	if *verbose {
		logLevel = "all:DEBUG"
	}

	if *level != "" {
		logLevel = *level
	}

	loggerFactory := logger.NewLoggerFactory(logLevel)
	log := loggerFactory.NewLogger("authd")

	conf := make(chan *stnrv1.StunnerConfig, 10)
	defer close(conf)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Info("Obtaining CDS server address")
	cdsAddr, err := cdsclient.DiscoverK8sCDSServer(ctx, k8sFlags, cdsFlags,
		loggerFactory.NewLogger("k8s-discover"))
	if err != nil {
		log.Errorf("Could not find CDS server: %s", err.Error())
		os.Exit(1)
	}

	log.Infof("Starting CDS client to server at %s", cdsAddr)
	client, err := cdsclient.NewAllConfigsAPI(cdsAddr, loggerFactory.NewLogger("cds-client"))
	if err != nil {
		log.Errorf("Could not start CDS client: %s", err.Error())
		os.Exit(1)
	}

	if err := client.Watch(ctx, conf); err != nil {
		log.Errorf("Could not watch CDS server: %s", err.Error())
		os.Exit(1)
	}

	log.Info("Starting auth request handler")
	handler, err := handler.NewHandler(conf, loggerFactory.NewLogger("auth-svc"))
	if err != nil {
		log.Errorf("could not start authentication server: %s", err.Error())
		os.Exit(1)
	}
	handler.Start(ctx)

	router := server.HandlerWithOptions(handler, server.GorillaServerOptions{})

	log.Infof("Starting HTTP REST server at port %d", *port)
	srv := &http.Server{
		Addr:     fmt.Sprintf(":%d", *port),
		Handler:  router,
		ErrorLog: golog.New(&httpLogWriter{loggerFactory.NewLogger("http-server")}, "", 0),
	}
	defer srv.Close()

	go func() {
		if err = srv.ListenAndServe(); err != nil {
			log.Errorf("HTTP server error: %s", err.Error())
			os.Exit(1)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

}
