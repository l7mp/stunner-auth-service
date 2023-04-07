/*
Copyright 2023.

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

package main

import (
	"flag"
	"fmt"
	"github.com/go-logr/logr"
	"log"
	"net/http"
	"os"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"go.uber.org/zap/zapcore"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	//+kubebuilder:scaffold:imports

	"github.com/l7mp/stunner-auth-service/internal/controllers"
	"github.com/l7mp/stunner-auth-service/internal/handler"
	"github.com/l7mp/stunner-auth-service/pkg/server"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	//+kubebuilder:scaffold:scheme
}

type serverErrorLogWriter struct {
	logger logr.Logger
}

func (l *serverErrorLogWriter) Write(p []byte) (int, error) {
	m := string(p)
	l.logger.Info(m)
	return len(p), nil
}

func newServerErrorLog(logger logr.Logger) *log.Logger {
	return log.New(&serverErrorLogWriter{logger.WithName("http-server")}, "", 0)
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var port int
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.IntVar(&port, "port", 8088, "HTTP port (defualt: 8088).")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	logger := zap.New(zap.UseFlagOptions(&opts), func(o *zap.Options) {
		o.TimeEncoder = zapcore.RFC3339NanoTimeEncoder
	})
	ctrl.SetLogger(logger.WithName("ctrl-runtime"))
	setupLog := logger.WithName("setup")

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "ca893bb3.l7mp.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting ConfigMap controller")
	if err := controllers.RegisterConfigMapController(mgr, logger); err != nil {
		setupLog.Error(err, "problem running configmap manager")
		os.Exit(1)
	}

	handler, err := handler.NewHandler(logger)
	if err != nil {
		setupLog.Error(err, "could not start authentication server")
		os.Exit(1)
	}

	router := server.HandlerWithOptions(handler, server.GorillaServerOptions{})

	setupLog.Info("starting HTTP REST server", "port", port)
	srv := &http.Server{
		Addr:     fmt.Sprintf(":%d", port),
		Handler:  router,
		ErrorLog: newServerErrorLog(logger),
	}
	defer srv.Close()
	go func() {
		if err = srv.ListenAndServe(); err != nil {
			setupLog.Error(err, "error running HTTP listener")
			os.Exit(1)
		}
	}()

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}

}
