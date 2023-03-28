// package handler implements the actual functions to generate TURN credentials

package handler

import (
	"context"
	"sync"

	"github.com/l7mp/stunner"
	"github.com/l7mp/stunner/pkg/apis/v1alpha1"
	"github.com/pion/logging"
)

// Handler Implements server.ServerInterface
type Handler struct {
	configFile string
	config     v1alpha1.StunnerConfig // the running config
	stunner    *stunner.Stunner
	lock       sync.RWMutex // HTTP handlers run in threades and we are writing the config file
	Log        logging.LeveledLogger
}

func NewHandler(ctx context.Context, configFile string, logLevel string, watch bool) (*Handler, error) {
	// create a stunner instance just so that we can steal its logger
	h := Handler{
		configFile: configFile,
		stunner:    stunner.NewStunner(stunner.Options{DryRun: true}),
	}

	h.stunner.SetLogLevel(logLevel)
	logger := h.stunner.GetLogger()
	h.Log = logger.NewLogger("auth-service")
	h.Log.Tracef("NewHandler: starting config file handler for %q", configFile)

	ch := make(chan v1alpha1.StunnerConfig, 1)
	if watch {
		h.Log.Infof("watching configuration file at %q", configFile)

		err := stunner.WatchConfig(ctx, stunner.Watcher{
			ConfigFile:    configFile,
			ConfigChannel: ch,
			Logger:        logger,
		})
		if err != nil {
			return nil, err
		}
	} else {
		// load config file once
		h.Log.Infof("loading configuration from config file %q", configFile)

		c, err := stunner.LoadConfig(configFile)
		if err != nil {
			return nil, err
		}

		ch <- *c
	}

	// our config watcher receiver
	go func() {
		defer close(ch)
		defer h.stunner.Close()

		for {
			select {
			case <-ctx.Done():
				return

			case c := <-ch:
				// lock for write
				h.lock.Lock()
				c.DeepCopyInto(&h.config)
				h.lock.Unlock()
			}
		}
	}()

	return &h, nil
}
