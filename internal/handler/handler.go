// package handler implements the actual functions to generate TURN credentials

package handler

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/pion/logging"

	stnrv1 "github.com/l7mp/stunner/pkg/apis/v1"
	cdsclient "github.com/l7mp/stunner/pkg/config/client"
)

type hErr struct {
	error
	status int
}

// Handler Implements server.ServerInterface
type Handler struct {
	store *sync.Map
	conf  chan *stnrv1.StunnerConfig
	log   logging.LeveledLogger
}

func NewHandler(conf chan *stnrv1.StunnerConfig, log logging.LeveledLogger) (*Handler, error) {
	return &Handler{
		store: &sync.Map{},
		conf:  conf,
		log:   log,
	}, nil
}

func (h *Handler) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case c := <-h.conf:
				if c.Admin.Name == "" {
					h.log.Error("Skipping received config contains invalid gateway id")
					continue
				}

				if cdsclient.IsConfigDeleted(c) {
					h.log.Debugf("Config deleted for gateway %q", c.Admin.Name)
					h.store.Delete(c.Admin.Name)
				}

				h.log.Debugf("New config available for gateway %q: %s",
					c.Admin.Name, c.String())
				h.store.Store(c.Admin.Name, c)
			}
		}
	}()
}

// config API
func (h *Handler) SetConfig(id string, conf *stnrv1.StunnerConfig) {
	h.store.Store(id, conf)
}

func (h *Handler) GetConfig(id string) *stnrv1.StunnerConfig {
	value, ok := h.store.Load(id)
	if !ok {
		return nil
	}
	c, ok := value.(*stnrv1.StunnerConfig)
	if !ok {
		return nil
	}
	return c
}

func (h *Handler) NumConfig() int {
	num := 0
	h.store.Range(func(key, value any) bool { num++; return true })
	return num
}

func (h *Handler) DumpConfig() string {
	ret := []string{}
	num := 0

	h.store.Range(func(key, value any) bool {
		c, ok := value.(*stnrv1.StunnerConfig)
		if !ok {
			return false
		}
		ret = append(ret, c.String())
		num++
		return true
	})

	return fmt.Sprintf("store (%d objects): %s", num, strings.Join(ret, ", "))
}

func (h *Handler) Reset() {
	h.store = &sync.Map{}
}
