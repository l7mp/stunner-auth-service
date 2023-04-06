// package handler implements the actual functions to generate TURN credentials

package handler

import (
	"github.com/go-logr/logr"
)

type hErr struct {
	error
	status int
}

// Handler Implements server.ServerInterface
type Handler struct {
	log logr.Logger
}

func NewHandler(log logr.Logger) (*Handler, error) {
	h := Handler{log: log.WithName("handler")}

	return &h, nil
}
