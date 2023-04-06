// package handler implements the actual functions to generate TURN credentials

package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/l7mp/stunner-auth-service/internal/config"
	"github.com/l7mp/stunner-auth-service/internal/store"
	"github.com/l7mp/stunner-auth-service/pkg/types"
)

func (h *Handler) GetTurnAuth(w http.ResponseWriter, r *http.Request, params types.GetTurnAuthParams) {
	h.log.Info("GetTurnAuth: serving TURN auth token request", "params", params)

	// build iceparams and convert to turn REST API response
	svc := params.Service
	iceParams := types.GetIceAuthParams{
		Service:   (*types.GetIceAuthParamsService)(&svc),
		Username:  params.Username,
		Ttl:       params.Ttl,
		Key:       params.Key,
		Namespace: params.Namespace,
		Gateway:   params.Gateway,
		Listener:  params.Listener,
	}

	if store.ConfigMaps.Len() == 0 {
		http.Error(w, "No STUNner configuration available", http.StatusInternalServerError)
		return
	}

	ice, err := h.getIceServerConf(iceParams)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error during TURN auth token serialization: %q", err.error),
			err.status)
		return
	}

	// reparse ttl
	ttl := config.DefaultTimeout
	if params.Ttl != nil {
		ttl = time.Duration(int(*params.Ttl)) * time.Second
	}

	duration := int64(ttl.Seconds())
	servers := *ice.IceServers

	if len(servers) != 1 {
		h.log.Info("multiple TURN servers available: generating credentials only for the first one",
			"servers", fmt.Sprintf("%#v", servers))
	}

	turnAuthToken := types.TurnAuthenticationToken{
		Username: servers[0].Username,
		Password: servers[0].Credential,
		Ttl:      &duration,
		Uris:     servers[0].Urls,
	}

	h.log.Info("GetTurnAuth: ready", "response", turnAuthToken)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_ = json.NewEncoder(w).Encode(turnAuthToken)
}
