// package handler implements the actual functions to generate TURN credentials

package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/l7mp/stunner"
	stnrv1a1 "github.com/l7mp/stunner/pkg/apis/v1alpha1"
	a12n "github.com/l7mp/stunner/pkg/authentication"

	"github.com/l7mp/stunner-auth-service/internal/config"
	"github.com/l7mp/stunner-auth-service/internal/store"
	"github.com/l7mp/stunner-auth-service/pkg/types"
)

func (h *Handler) GetIceAuth(w http.ResponseWriter, r *http.Request, params types.GetIceAuthParams) {
	h.log.Info("GetIceAuth: serving ICE config request", "params", params)

	if store.ConfigMaps.Len() == 0 {
		e := "no STUNner configuration available"
		h.log.Info("GetIceAuth: error", "message", e, "status", http.StatusInternalServerError)
		http.Error(w, e, http.StatusInternalServerError)
		return
	}

	iceConfig, err := h.getIceServerConf(params)
	if err != nil {
		e := "could not generate ICE auth token"
		h.log.Info("GetIceAuth: error", "message", e, "error", err.error, "status", err.status)
		http.Error(w, fmt.Sprintf("%s: %q", e, err.error), err.status)
		return
	}

	if len(*iceConfig.IceServers) == 0 {
		e := "could not generate ICE config: no valid listener found"
		h.log.Info("GetIceAuth: error", "message", e, "status", http.StatusNotFound)
		http.Error(w, e, http.StatusNotFound)
		return
	}

	h.log.Info("GetIceAuth: ready", "response", iceConfig, "status", 200)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_ = json.NewEncoder(w).Encode(iceConfig)
}

func (h *Handler) getIceServerConf(params types.GetIceAuthParams) (types.IceConfig, *hErr) {
	h.log.V(1).Info("getIceServerConf: serving ICE config request", "params", params)

	service := params.Service
	if service == nil || (service != nil && *service != types.GetIceAuthParamsServiceTurn) {
		return types.IceConfig{}, &hErr{errors.New(`"service" must be "turn"`),
			http.StatusBadRequest}
	}

	iceServers := []types.IceAuthenticationToken{}

	// try to generate an iceconfig for each config in the store
	for _, config := range store.ConfigMaps.Get() {
		ice, err := h.getIceServerConfForStunnerConf(params, config)
		if err != nil {
			h.log.Info("cannot generate ICE server config for Stunner conf",
				"error", err.Error(), "conf", config)
			continue
		}

		if ice == nil {
			continue
		}

		iceServers = append(iceServers, *ice)
	}

	policy := "all"
	if params.IceTransportPolicy != nil {
		policy = string(*params.IceTransportPolicy)
	}

	p := types.IceTransportPolicy(policy)
	iceConfig := types.IceConfig{
		IceServers:         &iceServers,
		IceTransportPolicy: &p,
	}

	h.log.V(1).Info("getIceServerConf: ready", "repsonse", iceConfig)

	return iceConfig, nil
}

func (h *Handler) getIceServerConfForStunnerConf(params types.GetIceAuthParams, stunnerConfig *stnrv1a1.StunnerConfig) (*types.IceAuthenticationToken, *hErr) {
	h.log.V(1).Info("getIceServerConfForStunnerConf: considering Stunner config",
		"stunner-config", stunnerConfig, "params", params)

	// should we generate an ICE server config for this stunner config?
	uris := []string{}
	for _, l := range stunnerConfig.Listeners {
		l := l
		// format is namespace/gateway/listener
		tokens := strings.Split(l.Name, "/")
		if len(tokens) != 3 {
			h.log.Info(`invalid Listener: name shoult be "namespace/gateway/listener"`,
				"name", l.Name)
			continue
		}
		namespace, gateway, listener := tokens[0], tokens[1], tokens[2]

		h.log.V(1).Info("considering Listener", "namespace", namespace,
			"gateway", gateway, "listener", listener)

		// filter
		if params.Namespace != nil && *params.Namespace != namespace {
			h.log.V(1).Info("ignoring listener due to namespace mismatch",
				"required-namespace", *params.Namespace,
				"listener-namespace", namespace)
			continue
		}

		if params.Namespace != nil && params.Gateway != nil && *params.Gateway != gateway {
			h.log.V(1).Info("ignoring listener due to gateway name mismatch",
				"required-name", *params.Gateway,
				"listener-name", gateway)
			continue
		}

		if params.Namespace != nil && params.Gateway != nil && params.Listener != nil &&
			*params.Listener != listener {
			h.log.V(1).Info("ignoring listener due to name mismatch", "required-name",
				*params.Listener, "listener-name", listener)
			continue
		}

		uri, err := stunner.GetUriFromListener(&l)
		if err != nil {
			h.log.Error(err, "cannor generate URI for listener")
			continue
		}

		uris = append(uris, uri)
	}

	if len(uris) == 0 {
		return nil, nil
	}

	auth := stunnerConfig.Auth
	userid := ""
	if params.Username != nil {
		userid = *params.Username
	}

	ttl := config.DefaultTimeout
	if params.Ttl != nil {
		ttl = time.Duration(int(*params.Ttl)) * time.Second
	}

	username, password := "", ""
	authType := auth.Type

	// aliases
	switch authType {
	// plaintext
	case "static", "plaintext":
		authType = "plaintext"
	case "ephemeral", "timewindowed", "longterm":
		authType = "longterm"
	}

	atype, err := stnrv1a1.NewAuthType(authType)
	if err != nil {
		return nil, &hErr{
			fmt.Errorf("Internal server error: %w", err),
			http.StatusInternalServerError}
	}

	// h.log.Info("Params", "username", userid, "ttl", ttl.String(), "params",
	// 	fmt.Sprintf("%#v", params))

	switch atype {
	case stnrv1a1.AuthTypePlainText:
		u, userFound := auth.Credentials["username"]
		p, passFound := auth.Credentials["password"]
		if !userFound || !passFound {
			return nil, &hErr{
				errors.New("Invalid STUNner config: no username or password " +
					"(auth: plaintext)"),
				http.StatusInternalServerError,
			}
		}
		username = u
		password = p

	case stnrv1a1.AuthTypeLongTerm:
		secret, secretFound := auth.Credentials["secret"]
		if !secretFound {
			return nil, &hErr{
				errors.New("Invalid STUNner config: no shared secret (auth: longterm)"),
				http.StatusInternalServerError}
		}
		username = a12n.GenerateTimeWindowedUsername(time.Now(), ttl, userid)

		p, err := a12n.GetLongTermCredential(username, secret)
		if err != nil {
			return nil, &hErr{
				fmt.Errorf("Cannot generate longterm credential: %w", err),
				http.StatusInternalServerError}
		}
		password = p
	}

	iceAuth := types.IceAuthenticationToken{
		Username:   &username,
		Credential: &password,
		Urls:       &uris,
	}

	h.log.V(1).Info("getIceServerConfForStunnerConf: ready", "repsonse", iceAuth)

	return &iceAuth, nil
}
