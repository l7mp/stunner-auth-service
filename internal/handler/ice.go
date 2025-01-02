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
	stnrv1 "github.com/l7mp/stunner/pkg/apis/v1"
	a12n "github.com/l7mp/stunner/pkg/authentication"

	"github.com/l7mp/stunner-auth-service/internal/config"
	"github.com/l7mp/stunner-auth-service/pkg/types"
)

func (h *Handler) GetIceAuth(w http.ResponseWriter, r *http.Request, params types.GetIceAuthParams) {
	h.log.Infof("GetIceAuth: serving ICE config request with params %s", params.String())

	if h.NumConfig() == 0 {
		e := "no STUNner configuration available"
		h.log.Errorf("GetIceAuth: error: %s", e)
		http.Error(w, e, http.StatusInternalServerError)
		return
	}

	iceConfig, err := h.getIceServerConf(params)
	if err != nil {
		e := "could not generate ICE auth token"
		h.log.Errorf("GetIceAuth: error: %s", err.error)
		http.Error(w, fmt.Sprintf("%s: %q", e, err.error), err.status)
		return
	}

	if len(*iceConfig.IceServers) == 0 {
		e := "could not generate ICE config: no valid listener found"
		h.log.Errorf("GetIceAuth: error: %s", e)
		http.Error(w, e, http.StatusNotFound)
		return
	}

	h.log.Infof("GetIceAuth: response: %s, status: %d", iceConfig.String(), 200)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_ = json.NewEncoder(w).Encode(iceConfig)
}

func (h *Handler) getIceServerConf(params types.GetIceAuthParams) (types.IceConfig, *hErr) {
	h.log.Debugf("getIceServerConf: serving ICE config request %s", params.String())

	service := params.Service
	if service == nil || (service != nil && *service != types.GetIceAuthParamsServiceTurn) {
		return types.IceConfig{}, &hErr{errors.New(`"service" must be "turn"`),
			http.StatusBadRequest}
	}

	iceServers := []types.IceAuthenticationToken{}

	// try to generate an iceconfig for each config in the store
	h.store.Range(func(key, value any) bool {
		c, ok := value.(*stnrv1.StunnerConfig)
		if !ok {
			return false
		}

		ice, err := h.getIceServerConfForStunnerConf(params, c)
		if err != nil {
			h.log.Errorf("Cannot generate ICE server config for Stunner config: %s",
				err.Error())
			return true
		}

		if ice == nil {
			return true
		}

		iceServers = append(iceServers, *ice)
		return true
	})

	policy := "all"
	if params.IceTransportPolicy != nil {
		policy = string(*params.IceTransportPolicy)
	}

	p := types.IceTransportPolicy(policy)
	iceConfig := types.IceConfig{
		IceServers:         &iceServers,
		IceTransportPolicy: &p,
	}

	h.log.Debugf("getIceServerConf: response %s", iceConfig.String())

	return iceConfig, nil
}

func (h *Handler) getIceServerConfForStunnerConf(params types.GetIceAuthParams, stunnerConfig *stnrv1.StunnerConfig) (*types.IceAuthenticationToken, *hErr) {
	h.log.Debugf("getIceServerConfForStunnerConf: considering Stunner config %s", stunnerConfig.String())

	// should we generate an ICE server config for this stunner config?
	uris := []string{}
	for _, l := range stunnerConfig.Listeners {
		l := l
		// format is namespace/gateway/listener
		tokens := strings.Split(l.Name, "/")
		if len(tokens) != 3 {
			h.log.Errorf(`Invalid Listener %q: name should be "namespace/gateway/listener"`,
				l.Name)
			continue
		}
		namespace, gateway, listener := tokens[0], tokens[1], tokens[2]

		h.log.Debugf("Considering Listener: namespace: %s, gateway: %s, listener: %s", namespace,
			gateway, listener)

		if params.PublicAddr != nil {
			l.PublicAddr = *params.PublicAddr
			h.log.Debugf("Using public address from request: %s", l.PublicAddr)
		} else if config.PublicAddr != "" {
			l.PublicAddr = config.PublicAddr
			h.log.Debugf("Using public address from environment: %s", l.PublicAddr)
		}

		// filter
		if params.Namespace != nil && *params.Namespace != namespace {
			h.log.Debugf("Ignoring listener due to gateway namespace mismatch: "+
				"required-namespace: %s, gateway-namespace: %s",
				*params.Namespace, namespace)
			continue
		}

		if params.Namespace != nil && params.Gateway != nil && *params.Gateway != gateway {
			h.log.Debugf("Ignoring listener due to gateway name mismatch: "+
				"required-name: %s, gateway-name: %s",
				*params.Gateway, gateway)
			continue
		}

		if params.Namespace != nil && params.Gateway != nil && params.Listener != nil &&
			*params.Listener != listener {
			h.log.Debugf("Ignoring listener due to listener name mismatch: "+
				"required-name: %s, listener-name: %s",
				*params.Listener, listener)
			continue
		}

		uri, err := stunner.GetUriFromListener(&l)
		if err != nil {
			h.log.Errorf("Cannot generate URI for listener: %s", err.Error())
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

	atype, err := stnrv1.NewAuthType(authType)
	if err != nil {
		return nil, &hErr{
			fmt.Errorf("Internal server error: %w", err),
			http.StatusInternalServerError}
	}

	switch atype {
	case stnrv1.AuthTypePlainText:
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

	case stnrv1.AuthTypeLongTerm:
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

	h.log.Debugf("getIceServerConfForStunnerConf: response: %s", iceAuth.String())

	return &iceAuth, nil
}
