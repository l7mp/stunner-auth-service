// package handler implements the actual functions to generate TURN credentials

package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	stnrv2 "github.com/l7mp/stunner/v2/pkg/apis/v2"
	a12n "github.com/l7mp/stunner/v2/pkg/authentication"

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
		c, ok := value.(*stnrv2.StunnerConfig)
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

func (h *Handler) getIceServerConfForStunnerConf(params types.GetIceAuthParams, stunnerConfig *stnrv2.StunnerConfig) (*types.IceAuthenticationToken, *hErr) {
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

		// only a listener feeding a TURN server has a TURN URI
		if s, err := stunnerConfig.GetServerConfig(l.FirstServer()); err != nil ||
			s.Type != stnrv2.ServerTypeTURN.String() {
			h.log.Debugf("Ignoring listener %q: it feeds no TURN server", l.Name)
			continue
		}

		// Determine the public addresses to advertise for this listener, in precedence order:
		// request param > env override > listener public_addresses > listener public_address. An
		// empty result lets NewURIFromListener fall back to the listener address.
		pubAddrs := l.PublicAddrs
		if len(pubAddrs) == 0 {
			pubAddrs = []string{l.PublicAddr}
		}
		switch {
		case params.PublicAddr != nil:
			pubAddrs = []string{*params.PublicAddr}
			h.log.Debugf("Using public address from request: %s", *params.PublicAddr)
		case config.PublicAddr != "":
			pubAddrs = []string{config.PublicAddr}
			h.log.Debugf("Using public address from environment: %s", config.PublicAddr)
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

		for _, addr := range pubAddrs {
			lc := l
			lc.PublicAddr = addr
			u, err := stnrv2.NewURIFromListener(&lc)
			if err != nil {
				h.log.Errorf("Cannot generate URI for listener: %s", err.Error())
				continue
			}
			uris = append(uris, u.String())
		}
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

	atype, err := stnrv2.NewAuthType(authType)
	if err != nil {
		return nil, &hErr{
			fmt.Errorf("internal server error: %w", err),
			http.StatusInternalServerError}
	}

	switch atype {
	case stnrv2.AuthTypePlainText:
		u, userFound := auth.Credentials["username"]
		p, passFound := auth.Credentials["password"]
		if !userFound || !passFound {
			return nil, &hErr{
				errors.New("invalid STUNner config: no username or password " +
					"(auth: plaintext)"),
				http.StatusInternalServerError,
			}
		}
		username = u
		password = p

	case stnrv2.AuthTypeLongTerm:
		secret, secretFound := auth.Credentials["secret"]
		if !secretFound {
			return nil, &hErr{
				errors.New("invalid STUNner config: no shared secret (auth: longterm)"),
				http.StatusInternalServerError}
		}
		username = a12n.GenerateTimeWindowedUsername(time.Now(), ttl, userid)

		p, err := a12n.GetLongTermCredential(username, secret)
		if err != nil {
			return nil, &hErr{
				fmt.Errorf("cannot generate longterm credential: %w", err),
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
