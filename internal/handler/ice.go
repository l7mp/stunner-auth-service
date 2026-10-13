// package handler implements the actual functions to generate TURN credentials

package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	stnrv2 "github.com/l7mp/stunner/v2/pkg/apis/v2"

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

	userid := ""
	if params.Username != nil {
		userid = *params.Username
	}
	ttl := config.DefaultTimeout
	if params.Ttl != nil {
		ttl = time.Duration(int(*params.Ttl)) * time.Second
	}
	// one expiry for the whole request, so that every URI of a policy carries the same credentials
	expiry := time.Now().Add(ttl)

	iceServers := []types.IceAuthenticationToken{}

	// try to generate an iceconfig for each config in the store
	h.store.Range(func(key, value any) bool {
		c, ok := value.(*stnrv2.StunnerConfig)
		if !ok {
			return false
		}

		iceServers = append(iceServers, h.getIceServerConfForStunnerConf(params, c, userid,
			expiry)...)
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

// getIceServerConfForStunnerConf returns the ICE servers of a config: the TURN URIs of its
// listeners, one ICE server per credentials.
func (h *Handler) getIceServerConfForStunnerConf(params types.GetIceAuthParams, stunnerConfig *stnrv2.StunnerConfig, userid string, expiry time.Time) []types.IceAuthenticationToken {
	h.log.Debugf("getIceServerConfForStunnerConf: considering Stunner config %s", stunnerConfig.String())

	// a public address from the request, or else from the environment, overrides the ones of
	// the listeners
	addr := config.PublicAddr
	if params.PublicAddr != nil {
		addr = *params.PublicAddr
	}
	if addr != "" {
		c := *stunnerConfig
		c.Listeners = slices.Clone(c.Listeners)
		for i := range c.Listeners {
			c.Listeners[i].PublicAddr, c.Listeners[i].PublicAddrs = addr, nil
		}
		stunnerConfig = &c
	}

	// the URIs of the listeners, by their credentials
	type credentials struct{ username, password string }
	uris, creds := map[credentials][]string{}, []credentials{}
	for _, l := range stunnerConfig.Listeners {
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

		lus, err := stunnerConfig.GetTURNURIForListener(l.Name, userid, expiry)
		if err != nil {
			h.log.Infof("Ignoring listener %q: %s", l.Name, err.Error())
			continue
		}
		for _, u := range lus {
			c := credentials{u.Username, u.Password}
			if _, ok := uris[c]; !ok {
				creds = append(creds, c)
			}
			uris[c] = append(uris[c], u.String())
		}
	}

	ret := []types.IceAuthenticationToken{}
	for _, c := range creds {
		us := uris[c]
		ice := types.IceAuthenticationToken{Username: &c.username, Credential: &c.password,
			Urls: &us}
		h.log.Debugf("getIceServerConfForStunnerConf: ICE server: %s", ice.String())
		ret = append(ret, ice)
	}
	return ret
}
