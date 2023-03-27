// package handler implements the actual functions to generate TURN credentials

package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/l7mp/stunner"
	"github.com/l7mp/stunner/pkg/apis/v1alpha1"
	a12n "github.com/l7mp/stunner/pkg/authentication"

	"github.com/l7mp/stunner-auth-service/internal/config"
	"github.com/l7mp/stunner-auth-service/pkg/types"
)

type hErr struct {
	error
	status int
}

func (h *Handler) GetTurnAuth(w http.ResponseWriter, r *http.Request, params types.GetTurnAuthParams) {
	h.Log.Info("GetTurnAuth: serving TURN auth token request")

	// build iceparams and convert to turn REST API response
	svc := params.Service
	iceParams := types.GetIceAuthParams{
		Service:  (*types.GetIceAuthParamsService)(&svc),
		Username: params.Username,
		Ttl:      params.Ttl,
		Key:      params.Key,
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
	turnAuthToken := types.TurnAuthenticationToken{
		Username: servers[0].Username,
		Password: servers[0].Credential,
		Ttl:      &duration,
		Uris:     servers[0].Urls,
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_ = json.NewEncoder(w).Encode(turnAuthToken)
}

func (h *Handler) GetIceAuth(w http.ResponseWriter, r *http.Request, params types.GetIceAuthParams) {
	h.Log.Info("GetIceAuth: serving ICE config request")

	iceConfig, err := h.getIceServerConf(params)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error during ICE auth token serialization: %q", err.error),
			err.status)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	_ = json.NewEncoder(w).Encode(iceConfig)
}

func (h *Handler) getIceServerConf(params types.GetIceAuthParams) (types.IceConfig, *hErr) {
	ice := types.IceConfig{}

	// lock for reading
	h.lock.RLock()
	defer h.lock.RUnlock()

	auth := h.config.Auth

	service := params.Service
	if service == nil || (service != nil && *service != types.GetIceAuthParamsServiceTurn) {
		return ice, &hErr{errors.New(`"service" must be "turn"`),
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

	policy := "all"
	if params.IceTransportPolicy != nil {
		policy = string(*params.IceTransportPolicy)
	}

	username, password := "", ""
	atype, err := v1alpha1.NewAuthType(auth.Type)
	if err != nil {
		return ice, &hErr{
			fmt.Errorf("Internal server error: %w", err),
			http.StatusInternalServerError}
	}

	h.Log.Debugf("Params: username=%q, ttl=%q, policy=%q", userid, ttl.String(), policy)

	switch atype {
	case v1alpha1.AuthTypePlainText:
		u, userFound := auth.Credentials["username"]
		p, passFound := auth.Credentials["password"]
		if !userFound || !passFound {
			return ice, &hErr{
				errors.New("Invalid STUNner config: no username or password " +
					"(auth: plaintext)"),
				http.StatusInternalServerError,
			}
		}
		username = u
		password = p

	case v1alpha1.AuthTypeLongTerm:
		secret, secretFound := auth.Credentials["secret"]
		if !secretFound {
			return ice, &hErr{
				errors.New("Invalid STUNner config: no shared secret (auth: longterm)"),
				http.StatusInternalServerError}
		}
		username = a12n.GenerateTimeWindowedUsername(time.Now(), ttl, userid)
		p, err := a12n.GetLongTermCredential(username, secret)
		if err != nil {
			return ice, &hErr{
				fmt.Errorf("Cannot generate longterm credential: %w", err),
				http.StatusInternalServerError}
		}
		password = p
	}

	uris, err := stunner.GetTurnUris(&h.config)
	if err != nil {
		return ice, &hErr{
			fmt.Errorf("Invalid STUNner listener config: %w", err),
			http.StatusInternalServerError}
	}

	p := types.IceTransportPolicy(policy)
	ice = types.IceConfig{
		IceServers: &[]types.IceAuthenticationToken{
			{
				Username:   &username,
				Credential: &password,
				Urls:       &uris,
			},
		},
		IceTransportPolicy: &p,
	}

	return ice, nil
}
