package worker

import (
	"encoding/json"
	"net/http"

	"github.com/l7mp/stunner-auth-service/internal/auth"
	"github.com/l7mp/stunner-auth-service/internal/model"
)

func HandleIceRequest(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	username := r.URL.Query().Get("username")
	iceTransportPolicy := r.URL.Query().Get("icetransportpolicy")
	if service != "turn" {
		http.Error(w, "Service is not turn", http.StatusBadRequest)
		return
	}

	internalAuthToken, err := auth.CreateAuthenticationToken(username)
	if err != nil {
		http.Error(w, "Error during auth token creation", http.StatusInternalServerError)
		return
	}
	authToken := convertInternalToIceAuthToken(internalAuthToken)

	iceConfig := model.IceConfig{
		IceServers:         []model.IceAuthenticationToken{authToken},
		IceTransportPolicy: iceTransportPolicy,
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err != json.NewEncoder(w).Encode(iceConfig) {
		http.Error(w, "Error during auth token serialization", http.StatusInternalServerError)
		return
	}

	return
}

func convertInternalToIceAuthToken(internalAuthToken auth.InternalAuthToken) model.IceAuthenticationToken {
	return model.IceAuthenticationToken{
		Url:        internalAuthToken.Uris,
		Username:   internalAuthToken.Username,
		Credential: internalAuthToken.Password,
	}
}
