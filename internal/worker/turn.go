package worker

import (
	"encoding/json"
	"net/http"

	"github.com/l7mp/stunner-auth-service/internal/auth"
	"github.com/l7mp/stunner-auth-service/internal/model"
)

func HandleTurnRequest(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	username := r.URL.Query().Get("username")
	if service != "turn" {
		http.Error(w, "Service is not turn", http.StatusBadRequest)
		return
	}

	internalAuthToken, err := auth.CreateAuthenticationToken(username)
	if err != nil {
		http.Error(w, "Error during auth token creation", http.StatusInternalServerError)
		return
	}
	returnAuthToken := convertInternalToTurnAuthToken(internalAuthToken)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err != json.NewEncoder(w).Encode(returnAuthToken) {
		http.Error(w, "Error during auth token serialization", http.StatusInternalServerError)
		return
	}

	return
}

func convertInternalToTurnAuthToken(internalAuthToken auth.InternalAuthToken) model.TurnAuthenticationToken {
	return model.TurnAuthenticationToken{
		Username: internalAuthToken.Username,
		Password: internalAuthToken.Password,
		Ttl:      internalAuthToken.Ttl,
		Uris:     internalAuthToken.Uris,
	}
}
