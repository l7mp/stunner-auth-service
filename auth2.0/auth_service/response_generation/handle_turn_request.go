package response_generation

import (
	"authhandler/auth_generation"
	swagger "authhandler/swagger_api_models"
	"encoding/json"
	"net/http"
)

func HandleTurnRequest(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	username := r.URL.Query().Get("username")
	if service != "turn" {
		http.Error(w, "Service is not turn", http.StatusBadRequest)
		return
	}

	internalAuthToken, err := auth_generation.CreateAuthenticationToken(username)
	if err != nil {
		http.Error(w, "Error during auth token creation", http.StatusInternalServerError)
		return
	}
	returnAuthToken := convertInternalToTurnAuthToken(internalAuthToken)

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	response, _ := json.Marshal(returnAuthToken)
	_, err = w.Write(response)
	if err != nil {
		http.Error(w, "Error during response creation", http.StatusInternalServerError)
		return
	}
}

func convertInternalToTurnAuthToken(internalAuthToken auth_generation.InternalAuthToken) swagger.TurnAuthenticationToken {
	return swagger.TurnAuthenticationToken{Username: internalAuthToken.Username,
		Password: internalAuthToken.Password,
		Ttl:      internalAuthToken.Ttl,
		Uris:     internalAuthToken.Uris}
}
