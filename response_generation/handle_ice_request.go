package response_generation

import (
	"authhandler/auth_generation"
	swagger "authhandler/swagger_api_models"
	"encoding/json"
	"net/http"
)

func HandleIceRequest(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	username := r.URL.Query().Get("username")
	iceTransportPolicy := r.URL.Query().Get("icetransportpolicy")
	if service != "turn" {
		http.Error(w, "Service is not turn", http.StatusBadRequest)
		return
	}

	internalAuthToken, err := auth_generation.CreateAuthenticationToken(username)
	if err != nil {
		http.Error(w, "Error during auth token creation", http.StatusInternalServerError)
		return
	}
	authToken := convertInternalToIceAuthToken(internalAuthToken)

	iceConfig := swagger.IceConfig{IceServers: []swagger.IceAuthenticationToken{authToken}, IceTransportPolicy: iceTransportPolicy}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	response, _ := json.Marshal(iceConfig)
	_, err = w.Write(response)
	if err != nil {
		http.Error(w, "Error during response creation", http.StatusInternalServerError)
		return
	}
}

func convertInternalToIceAuthToken(internalAuthToken auth_generation.InternalAuthToken) swagger.IceAuthenticationToken {
	return swagger.IceAuthenticationToken{
		Url:        internalAuthToken.Uris,
		Username:   internalAuthToken.Username,
		Credential: internalAuthToken.Password,
	}
}
