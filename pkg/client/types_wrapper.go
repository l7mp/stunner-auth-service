package client

import (
	"encoding/json"

	"github.com/l7mp/stunner-auth-service/internal/client"
	"github.com/l7mp/stunner-auth-service/pkg/types"
)

type ClientOption = client.ClientOption

type GetIceAuthParams = types.GetIceAuthParams
type GetTurnAuthParams = types.GetTurnAuthParams
type GetTurnAuthParamsService = types.GetTurnAuthParamsService

type TurnAuthenticationToken = types.TurnAuthenticationToken
type IceConfig = types.IceConfig

type GetTurnAuthResponse = client.GetTurnAuthResponse
type GetIceAuthResponse = client.GetIceAuthResponse

func PrintAuthToken(t *TurnAuthenticationToken) string {
	json, err := json.Marshal(t)
	if err != nil {
		return ""
	}
	return string(json)
}

func PrintIceConfig(c *IceConfig) string {
	json, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return string(json)
}
