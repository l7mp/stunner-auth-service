package client

import (
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
