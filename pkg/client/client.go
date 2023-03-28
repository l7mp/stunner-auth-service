// Package client provides primitives to interact with the openapi HTTP API.
package client

import (
	"context"
	"fmt"
	"net/http"

	"github.com/l7mp/stunner-auth-service/internal/client"
	"github.com/l7mp/stunner-auth-service/pkg/types"
)

// The simplified main API.

type Client struct {
	client.ClientWithResponses
}

// NewClient creates a new stunner TURN authentication client.
func NewClient(server string, opts ...ClientOption) (*Client, error) {
	c, err := client.NewClientWithResponses(server)
	if err != nil {
		return nil, err
	}
	return &Client{ClientWithResponses: *c}, nil
}

// GetTurnAuthToken returns a TURN server authentication token from the TURN authentication server.
func (c *Client) GetTurnAuthToken(ctx context.Context, params *GetTurnAuthParams) (*TurnAuthenticationToken, error) {
	if params == nil {
		p := GetTurnAuthParams{}
		params = &p
	}

	if params.Service == "" {
		params.Service = types.GetTurnAuthParamsServiceTurn
	}

	r, err := c.GetTurnAuthWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}

	if r.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("GetIceConfig: HTTP error: status=%d, message=%q, body=%q",
			r.StatusCode(), r.Status(), string(r.Body))
	}

	return r.JSON200, nil
}

// GetIceConfig returns an ICE server configuration from the TURN authentication server.
func (c *Client) GetIceConfig(ctx context.Context, params *GetIceAuthParams) (*IceConfig, error) {
	if params == nil {
		p := GetIceAuthParams{}
		params = &p
	}

	if params.Service == nil {
		s := types.GetIceAuthParamsServiceTurn
		params.Service = &s
	}

	r, err := c.GetIceAuthWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}

	if r.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("GetIceConfig: HTTP error: status=%d, message=%q, body=%q",
			r.StatusCode(), r.Status(), string(r.Body))
	}

	return r.JSON200, nil
}
