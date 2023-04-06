// Package types provides primitives to interact with the openapi HTTP API.
package types

import (
	"encoding/json"
)

func (p *GetTurnAuthParams) String() string       { return stringify(p) }
func (p *GetIceAuthParams) String() string        { return stringify(p) }
func (p *TurnAuthenticationToken) String() string { return stringify(p) }
func (p *IceConfig) String() string               { return stringify(p) }
func (p *IceAuthenticationToken) String() string  { return stringify(p) }

func stringify(p any) string {
	b, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	return string(b)
}
