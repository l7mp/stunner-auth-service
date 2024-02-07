package config

import "time"

const (
	// DefaultTimeout is the default TURN credential timeout. Default is one day, in seconds.
	DefaultTimeout = 24 * time.Hour
)
