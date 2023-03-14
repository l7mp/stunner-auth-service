package config

import (
	"time"
)

const (
	// DefaultTimeout is the default TURN credential timeout. Default is one day, in seconds.
	DefaultTimeout = 24 * time.Hour
	// DefaultConfigPath is the default path at which to search for the running STUNner config,
	// override with the below environment variable.
	DefaultConfigPath = "/etc/stunnerd/stunnerd.conf"
	// ConfigPathEnvName is the name of the environment variable at which to search for the
	// running STUNner config.
	ConfigPathEnvName = "STUNNERD_CONFIG_PATH"
)
