package auth_generation

import (
	"fmt"
	"github.com/l7mp/stunner/pkg/apis/v1alpha1"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"os"
	"strings"
	"time"
)

var ViperInstance *viper.Viper
var Timeout = time.Hour //One hour in secondsTODO: Why is this hard coded

func ReadConfigFromFile() {
	log.SetLevel(log.DebugLevel)
	pathToConfig := getPathFromEnv(os.Getenv, "STUNNERD_CONFIG_PATH")
	ViperInstance = viper.New()
	ViperInstance.SetConfigName("stunnerd.conf")
	ViperInstance.SetConfigType("json")

	ViperInstance.AddConfigPath(pathToConfig)
	if err := ViperInstance.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Panicf("Config file not found at %s", pathToConfig)
		} else {
			log.Panicf("Config file could not be parsed")
		}
	}
	ViperInstance.WatchConfig()
	log.Debugf("Values in Viper:\n%v", ViperInstance)
	viper.DebugTo(log.StandardLogger().Out)
}

func getPathFromEnv(getEnv func(string) string, env_key string) string {
	pathToConfig := getEnv(env_key)
	if len(pathToConfig) == 0 {
		log.Panicf("env var %s not set", env_key)
	}
	return pathToConfig
}

func getAuthConfig() (v1alpha1.AuthConfig, error) {

	var authConfig v1alpha1.AuthConfig

	supportedVersion := "v1alpha1"
	detectedVersion := ViperInstance.Get("version")
	if detectedVersion != supportedVersion {
		log.Warnf("Config version not supported, but trying to proceed anyway. Supported version: %s, detected version: %s", supportedVersion, detectedVersion)
		log.Debugf("%v", ViperInstance.AllKeys())
	}

	err := ViperInstance.UnmarshalKey("auth", &authConfig)
	if err != nil {
		log.Debug(authConfig)
		log.Error("Error unmarhaling  auth configuration")
		return v1alpha1.AuthConfig{}, err
	}

	err = authConfig.Validate()
	if err != nil {
		log.Debug(authConfig)
		log.Errorf("Error validating auth configuration: %s", err)
		return v1alpha1.AuthConfig{}, err
	}
	log.Infof("%s", authConfig)
	return authConfig, nil
}

// TODO: This should be rewritten to use normal unmarshaling, but currently the unmarshal doesn't return the ip addresss
func getTurnServers() ([]string, error) {
	supportedVersion := "v1alpha1"
	detectedVersion := ViperInstance.Get("version")
	if detectedVersion != supportedVersion {
		log.Warnf("Config version not supported, but trying to proceed anyway. Supported version: %s, detected version: %s", supportedVersion, detectedVersion)
		log.Debugf("%v", ViperInstance.AllKeys())
	}

	var asd []map[string]interface{}
	err := ViperInstance.UnmarshalKey("listeners", &asd)
	if err != nil {
		log.Infof("%v", err)
		return []string{}, err
	}
	var turnServers []string
	for _, contents := range asd {
		turnServers = append(turnServers, fmt.Sprintf("turn:%s:%.0f?transport=%s", contents["public_address"], contents["public_port"], strings.ToLower(fmt.Sprintf("%s", contents["protocol"]))))
	}
	log.Infof("Returned turn Servers:\n%v", turnServers)
	return turnServers, err
}
