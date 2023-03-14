package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"github.com/l7mp/stunner/pkg/apis/v1alpha1"
	"strconv"
	"time"
)

func CreateAuthenticationToken(username string) (InternalAuthToken, error) {
	config, _ := getAuthConfig()

	returnUsername, password := CreateAuthentiactionTokenFromConfig(username, config)
	turnServers, _ := getTurnServers()
	duration := Timeout //Still should be taken from the config

	returnPassword := InternalAuthToken{Username: returnUsername,
		Password: password,
		Ttl:      int64(duration / time.Second),
		Uris:     turnServers}
	return returnPassword, nil
}

func CreateAuthentiactionTokenFromConfig(username string, config v1alpha1.AuthConfig) (string, string) {
	var returnUsername string
	var password string
	duration := Timeout //Still should be taken from the config
	if config.Type == "longterm" {
		sharedSecret := config.Credentials["secret"]
		returnUsername = createUsername(time.Now(), duration, username)
		password, _ = longTermCredentials(returnUsername, sharedSecret)
	} else if config.Type == "plaintext" {
		returnUsername = username
		password, _ = config.Credentials["password"]
	}
	return returnUsername, password
}

func createUsername(startTime time.Time, timeout time.Duration, username string) string {
	endTime := startTime.Add(timeout).Unix()
	timeUsername := strconv.FormatInt(endTime, 10)
	username = timeUsername + ":" + username
	return username
}

func longTermCredentials(username string, sharedSecret string) (string, error) {
	mac := hmac.New(sha1.New, []byte(sharedSecret))
	_, _ = mac.Write([]byte(username))
	password := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(password), nil
}
