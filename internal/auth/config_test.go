package auth

import (
	"bytes"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"testing"
)

func assertPanic(t *testing.T, f func(getEnv func(string) string, env_key string) string, getEnv func(string) string, env_key string) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()
	f(getEnv, env_key)
}

func TestConfig(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	type Wants struct {
		authtype string
		realm    string
		username string
		password string
		secret   string
	}
	tests := []struct {
		name    string
		config  string
		wants   Wants
		wantErr bool
	}{
		{
			name: "Basic",
			config: `
            version: v1alpha1
            auth:
              type: plaintext
              realm: $STUNNER_REALM
              credentials:
                username: $STUNNER_USERNAME
                password: $STUNNER_PASSWORD
                secret: $STUNNER_SHARED_SECRET
                # - name: media-server-cluster`,
			wants: Wants{
				authtype: "plaintext",
				realm:    "$STUNNER_REALM",
				username: "$STUNNER_USERNAME",
				password: "$STUNNER_PASSWORD",
				secret:   "$STUNNER_SHARED_SECRET",
			},
		},
		{
			name: "Missing type and realm fields - testing defaults",
			config: `
            version: v1alpha1
            auth:
              credentials:
                username: $STUNNER_USERNAME
                password: $STUNNER_PASSWORD`,
			wants: Wants{
				authtype: "plaintext",
				realm:    "stunner.l7mp.io",
				username: "$STUNNER_USERNAME",
				password: "$STUNNER_PASSWORD",
			},
		},
		{
			name: "Only giving plaintext - testing validation",
			config: `
            version: v1alpha1
            auth:
              type: plaintext`,
			wantErr: true,
		},
		{
			name: "Wrong version",
			config: `
            version: veryWrongVersion
            auth:
              type: plaintext
              credentials:
                username: $STUNNER_USERNAME
                password: $STUNNER_PASSWORD`,
			wantErr: false,
			wants: Wants{
				authtype: "plaintext",
				realm:    "stunner.l7mp.io",
				username: "$STUNNER_USERNAME",
				password: "$STUNNER_PASSWORD",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ViperInstance = viper.New()
			ViperInstance.SetConfigType("yaml")
			var yamlExample = []byte(tt.config)

			err := ViperInstance.ReadConfig(bytes.NewBuffer(yamlExample))
			if err != nil {
				t.Errorf("Failed reading test config %s", err)
			}
			authconfig, err := getAuthConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("getAuthConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if authconfig.Type != tt.wants.authtype {
				t.Errorf("authconfig.Type = %v, want %v", authconfig.Type, tt.wants.authtype)
			}
			if authconfig.Realm != tt.wants.realm {
				t.Errorf("authconfig.Realm = %v, want %v", authconfig.Realm, tt.wants.realm)
			}
			if authconfig.Credentials["username"] != tt.wants.username {
				t.Errorf("authconfig.Credentials[\"username\"] = %v, want %v", authconfig.Credentials["username"], tt.wants.username)
			}
			if authconfig.Credentials["password"] != tt.wants.password {
				t.Errorf("authconfig.Credentials[\"password\"]= %v, want %v", authconfig.Credentials["password"], tt.wants.password)
			}
			if authconfig.Credentials["secret"] != tt.wants.secret {
				t.Errorf("authconfig.Credentials[\"secret\"] = %v, want %v", authconfig.Credentials["secret"], tt.wants.secret)
			}
		})
	}
}

func Test_getPathFromEnv(t *testing.T) {
	type args struct {
		getEnv  func(string) string
		env_key string
	}
	tests := []struct {
		name      string
		args      args
		want      string
		wantPanic bool
	}{
		{name: "Default", args: args{getEnv: func(s string) string { return s }, env_key: "test_env_key"}, want: "test_env_key"},
		{name: "Env var not set", args: args{getEnv: func(s string) string { return "" }, env_key: "test_env_key"}, wantPanic: true},
	}
	for _, tt := range tests {
		if tt.wantPanic {
			assertPanic(t, getPathFromEnv, tt.args.getEnv, tt.args.env_key)
		} else {
			t.Run(tt.name, func(t *testing.T) {
				if got := getPathFromEnv(tt.args.getEnv, tt.args.env_key); got != tt.want {
					t.Errorf("getPathFromEnv() = %v, want %v", got, tt.want)
				}
			})
		}
	}
}
