package auth

import (
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v2"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/l7mp/stunner/pkg/apis/v1alpha1"

	authconf "github.com/l7mp/stunner-auth-service/internal/config"
)

func TestLongTermCredentials(t *testing.T) {
	type args struct {
		username     string
		sharedSecret string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{name: "Basic function 1", args: args{username: "1212:asdasdasd", sharedSecret: "asdasd"}, want: "7Hjq4BOm5P4fC4P4FcfsYTjtKJM="},
		{name: "Basic function 2", args: args{username: "1998:isty", sharedSecret: "zombor"}, want: "UtGmS2eqtwZ3JgSFjd83/nfmnAg="},
		{name: "Empty string", args: args{username: "", sharedSecret: ""}, want: "+9sdGxiqbAgyS31ktx+3Y3BpDh0="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := longTermCredentials(tt.args.username, tt.args.sharedSecret)
			if (err != nil) != tt.wantErr {
				t.Errorf("longTermCredentials() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("longTermCredentials() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_createAuthenticationToken(t *testing.T) {
	type args struct {
		username string
	}
	var tests []struct {
		name    string
		args    args
		want    InternalAuthToken
		wantErr bool
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateAuthenticationToken(tt.args.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("createAuthenticationToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("createAuthenticationToken() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_createUsername(t *testing.T) {
	type args struct {
		startTime time.Time
		timeout   time.Duration
		username  string
	}
	tests := []struct {
		name     string
		args     args
		username string
	}{
		{name: "Basic", args: args{username: "isti", startTime: time.UnixMilli(0), timeout: time.Duration(0)}, username: "0:isti"},
		{name: "Add duration", args: args{username: "isti", startTime: time.UnixMicro(0), timeout: time.Duration(2000000000)}, username: "2:isti"},
		{name: "Add longer duration", args: args{username: "isti", startTime: time.UnixMicro(0), timeout: time.Duration(8000000000000)}, username: "8000:isti"},
		{name: "Different username", args: args{username: "almakorte", startTime: time.UnixMicro(0), timeout: time.Duration(2000000000)}, username: "2:almakorte"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := createUsername(tt.args.startTime, tt.args.timeout, tt.args.username)
			if got != tt.username {
				t.Errorf("createUsername() got1 = %v, want %v", got, tt.username)
			}
		})
	}
}
func Test_againstTurn(t *testing.T) {
	secret := "asd"
	username, password, err := turn.GenerateLongTermCredentials(secret, authconf.DefaultTimeout)
	result, err := longTermCredentials(username, secret)
	log.Infof("%s, %s", password, result)
	if err != nil {
		t.Errorf("Got error: %v", err)
	}
	if result != password {
		t.Errorf("longTermCredentials got1 = %v, want %v", result, password)
	}
}
func Test_LongTermAuth(t *testing.T) {
	const sharedSecret = "HELLO_WORLD"

	serverListener, err := net.ListenPacket("udp4", "0.0.0.0:3478")
	assert.NoError(t, err)

	server, err := turn.NewServer(turn.ServerConfig{
		AuthHandler: func(username, realm string, srcAddr net.Addr) (key []byte, ok bool) {
			log.Tracef("Authentication username=%q realm=%q srcAddr=%v\n", username, realm, srcAddr)
			timestamp := strings.Split(username, ":")[0]
			t, err := strconv.Atoi(timestamp)
			if err != nil {
				log.Errorf("Invalid time-windowed username %q", username)
				return nil, false
			}
			if int64(t) < time.Now().Unix() {
				log.Errorf("Expired time-windowed username %q", username)
				return nil, false
			}
			password, err := longTermCredentials(username, sharedSecret)
			if err != nil {
				log.Error(err.Error())
				return nil, false
			}
			return turn.GenerateAuthKey(username, realm, password), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: serverListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP("127.0.0.1"),
					Address:      "0.0.0.0",
				},
			},
		},
		Realm:         "pion.ly",
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	assert.NoError(t, err)

	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	assert.NoError(t, err)
	Username, Password := CreateAuthentiactionTokenFromConfig("custom_random_username", v1alpha1.AuthConfig{Type: "longterm", Credentials: map[string]string{
		"secret": sharedSecret}})
	assert.NoError(t, err)
	log.Infof("%s, %s", Username, Password)
	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: "0.0.0.0:3478",
		TURNServerAddr: "0.0.0.0:3478",
		Conn:           conn,
		Username:       Username,
		Password:       Password,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	})
	assert.NoError(t, err)
	assert.NoError(t, client.Listen())

	relayConn, err := client.Allocate()
	assert.NoError(t, err)

	client.Close()
	assert.NoError(t, relayConn.Close())
	assert.NoError(t, conn.Close())
	assert.NoError(t, server.Close())
}
func Test_plaintextAuth(t *testing.T) {
	const presharedPassword = "HELLO_WORLD"
	const presharedUsername = "FERI"
	serverListener, err := net.ListenPacket("udp4", "0.0.0.0:3478")
	assert.NoError(t, err)

	server, err := turn.NewServer(turn.ServerConfig{
		AuthHandler: func(username string, realm string, srcAddr net.Addr) ([]byte, bool) {
			log.Infof("plaintext auth request: username=%q realm=%q srcAddr=%v\n",
				username, realm, srcAddr)

			key := turn.GenerateAuthKey(username, realm, presharedPassword)
			if username == presharedUsername {
				return key, true
			}

			return nil, false
		},
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: serverListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP("127.0.0.1"),
					Address:      "0.0.0.0",
				},
			},
		},
		Realm:         "pion.ly",
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	assert.NoError(t, err)

	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	assert.NoError(t, err)
	Username, Password := CreateAuthentiactionTokenFromConfig(presharedUsername, v1alpha1.AuthConfig{Type: "plaintext", Credentials: map[string]string{
		"password": presharedPassword}})
	assert.NoError(t, err)
	log.Infof("%s, %s", Username, Password)
	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: "0.0.0.0:3478",
		TURNServerAddr: "0.0.0.0:3478",
		Conn:           conn,
		Username:       Username,
		Password:       Password,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	})
	assert.NoError(t, err)
	assert.NoError(t, client.Listen())

	relayConn, err := client.Allocate()
	assert.NoError(t, err)

	client.Close()
	assert.NoError(t, relayConn.Close())
	assert.NoError(t, conn.Close())
	assert.NoError(t, server.Close())
}
