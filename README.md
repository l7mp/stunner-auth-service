# A REST API for generating STUNner TURN authentication credentials 

*Work in progress* 

This service implements the [*REST API For Access To TURN
Services*](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00) IETF draft
specification to assist in accessing the TURN services provided by
[STUNner](https://github.com/l7mp/stunner). While STUNner allows a fixed username/password pair to
be used for *all* clients this mode is not recommended for production use; instead this service can
be used to generate ephemeral (i.e. time-limited) credentials. The usage of ephemeral credentials
ensures that access to STUNner can be controlled even if the credentials can be discovered by the
user, as is the case in WebRTC where TURN credentials must be specified in JavaScript.

## Description

By providing a cloud-based relay service, STUNner ensures that a WebRTC media connection can be
established via TURN even when one or both sides is incapable of a direct P2P connection.  However,
as a relay service, STUNner imposes a nontrivial cost on the service provider.  Therefore, it is
recommended to tightly control user access to the TURN services provided by STUNner.

TURN implements a mechanism to control access via long-term credentials that are provided as part of
the TURN protocol.  It is expected that these credentials will be kept secret; if the credentials
are discovered, the TURN server could be used by unauthorized users or applications.  However, in
web applications, ensuring this secrecy is typically impossible.

To address this problem, this service provides a REST API that can be used to retrieve TURN
credentials specifically for STUNner as the TURN server. The service watches the running STUNner
dataplane configuration (usually the configmap called `stunnerd-config` in the current namespace)
and automatically generates TURN credentials that will match the current [authentication
settings](https://github.com/l7mp/stunner/blob/main/doc/AUTH.md) for STUNner. The main use of this
service is by the WebRTC application server to generate an [ICE server
configuration](https://developer.mozilla.org/en-US/docs/Web/API/RTCIceServer) to be returned to
clients to enable them to connect via STUNner as the TURN server.

## Usage

Most users will have the Stunner authentication REST API server automatically deployed into their
cluster by the Stunner [Helm charts](https://github.com/l7mp/stunner-helm). You can reach the REST
API server like you reach any other HTTP service in Kubernetes.

The simplest way to experiment with the REST API server is to build and run the server locally,
bootstrap it with a valid Stunner configuration, and send queries to it using curl. We provide a
sample Stunner config for this purpose named `stunnerd-test.yaml`.

The below will re-generate the client-side and server-side HTTP request handlers from the OpenAPI
spec available at `api/stunner.yaml` and start a new REST API server locally on port 8087 (`--port
8087`), in verbose mode (`--verbose`), using the Stunner config file `stunnerd-test.yaml` (`--config
stunnerd-test.yaml`), and also enabling watch-mode (`--watch`):

``` console
make generate
go run main.go --verbose --config stunnerd-test.yaml --watch
```

The below will query the REST API for a TURN authentication token, setting the username to
`my-user` and the expiration time of the returned TURN credentials to 1 hour from the present
(`ttl` is set to 3600 sec).

``` console
curl -s http://localhost:8087?service=turn\&username=my-user\&ttl=3600| jq .
{
  "username": "1680036887:my-user"
  "password": "P8pCmIfe8faGAcbsxevYv35l0j4=",
  "ttl": 3600,
  "uris": [
    "turn:1.2.3.4:3478?transport=udp",
    "turn:1.2.3.4:3478?transport=tcp",
    "turns:127.0.0.1:3479?transport=tcp",
    "turns:127.0.0.1:3479?transport=udp"
  ],
}
```

Note that `service=turn` is mandatory, the rest of the parameters are optional; see the [*REST API
For Access To TURN
Services*](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00) IETF draft
specification to understand the fields of the returned JSON. Note also that `jq` is used above only
to pretty-print the response JSON, feel free to remove it.

Suppose now that the public IP address of the UDP and the TCP TURN listeners (the first two URIs
above) changes from `1.2.3.4` to `5.6.7.8`. This is reconciled by the [stunner gateway
operator](https://github.com/l7mp/stunner-gateway-operator) rendering a new running config for
Stunner, which in the below we simulate locally by exchanging the IP addresses in the local Stunner
config file as follows:

```console
sed -i 's/1\.2\.3\.4/5.6.7.8/g' stunnerd-test.yaml 
```

The REST API server watches this configuration file so it will immediately pick up the new IP
addresses. This can be seen by asking for another TURN auth token from the auth server:

```console
curl -s http://localhost:8087?service=turn\&username=my-user\&ttl=3600| jq .
{
  "password": "PE7kz+9BJIxe98eST0IE2yo66nI=",
  "ttl": 3600,
  "uris": [
    "turn:5.6.7.8:3478?transport=udp",
    "turn:5.6.7.8:3478?transport=tcp",
    "turns:127.0.0.1:3479?transport=tcp",
    "turns:127.0.0.1:3479?transport=udp"
  ],
  "username": "1680037254:my-user"
}
```

Observe that the new IP addresses in the first to URIs. 

In addition to TURN authentication tokens, the REST API server can also generate full [ICE
configurations](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection#parameters). These
should be sent from the application to the clients, so that clients can use the correct ICE config
to connect via STUNner as the TURN server. Use the `/ice` API endpoint to generate an ICE config:

``` console
curl -s http://localhost:8087/ice?service=turn\&username=my-user\&ttl=3600| jq .
{
  "iceServers": [
    {
      "credential": "Ad5JZbsKve06gZj+6kH9EeJYTJA=",
      "urls": [
        "turn:5.6.7.8:3478?transport=udp",
        "turn:5.6.7.8:3478?transport=tcp",
        "turns:127.0.0.1:3479?transport=tcp",
        "turns:127.0.0.1:3479?transport=udp"
      ],
      "username": "1680037776:my-user"
    }
  ],
  "iceTransportPolicy": "all"
}
```

## API

The REST API exposes two API endpoints: `getTurnAuth` can be called to obtain a TURN authentication
credential stanza as in the [*REST API For Access To TURN
Services*](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00) spec, while
`getIceAuth` returns an [ICE server
configuration](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection#parameters)
ready to be supplied to an `RTCPeerConnection` call as configuration. The difference between the
two is mostly syntactic: we recommend the use of the latter API as it provides a standard format
expected by client WebRTC implementations.

## The `getTurnAuth` API

The `getTurnAuth` API can be used to obtain a TURN authentication credential stanza as in the
[*REST API For Access To TURN
Services*](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00) spec.

### Request

A request to the `getTurnAuth` API endpoint includes the following parameters, specified in the URL:
- `service`: specifies the desired service (turn)
- `username`: an optional user id to be associated with the credentials
- `key`: if an API key is used for authentication, the API key

### Response

The response is returned with content-type `"application/json"`, and consists of a JSON object with the following parameters:
- `username`: the TURN username to use; depending on the running STUNner configuration this may be
  a fix username or a colon-delimited combination of an expiration time as a UNIX timestamp and the
  username parameter from the request (if specified).
- `password`: the TURN password to use; again, depending on the running STUNner configuration this
  may be a fix password or a value dynamically computed from the a secret key shared with STUNner
  and the returned username value, see details in the
  [spec](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00).
- `ttl`: the duration for which the username and password are valid, in seconds, default is one day
  (86400 seconds).
- `uris`: an array of TURN URIs, indicating the addresses and/or protocols that can be used to
  reach STUNner.  Each Gateway will be wrapped by STUNner with a Kubernetes LoadBalancer service
  and the public IP address of that LoadBalancer service will be used as a TURN server address in
  the returned URI, the public port as the TURN port, and the Gateway protocol as the TURN
  protocol.

### Example

Consider the below STUNner configuration:

```yaml
apiVersion: stunner.l7mp.io/v1alpha1
kind: GatewayConfig
metadata:
  name: stunner-gatewayconfig
spec:
  authType: plaintext
  userName: "user-1"
  password: "pass-1"
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: Gateway
metadata:
  name: stunner-gateway
spec:
  gatewayClassName: stunner-gatewayclass
  listeners:
    - name: tcp-listener
      port: 3478
      protocol: TCP
    - name: tls-listener
      port: 443
      protocol: TLS
      tls:
        mode: Terminate
        certificateRefs:
          - name: tls-secret
```

Furthermore, suppose that public IP for the LoadBalancer service that exposes this gateway is
`1.2.3.4` and assume the following request to the `getTurnAuth` API:
`GET/?service=turn&username=mbzrxpgjys`. Then, the returned TURN credential will be as follows:

```js
{
    "username" : "mbzrxpgjys",
    "password" : "pass-1",
    "ttl" : 86400,
    "uris" : [
        "turn:1.2.3.4:3478?transport=tcp",
        "turns:1.2.3.4:443?transport=tcp"
    ]
```

Observe that the username specified in the GET request overrides the default given in the
GatewayConfig (i.e., `user-1`).

Now suppose that the STUNner authentication mode is set to `longterm` as follows:


```yaml
apiVersion: stunner.l7mp.io/v1alpha1
kind: GatewayConfig
metadata:
  name: stunner-gatewayconfig
spec:
  authType: longterm
  password: "sharedPass"
```

In this case the same GET request will yield the following response:

```js
{
    "username" : "12334939:mbzrxpgjys",
    "password" : "adfsaflsjfldssia",
    "ttl" : 86400,
    "uris" : [
        "turn:1.2.3.4:3478?transport=tcp",
        "turns:1.2.3.4:443?transport=tcp"
    ]
```

Now, the username is a colon delimited pair of an expiry timestamp and the username specified in
the GET request and the password is a HMAC generated by using the auth secret `sharedPass` supplied
to STUNner in the GatewayConfig. If no username is given in the GET request, the username in the
response is a pure timestamp: `12334939:`.

## The `getIceAuth` API

The `getIceAuth` API can be used to obtain a full [ICE server
configuration](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection#parameters). The
use of this API is exactly the same as in the `getTurnAuth` API with one additional optional
parameter called `icetransportpolicy`, which can be set by the caller to fix the [ICE transport
policy](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection#parameters)
to either `all` (to let ICE to consider all candidates) or `relay` (to consider only relayed ICE
candidates). The response is in the format of a standard [ICE server
configuration](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection#parameters)
that can be readily passed to the `RTCPeerConnection` call.

For instance, the second request in the above example would return the following response:

``` js
{
    iceServers: [
        urls: [
            "turn:1.2.3.4:3478?transport=tcp",
            "turns:1.2.3.4:443?transport=tcp"
        ],
        username: "12334939:mbzrxpgjys",
        credential: "adfsaflsjfldssia",
    }
    iceTransportPolicy: 'relay'
}
```

Also specifying the ICE transport policy in the request as in `GET
/?service=turn&iceTransportPolicy=relay` would yield:

``` js
{
    iceServers: [
        urls: [
            "turn:1.2.3.4:3478?transport=tcp",
            "turns:1.2.3.4:443?transport=tcp"
        ],
        username: "12334939:mbzrxpgjys",
        credential: "adfsaflsjfldssia",
    }
    iceTransportPolicy: 'relay'
}
```

## Help

STUNner development is coordinated in Discord, feel free to [join](https://discord.gg/DyPgEsbwzc).

## License

Copyright 2021-2023 by its authors. Some rights reserved. See [AUTHORS](../AUTHORS).

MIT License - see [LICENSE](../LICENSE) for full text.

## Acknowledgments

Initial code adopted from [pion/stun](https://github.com/pion/stun) and
[pion/turn](https://github.com/pion/turn).

