<p align="center">
  <img alt="STUNner Authentication Service", src="stunner_auth.svg" width="50%" height="50%"></br>
  <a href="https://discord.gg/DyPgEsbwzc" alt="Discord">
    <img alt="Discord" src="https://img.shields.io/discord/945255818494902282" /></a>
  <a href="https://hub.docker.com/repository/docker/l7mp/stunner-auth-server" alt="Docker pulls">
    <img src="https://img.shields.io/docker/pulls/l7mp/stunner-auth-server" /></a>
  <a href="https://github.com/l7mp/stunner-auth-service/blob/main/LICENSE" alt="MIT">
    <img src="https://img.shields.io/github/license/l7mp/stunner-auth-service" /></a>
</p>

# A REST API for generating TURN authentication credentials for STUNner

This service implements the [*REST API For Access To TURN
Services*](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00) IETF draft
specification to assist in accessing the TURN services provided by
[STUNner](https://github.com/l7mp/stunner). By default, STUNner uses a fixed username/password pair
that can be leveraged by *all* clients to make TURN relay connections. This mode, however, is not
recommended for production use. Instead, the **STUNner authentication service** provided by this
REST API can be used to generate per-client ephemeral (i.e. time-limited) credentials with a
configurable expiration deadline. The use of ephemeral credentials ensures that access to STUNner
can be controlled even if the credentials can be discovered by the user, as is the case in WebRTC
where TURN credentials are usually negotiated in JavaScript.

## Description

By providing a cloud-based relay service, STUNner ensures that WebRTC peers can establish a media connection via TURN even when one or both sides is incapable of a direct P2P connection. This is the case, for instance, when media servers are deployed in a Kubernetes cluster.  As a gateway service, STUNner opens external access to the Kubernetes cluster.  STUNner implements a mechanism to control user access via long-term credentials that are provided as part of the TURN protocol.  It is expected that these credentials will be kept secret; if the credentials are discovered, the TURN server could be used by unauthorized users or applications.  However, in web applications, ensuring this secrecy is typically impossible.

To address this problem, the STUNner authentication service provides a REST API that can be used to retrieve TURN credentials to access STUNner. The service watches the running STUNner dataplane configuration(s) from Kubernetes and automatically generates TURN credentials that will match the current [authentication settings](https://github.com/l7mp/stunner/blob/main/doc/AUTH.md) for STUNner. The REST API also allows to easily filter the returned TURN URIs to a selected set of STUNner Gateways: it is possible to return all public TURN URIs per Kubernetes namespace, select a particular STUNner Gateways within a namespace, or specify exactly which STUNner Gateway listener (say, TCP or UDP) the returned credential should apply to. This allows to direct users to access the Kubernetes cluster via a specific STUNner listener.

The main use of this service is by a WebRTC application server to generate an [ICE server
configuration](https://developer.mozilla.org/en-US/docs/Web/API/RTCIceServer) to be returned to
clients during session setup.

## Getting started

Most users will have the Stunner authentication REST API server automatically deployed into their
cluster by the Stunner [Helm charts](https://github.com/l7mp/stunner-helm). By default the
authentication server is deployed into the `stunner-system` namespace, exposed in the cluster by the Service
called `stunner-auth`, and listens on port 8088 over plain HTTP. You can reach the auth service via the URL
`http://stunner-auth.stunner-system:8088`. 

Alternatively, you can deploy and test the REST API using the packaged static manifests as follows.

``` console
kubectl create namespace stunner-system
kubectl apply -f deploy/kubernetes-stunner-auth-service.yaml
```

The REST server can also be fired up locally for quick testing, provided that a valid
kubeconfig is available for a remote cluster. The server can discover the remote CDS server to load
STUNner configs.

``` console
go build -o authd main.go
./authd -v
```

If a CDS service is available on a well-known address, then that address can also be explicitly
specified on the command line. The below will use the CDS server exposed at `127.0.0.1:13478` and
set the log level to maximum.

``` console
./authd --cds-server-address="127.0.0.1:13478" -l all:TRACE
```

## Usage

For the purposes of this test, we set up the [Simple
tunnel](https://github.com/l7mp/stunner/blob/main/docs/examples/simple-tunnel/README.md) STUNner
tutorial and loaded the necessary Kubernetes manifests for demonstration purposes. Make sure [`stunnerctl`](https://github.com/l7mp/stunner/blob/main/cmd/stunnerctl/README.md) has been properly installed. The sample
configuration defines 2 Gateways with the below config:

``` console
bin/stunnerctl -n stunner config 
Gateway: stunner/tcp-gateway (loglevel: "all:INFO")
Authentication type: static, username/password: user-1/pass-1
Listeners:
  - Name: stunner/tcp-gateway/tcp-listener
    Protocol: TURN-TCP
    Public address:port: 10.102.33.126:3478
    Routes: [stunner/iperf-server]
    Endpoints: [10.106.145.240, 10.244.0.11]
Gateway: stunner/udp-gateway (loglevel: "all:INFO")
Authentication type: static, username/password: user-1/pass-1
Listeners:
  - Name: stunner/udp-gateway/udp-listener
    Protocol: TURN-UDP
    Public address:port: 10.103.187.184:3478
    Routes: [stunner/iperf-server]
    Endpoints: [10.106.145.240, 10.244.0.11]
```

In addition, we fired up a local auth-service REST server that connects to the test cluster running
the tutorial, which is available at `localhost:8088`:

``` console
./authd -v
```

Note that in reality the authentication service should run in your Kubernetes cluster and it should
be available only to clients *inside* the same cluster. This helps prevent security problems arising from unauthenticated
external clients obtaining valid TURN credentials for a running cluster.

**Warning:** Never expose the STUNner authentication service externally. Since the REST API is not
authenticated, this would provide unchecked access to anyone to your STUNner gateways. If you want
to supply TURN credentials to your WebRTC clients, generate the authentication tokens from the
application server (that runs inside the cluster too) first and only then return the credentials
obtained from the REST API during call setup!

### Generating a TURN authentication token

The below will query the REST API for a TURN authentication token, setting the username to
`my-user` and the expiration time of the returned TURN credentials to 1 hour from the present
(`ttl` is set to 3600 sec). 

``` console
curl -s http://localhost:8088?service=turn\&username=my-user\&ttl=3600| jq .
{
  "password": "pass-1",
  "ttl": 3600,
  "uris": [
    "turn:10.102.33.126:3478?transport=tcp"
  ],
  "username": "user-1"
}
```

The parameter `service=turn` is mandatory, the rest of the parameters are optional; see the [*REST
API For Access To TURN
Services*](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00) IETF draft
specification to understand the fields of the returned JSON or the [OpenAPI
specs](api/stunner.yaml) packaged with the repo. Make sure to customers the TTL: when the credential express STUNner will deny any access, even for the the clientsv do still have active connections. This may cause live sessions to be disconnected. Note also that `jq` is used above only to
pretty-print the response JSON, feel free to remove it.

Due to a limitation of the REST API spec, the authentication service can generate the TURN access
token for only a single Gateway. If you have multiple Gateways configured, a random Gateway will be
chosen (use the `/ice` API endpoint below to sidestep this limitation).  Observe that the response
contains a single TURN URIs corresponding to the TCP gateway.

### Generating a complete ICE configuration

In addition to TURN authentication tokens, the REST API server can also generate full [ICE
configurations](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection#parameters). These
should be sent from the application to the clients, so that clients can use the correct ICE config
to connect via STUNner as the TURN server. 

Use the `/ice` API endpoint to generate an ICE config:

``` console
curl -s http://localhost:8088/ice?service=turn\&username=my-user\&ttl=3600| jq .
{
  "iceServers": [
    {
      "credential": "pass-1",
      "urls": [
        "turn:10.102.33.126:3478?transport=tcp"
      ],
      "username": "user-1"
    },
    {
      "credential": "pass-1",
      "urls": [
        "turn:10.103.187.184:3478?transport=udp"
      ],
      "username": "user-1"
    }
  ],
  "iceTransportPolicy": "all"
}
```

By default the returned ICE configuration will contain a separate ICE server configuration for each
Gateway in the cluster. In order to select only the Gateways within a single namespace, provide the
name of the required namespace in the HTTP request parameters. You can select a particular Gateway
using the `gateway=<gateway-name>` parameter and a particular listener using
`listener=<listenername>`.  For instance, the below will generate a TURN URI only for the first
listener in the sample STUNner config:

``` console
curl -s "http://localhost:8088/ice?service=turn&namespace=stunner&gateway=udp-gateway&listener=udp-listener&iceTransportPolicy=relay" | jq .
{
  "iceServers": [
    {
      "credential": "pass-1",
      "urls": [
        "turn:10.103.187.184:3478?transport=udp"
      ],
      "username": "user-1"
    }
  ],
  "iceTransportPolicy": "relay"
}
```

The request parameters defined for the TURN REST API (namely, `username` and `ttl`) can be used for
this API too. In addition, the parameter `iceTransportPolicy=relay` will force clients to skip
generating host and server-reflexive ICE candidates and
use TURN for connecting unconditionally. This will make client connections much faster.

### Ensuring valid Gateway public IP addresses

In certain scenarios, STUNner is unable to determine the public IP for a Gateway
(e.g. private Kubernetes clusters without LoadBalancer and node ExternalIPs). In
these cases the public IP can be manually set using the following methods, listed in
order of priority (from highest to lowest):

- Setting the [`public-addr` URL parameter](#request) when requesting configurations.
- Setting the `STUNNER_PUBLIC_ADDR` environment variable (see the
    "stunner-auth-server" container in the [Kubernetes manifest](deploy/kubernetes-stunner-auth-service.yaml)).

If multiple methods are used, the one with the highest priority will override the rest
(e.g., setting the `public-addr` parameter always takes precedence).

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
- `service`: specifies the desired service (turn).
- `username`: an optional user id to be associated with the credentials.
- `key`: if an API key is used for authentication, the API key.
- `namespace`: consider only the STUNner Gateways in the given namespace when generating TURN URIs.
- `gateway`: consider only the specified STUNner Gateway; if `gateway` is set then `namespace` must
  be set as well.
- `listener`: consider only the specified listener on the given STUNner Gateway; if `listener` is
  set then `namespace` and `gateway` must be set too.
- `ttl`: the requested lifetime of the credential. Default is one day, make sure to customize.
- `public-addr`: override the public IP address with the provided value.

### Response

The response is returned with content-type `"application/json"`, and consists of a JSON object with the following parameters:
- `username`: the TURN username to use; depending on the running STUNner configuration this may be
  a fix username (for the `static` auth type) or a colon-delimited combination of an expiration
  time as a UNIX timestamp and the username parameter from the request (for the `ephemeral` auth
  type).
- `password`: the TURN password to use; again, depending on the running STUNner configuration this
  may be a fix password or a value dynamically computed from the a secret key shared with STUNner
  and the returned username value (for the `ephemeral` auth type), see details in the
  [spec](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00).
- `ttl`: the duration for which the username and password are valid, in seconds, default is one day
  (86400 seconds). Note that `static` passwords are valid forever.
- `uris`: an array of TURN URIs, indicating the addresses and/or protocols that can be used to
  reach STUNner.  Each Gateway will be wrapped by STUNner with a Kubernetes LoadBalancer service
  and the public IP address of that LoadBalancer service will be used as a TURN server address in
  the returned URI, the public port as the TURN port, and the Gateway protocol as the TURN
  protocol.

## The `getIceAuth` API

The `getIceAuth` API can be used to obtain a full [ICE server
configuration](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection#parameters). The
use of this API is similar to that of the `getTurnAuth` API. An additional optional parameter
called `icetransportpolicy` is also available, which can be set to fix the [ICE transport
policy](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection#parameters)
to either `all` (let ICE to consider all candidates) or `relay` (consider only relayed ICE
candidates). The response is in the format of a standard [ICE server
configuration](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection#parameters)
that can be readily passed to the `RTCPeerConnection` call.

## Help

STUNner development is coordinated in Discord, feel free to [join](https://discord.gg/DyPgEsbwzc).

## License

Copyright 2021-2024 by its authors. Some rights reserved. See [AUTHORS](AUTHORS).

MIT License - see [LICENSE](LICENSE) for full text.

