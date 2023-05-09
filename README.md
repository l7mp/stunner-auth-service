<p align="center">
  <img alt="STUNner Authentication Service", src="stunner_auth.svg" width="50%" height="50%"></br>
  <a href="https://github.com/l7mp/stunner-auth-service/blob/main/LICENSE" alt="MIT">
    <img src="https://img.shields.io/github/license/l7mp/stunner-auth-service" /></a>
</p>

# A REST API for generating STUNner TURN authentication credentials 

This service implements the [*REST API For Access To TURN
Services*](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00) IETF draft
specification to assist in accessing the TURN services provided by
[STUNner](https://github.com/l7mp/stunner). By default, STUNner uses a fixed username/password pair
that can be leveraged by *all* clients to make TURN relay connections. This mode, however, is not
recommended for production use. Instead, the **STUNner authentication service** provided by this
REST API can be used to generate per-client ephemeral (i.e. time-limited) credentials with a
configurable expiration deadline. The usage of ephemeral credentials ensures that access to STUNner
can be controlled even if the credentials can be discovered by the user, as is the case in WebRTC
where TURN credentials must be specified in JavaScript.

## Description

By providing a cloud-based relay service, STUNner ensures that a WebRTC media connection can be
established via TURN even when one or both sides is incapable of a direct P2P connection, as it is
the case when the media servers run inside a Kubernetes cluster.  However, as a gateway service,
STUNner opens external access to the Kubernetes cluster.  Therefore, it is recommended to tightly
control user access to the TURN services provided by STUNner.

STUNner implements a mechanism to control access via long-term credentials that are provided as
part of the TURN protocol.  It is expected that these credentials will be kept secret; if the
credentials are discovered, the TURN server could be used by unauthorized users or applications.
However, in web applications, ensuring this secrecy is typically impossible.

To address this problem, this service provides a REST API that can be used to retrieve TURN
credentials to access STUNner. The service watches the running STUNner dataplane configuration(s)
from Kubernetes and automatically generates TURN credentials that will match the current
[authentication settings](https://github.com/l7mp/stunner/blob/main/doc/AUTH.md) for STUNner. The
REST API also allows to easily filter the returned TURN URIs to a selected set of STUNner Gateways:
it is possible to return all public URIs per Kubernetes namespace, select a particular STUNner
Gateways within a namespace, or specify exactly which STUNner Gateway listener (say, TCP or UDP)
the returned credential should apply to. This allows to direct users to access the Kubernetes
cluster via a specific STUNner listener.

The main use of this service is by a WebRTC application server to generate an [ICE server
configuration](https://developer.mozilla.org/en-US/docs/Web/API/RTCIceServer) to be returned to
clients during session setup.

## Usage

Most users will have the Stunner authentication REST API server automatically deployed into their
cluster by the Stunner [Helm charts](https://github.com/l7mp/stunner-helm). By default the
authentication server is deployed into `stunner-system` namespace, it is exposed by the Service
called `stunner-auth`, and it listens on port 8088 over plain HTTP, so you can reach it via the URL
`http://stunner-auth.stunner-system:8088`. 

Alternatively, you can deploy and test the REST API using the packaged static manifests as follows.

``` console
kubectl create namespace stunner-system
kubectl apply -f deploy/kubernetes-stunner-auth-service.yaml
kubectl apply -f deploy/sample-stunnerd-config.yaml
```

The last command loads a fake STUNner running config that can be used to test the authentication
service without actually deploying STUNner. The sample configuration defines 4 static listeners
with a IP addresses and ports as follows:

``` console
cd <stunner>
cmd/stunnerctl/stunnerctl running-config default/stunnerd-config
STUN/TURN authentication type:	longterm
STUN/TURN secret:		my-secret
Listener 1
	Name:	testnamespace/testgateway/udp
	Listener:	testnamespace/testgateway/udp
	Protocol:	udp
	Public address:	1.2.3.4
	Public port:	3478
Listener 2
	Name:	dummynamespace/testgateway/tcp
	Listener:	dummynamespace/testgateway/tcp
	Protocol:	tcp
	Public address:	1.2.3.4
	Public port:	3478
Listener 3
	Name:	testnamespace/dummygateway/tls
	Listener:	testnamespace/dummygateway/tls
	Protocol:	tls
Listener 4
	Name:	testnamespace/testgateway/dtls
	Listener:	testnamespace/testgateway/dtls
	Protocol:	dtls
```

### Generating a TURN authentication token

The below will query the REST API for a TURN authentication token, setting the username to
`my-user` and the expiration time of the returned TURN credentials to 1 hour from the present
(`ttl` is set to 3600 sec).

``` console
curl -s http://stunner-auth.stunner-system:8088?service=turn\&username=my-user\&ttl=3600| jq .
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

Note that by default the TURN authentication service is reachable only from within the cluster (the
Service `stunner-auth.stunner-system` that exposes the authentication server is of type
`ClusterIP`), so you have to issue the `curl` command from a pod running in the same cluster.

:warning: Never expose the STUNner authentication service externally. Since the REST API is not
authenticated, this would provide unchecked access to anyone to your STUNner gateways. If you want
to supply TURN credentials to your WebRTC clients, generate the authentication tokens from the
application server first and then return the credentials obtained from the REST API during call
setup!

The parameter `service=turn` is mandatory, the rest of the parameters are optional; see the [*REST
API For Access To TURN
Services*](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00) IETF draft
specification to understand the fields of the returned JSON or the [OpenAPI
specs](api/stunner.yaml) packaged with the repo. Note also that `jq` is used above only to
pretty-print the response JSON, feel free to remove it.

Due to a limitation of the REST API spec, the authentication service can generate the TURN access
token for only a single Gateway. If you have multiple Gateways configured, a random Gateway will be
chosen (use the `/ice` API endpoint below to sidestep this limitation).  Observe that the response
contains 4 TURN URIs, one corresponding to each of the 4 listeners defined in the sample STUNner
config. 

### Generating a complete ICE configuration

In addition to TURN authentication tokens, the REST API server can also generate full [ICE
configurations](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection#parameters). These
should be sent from the application to the clients, so that clients can use the correct ICE config
to connect via STUNner as the TURN server. 

Use the `/ice` API endpoint to generate an ICE config:

``` console
curl -s http://stunner-auth.stunner-system:8088/ice?service=turn\&username=my-user\&ttl=3600| jq .
{
  "iceServers": [
    {
      "username": "1680037776:my-user"
      "credential": "Ad5JZbsKve06gZj+6kH9EeJYTJA=",
      "urls": [
        "turn:5.6.7.8:3478?transport=udp",
        "turn:5.6.7.8:3478?transport=tcp",
        "turns:127.0.0.1:3479?transport=tcp",
        "turns:127.0.0.1:3479?transport=udp"
      ],
    }
  ],
  "iceTransportPolicy": "all"
}
```

By default the returned ICE configuration will contain a separate ICE server configuration for each
Gateway in the cluster. In order to select only the Gateways within a single namespace, provide the
name of the required namespace in the HTTP request parameters. You can select a particular Gateway
using the `gateway=<gateway-name>` parameter and a particular listener using
`listener=<listenername>`. 

For instance, the below will generate a TURN URI only for the first listener in the sample STUNner
config:

``` console
curl "http://stunner-auth.stunner-system:8088/ice?service=turn&namespace=testnamespace&gateway=testgateway&listener=udp&iceTransportPolicy=relay"
{
  "iceServers": [
    {
      "username": "1681252038:"
      "credential": "+JJnoo+liMnom07gw9moVgUzsEM=",
      "urls": [
        "turn:1.2.3.4:3478?transport=udp"
      ],
    }
  ],
  "iceTransportPolicy": "relay"
}
```

The request parameters defined for the TURN REST API (namely, `username` and `ttl`) can be used for
this API too. In addition, the parameter `iceTransportPolicy=relay` will set the
`iceTransportPolicy` to `relay` in the returned ICE configuration (by default it is set to `all`):
this is useful to force clients to skip generating Host and Server-reflexive ICE candidates (which
will not work with STUNner anyway) and use TURN for connecting unconditionally.

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

<!-- ### Example -->

<!-- Consider the below STUNner configuration: -->

<!-- ```yaml -->
<!-- apiVersion: stunner.l7mp.io/v1alpha1 -->
<!-- kind: GatewayConfig -->
<!-- metadata: -->
<!--   name: stunner-gatewayconfig -->
<!-- spec: -->
<!--   authType: plaintext -->
<!--   userName: "user-1" -->
<!--   password: "pass-1" -->
<!-- --- -->
<!-- apiVersion: gateway.networking.k8s.io/v1alpha2 -->
<!-- kind: Gateway -->
<!-- metadata: -->
<!--   name: stunner-gateway -->
<!-- spec: -->
<!--   gatewayClassName: stunner-gatewayclass -->
<!--   listeners: -->
<!--     - name: tcp-listener -->
<!--       port: 3478 -->
<!--       protocol: TCP -->
<!--     - name: tls-listener -->
<!--       port: 443 -->
<!--       protocol: TLS -->
<!--       tls: -->
<!--         mode: Terminate -->
<!--         certificateRefs: -->
<!--           - name: tls-secret -->
<!-- ``` -->

<!-- Furthermore, suppose that public IP for the LoadBalancer service that exposes this gateway is -->
<!-- `1.2.3.4` and assume the following request to the `getTurnAuth` API: -->
<!-- `GET/?service=turn&username=mbzrxpgjys`. Then, the returned TURN credential will be as follows: -->

<!-- ```js -->
<!-- { -->
<!--     "username" : "mbzrxpgjys", -->
<!--     "password" : "pass-1", -->
<!--     "ttl" : 86400, -->
<!--     "uris" : [ -->
<!--         "turn:1.2.3.4:3478?transport=tcp", -->
<!--         "turns:1.2.3.4:443?transport=tcp" -->
<!--     ] -->
<!-- ``` -->

<!-- Observe that the username specified in the GET request overrides the default given in the -->
<!-- GatewayConfig (i.e., `user-1`). -->

<!-- Now suppose that the STUNner authentication mode is set to `longterm` as follows: -->


<!-- ```yaml -->
<!-- apiVersion: stunner.l7mp.io/v1alpha1 -->
<!-- kind: GatewayConfig -->
<!-- metadata: -->
<!--   name: stunner-gatewayconfig -->
<!-- spec: -->
<!--   authType: longterm -->
<!--   password: "sharedPass" -->
<!-- ``` -->

<!-- In this case the same GET request will yield the following response: -->

<!-- ```js -->
<!-- { -->
<!--     "username" : "12334939:mbzrxpgjys", -->
<!--     "password" : "adfsaflsjfldssia", -->
<!--     "ttl" : 86400, -->
<!--     "uris" : [ -->
<!--         "turn:1.2.3.4:3478?transport=tcp", -->
<!--         "turns:1.2.3.4:443?transport=tcp" -->
<!--     ] -->
<!-- ``` -->

<!-- Now, the username is a colon delimited pair of an expiry timestamp and the username specified in -->
<!-- the GET request and the password is a HMAC generated by using the auth secret `sharedPass` supplied -->
<!-- to STUNner in the GatewayConfig. If no username is given in the GET request, the username in the -->
<!-- response is a pure timestamp: `12334939:`. -->

## The `getIceAuth` API

The `getIceAuth` API can be used to obtain a full [ICE server
configuration](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection#parameters). The
use of this API is similar to that of the `getTurnAuth` API. An additional optional parameter
called `icetransportpolicy` is also available, which can be set to fix the [ICE transport
policy](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection#parameters)
to either `all` (to let ICE to consider all candidates) or `relay` (to consider only relayed ICE
candidates). The response is in the format of a standard [ICE server
configuration](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection#parameters)
that can be readily passed to the `RTCPeerConnection` call.

<!-- For instance, the second request in the above example would return the following response: -->

<!-- ``` js -->
<!-- { -->
<!--     iceServers: [ -->
<!--         urls: [ -->
<!--             "turn:1.2.3.4:3478?transport=tcp", -->
<!--             "turns:1.2.3.4:443?transport=tcp" -->
<!--         ], -->
<!--         username: "12334939:mbzrxpgjys", -->
<!--         credential: "adfsaflsjfldssia", -->
<!--     } -->
<!--     iceTransportPolicy: 'relay' -->
<!-- } -->
<!-- ``` -->

<!-- Also specifying the ICE transport policy in the request as in `GET -->
<!-- /?service=turn&iceTransportPolicy=relay` would yield: -->

<!-- ``` js -->
<!-- { -->
<!--     iceServers: [ -->
<!--         urls: [ -->
<!--             "turn:1.2.3.4:3478?transport=tcp", -->
<!--             "turns:1.2.3.4:443?transport=tcp" -->
<!--         ], -->
<!--         username: "12334939:mbzrxpgjys", -->
<!--         credential: "adfsaflsjfldssia", -->
<!--     } -->
<!--     iceTransportPolicy: 'relay' -->
<!-- } -->
<!-- ``` -->

## Help

STUNner development is coordinated in Discord, feel free to [join](https://discord.gg/DyPgEsbwzc).

## License

Copyright 2021-2023 by its authors. Some rights reserved. See [AUTHORS](AUTHORS).

MIT License - see [LICENSE](LICENSE) for full text.

## Acknowledgments

Initial code adopted from [pion/stun](https://github.com/pion/stun) and
[pion/turn](https://github.com/pion/turn).

