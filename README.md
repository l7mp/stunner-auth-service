# A REST API for generating STUNner TURN authentication credentials 

*Work in progress* 

This service implements the [/REST API For Access To TURN
Services/](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00) IETF draft
specification to provide access to the TURN services provided by STUNner. While STUNner allows a
fixed username/password pair to be used for *all* clients this mode is not recommended; instead
this service can be used to generate ephemeral (i.e. time-limited) credentials. The usage of
ephemeral credentials ensures that access to STUNner can be controlled even if the credentials can
be discovered by the user, as is the case in WebRTC where TURN credentials must be specified in
JavaScript.

## Description

By providing a cloud-based relay service, TURN ensures that a connection can be established even
when one or both sides is incapable of a direct P2P connection.  However, as a relay service, it
imposes a nontrivial cost on the service provider.  Therefore, access to a TURN service is almost
always access-controlled.

TURN provides a mechanism to control access via long-term credentials that are provided as part of
the TURN protocol.  It is expected that these credentials will be kept secret; if the credentials
are discovered, the TURN server could be used by unauthorized users or applications.  However, in
web applications, ensuring this secrecy is typically impossible.

To address this problem, this service provides a REST API that can be used to retrieve TURN
credentials specifically for STUNner as the TURN server. The service watches the running STUNner
dataplane configuration (usually the configmap called `stunnerd-config` in the current namespace)
and automatically generates TURN credentials that will match the current [authentication
setting](https://github.com/l7mp/stunner/blob/main/doc/AUTH.md) for STUNner. The main use of this
service is by the WebRTC application server to generate an [ICE server
configuration](https://developer.mozilla.org/en-US/docs/Web/API/RTCIceServer) to be returned to
clients to enable them to connect via STUNner as the TURN server.

## API

The REST API exposes to API endpoints: `getTurnAuth` can be called to obtain a TURN authentication
credential stanza as in the [/REST API For Access To TURN
Services/](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00) spec, while
`getIceAuth` returns an [ICE server
configuration](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection#parameters)
ready to be supplied to the in an `RTCPeerConnection` call as configuration. The difference between
the two is mostly syntactic: we recommend the use of the latter API as it provides a format
expected by client WebRTC implementations

## The `getTurnAuth` API

The `getTurnAuth` API can be used to obtain a TURN authentication credential stanza as in the
[/REST API For Access To TURN
Services/](https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00) spec.

### Request

A request to the `getTurnAuth` API endpoint includes the following parameters, specified in the URL:
- `service`: specifies the desired service (turn)
- `username`: an optional user id to be associated with the credentials
- `key`: if an API key is used for authentication, the API key

### Response

The response is returned with content-type `"application/json"`, and consists of a JSON object with the following parameters:
- `username`: the TURN username to use; depending on the running STUNner configuration this may be
  a fix username of a colon-delimited combination of an expiration time as a UNIX timestamp and the
  username parameter from the request (if specified).
- `password`: the TURN password to use; again, depending on the running STUNner configuration this
  may be a fix password or a value dynamically computed from the a secret key shared with the TURN
  server and the returned username value, see details in the
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
`1.2.3.4` and assume the following request to the `getTurnAuth` API: `GET
/?service=turn&username=mbzrxpgjys`. Then, the returned TURN credential will be as follows

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
the GET request. If not username is given in the GET request, the username in the response is a
pure timestamp: `"12334939:"`.

## The `getIceAuth` API

The `getIceAuth` API can be used to obtain a full [ICE server
configuration](https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection#parameters). The
use of this API is exactly the same as in the `getTurnAuth` API with One additional optional
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

