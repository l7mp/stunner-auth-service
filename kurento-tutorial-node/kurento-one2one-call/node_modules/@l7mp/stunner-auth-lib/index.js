// @l7mp/stunner-auth-lib: A library to create ICE configuration and TURN credentials for the
// STUNner Kubernetes ingress gateway for WebRTC
//
// Copyright 2022 by its authors.
// Some rights reserved.
//
// Original code taken from: https://github.com/rojo2/turn-credentials

'use strict';

const crypto       = require('crypto');
const fs           = require('node:fs');
const {setTimeout} = require('node:timers/promises');

/**
 * ICE configuration Options
 * @typedef {Object} IceConfigurationOptions
 * @property {string} address
 * @property {number} port
 * @property {string} protocol
 * @property {string} auth_type
 * @property {string} realm
 * @property {string} username
 * @property {string} password
 * @property {string} secret
 * @property {number} [duration=24*3600]
 * @property {string} [algorithm=sha1]
 * @property {string} [encoding=base64]
 */

/**
 * ICE Configuration
 * @typedef {Object} IceConfiguration
 * @property {array} IceServers
 * @property {string} iceTransportPolicy
 */

/**
 * TURN Credential Options
 * @typedef {Object} TurnCredentialOptions
 * @property {string} auth_type
 * @property {string} realm
 * @property {string} username
 * @property {string} password
 * @property {string} secret
 * @property {number} [duration=24*3600]
 * @property {string} [algorithm=sha1]
 * @property {string} [encoding=base64]
 */

/**
 * TURN Credentials
 * @typedef {Object} TurnCredentials
 * @property {string} username
 * @property {string} credential
 * @property {string} realm
 */

/**
 * STUNner config file name
 * @const {string}
 */
const STUNNER_CONFIG_FILENAME = '/etc/stunnerd/stunnerd.conf';

/**
 * STUNner public address
 * @const {string}
 */
const STUNNER_PUBLIC_ADDR = "";  // no default!

/**
 * STUNner public port
 * @const {string}
 */
const STUNNER_PUBLIC_PORT = 3478;

/**
 * STUNner default protocol
 * @const {string}
 */
const STUNNER_TRANSPORT_PROTOCOL = "UDP";

/**
 * STUNner UDP transport enabled (only used in fallback mode)
 * @const {string}
 */
const STUNNER_TRANSPORT_UDP_ENABLE = true;

/**
 * STUNner TCP transport enabled (only used in fallback mode)
 * @const {string}
 */
const STUNNER_TRANSPORT_TCP_ENABLE = false;

/**
 * STUNner authentication mode
 * @const {string}
 */
const STUNNER_AUTH_TYPE = 'plaintext';

/**
 * STUN/TURN realm.
 * @const {string}
 */
const STUNNER_REALM = 'stunner.l7mp.io';

/**
 * STUNner username for plaintext authentication.
 * @const {string}
 */
const STUNNER_USERNAME = 'user';

/**
 * STUNner password for plaintext authentication.
 * @const {string}
 */
const STUNNER_PASSWORD = 'pass';

/**
 * Shared secret for long-term credential authentication.
 * @const {string}
 */
const STUNNER_SHARED_SECRET = 'my-secret';

/**
 * Credential lifetime for long-term credential authentication.
 * @const {string}
 */
const DURATION = process.env.STUNNER_DURATION || (24 * 60 * 60);

/**
 * ICE transport policy: either 'all' (generate all ICE candidates) or 'relay' (consider TURN relay candidates only).
 * @const {string}
 */
const STUNNER_ICE_TRANSPORT_POLICY = 'relay';

/**
 * Algorithm
 * @const {string}
 */
const ALGORITHM = 'sha1';

/**
 * Encoding used
 * @const {string}
 */
const ENCODING = 'base64';

/**
 * Creates ICE configuration for STUNner. If config file is available then it generates the config
 * from that using the options argument as override, otherwise it falls back to using the
 * environment variables overridden by the options argument.
 * @param {ICEConfigurationOptions} [options]
 * @returns {ICEConfiguration}
 */
function getIceConfig(options){
    if(!options)options={};
    let filename = options.config_file || process.env.STUNNER_CONFIG_FILENAME || STUNNER_CONFIG_FILENAME;

    try {
        const data = fs.readFileSync(filename);
        const conf = JSON.parse(data);

        const iceconf = getIceConfigFromConfig(conf, options);
        // console.log(`getIceConfig: ICE config generated from config file ${filename}:`,
        //             JSON.stringify(iceconf));

        return iceconf;
    } catch(err){
        console.log(`Cloud not read config file, falling back to env-mode: ${err.toString()}`);

        const iceconf = getIceConfigFallback(options);
        // console.log(`getIceConfig: ICE config generated in fallback mode:`,
        //             JSON.stringify(iceconf));

        return iceconf;
    }
}

/**
 * Creates TURN credentials for STUNner. If config file is available then it generates the
 * credentials from that using the options argument as override, otherwise it falls back to using
 * environment variables overridden by the options argument.
 * @param {TurnCredentialsOptions} [options]
 * @returns {TurnCredentials}
 */
// should get the same output as https://pkg.go.dev/github.com/pion/turn/v2#GenerateLongTermCredentials
function getStunnerCredentials(options){
    if(!options)options={};
    let filename = options.config_file || process.env.STUNNER_CONFIG_FILENAME || STUNNER_CONFIG_FILENAME;

    try {
        const data = fs.readFileSync(filename);
        const conf = JSON.parse(data);

        const auth = getStunnerCredentialsFromConfig(conf, options);
        // console.log(`getStunnerCredentials: TURN credentials generated from config file ${filename}:`,
        //            JSON.stringify(auth));

        return auth;
    } catch(err){
        console.log(`Cloud not read config file, falling back to env-mode: ${err.toString()}`);

        const auth = getStunnerCredentialsFallback(options);
        // console.log(`getStunnerCredentials: TURN credentials generated in fallback mode:`,
        //            JSON.stringify(auth));

        return auth;
    }
}

function getIceConfigFromConfig(conf, options){
    if(!(conf !== undefined && conf.version !== undefined &&
         conf.version === "v1alpha1" && conf.auth !== undefined)){
        throw new Error("invalid config file");
    }

    if(!options)options={};
    let ice_transport_policy = options.ice_transport_policy ||
        process.env.STUNNER_ICE_TRANSPORT_POLICY || STUNNER_ICE_TRANSPORT_POLICY;
        
    const cred = getStunnerCredentialsFromConfig(conf, options);
    var iceConfig = {
        iceServers: [],
        iceTransportPolicy: ice_transport_policy,
    };
        
    for(const l of conf.listeners) {
        let address = options.address  || l.public_address || process.env.STUNNER_PUBLIC_ADDR  ||
            STUNNER_PUBLIC_ADDR;
        let port = options.port || l.public_port || l.port || process.env.STUNNER_PUBLIC_PORT ||
            STUNNER_PUBLIC_PORT;
        let proto = options.protocol || l.protocol || process.env.STUNNER_PROTOCOL ||
            STUNNER_TRANSPORT_PROTOCOL;
            
        if(!address){
            throw new Error("invalid STUNner public address in config file "+
                            this.config_file + ": ICE configuration will be invalid");
        }
            
        iceConfig.iceServers.push(
            {
                url: `turn:${address}:${port}?transport=${proto}`,
                username: cred.username,
                credential: cred.credential,
            }
        );
    }
        
    return iceConfig;
}
    
function getStunnerCredentialsFromConfig(conf, options){
    if(!(conf !== undefined && conf.version !== undefined &&
         conf.version === "v1alpha1" && conf.auth !== undefined)){
        throw new Error("invalid config file");
    }

    if(!options)options={};
    let auth_type = options.auth_type || conf.auth.type                 || STUNNER_AUTH_TYPE;
    let realm     = options.realm     || conf.auth.realm                || STUNNER_REALM;
    let username  = options.username  || conf.auth.credentials.username || STUNNER_USERNAME;
    let password  = options.password  || conf.auth.credentials.password || STUNNER_PASSWORD;
    let secret    = options.secret    || conf.auth.credentials.secret   || STUNNER_SHARED_SECRET;
    let duration  = options.duration  || process.env.STUNNER_DURATION     || DURATION;
    let algorithm = options.algorithm || ALGORITHM;
    let encoding  = options.encoding  || ENCODING;
    
    switch (auth_type.toLowerCase()){
    case 'plaintext':
        return {
            username: username,
            credential: password,
            realm: realm,
        };
        
    case 'longterm':
        const timeStamp = Math.floor(Date.now() / 1000) + parseInt(duration);
        return getLongtermForTimeStamp(timeStamp, secret, realm, algorithm, encoding);
        
    default:
        throw new Error(`invalid authentication type: ${auth_type}`);
        return undefined;
    }
}

/*********************************
 *
 * Fallback mode: as long as no STUNner config file is available, use the environment 
 * variables overridden by the options argument to generate the ICE server configs
 *
 *********************************/
function getIceConfigFallback(options){
    if(!options)options={};
    let address   = options.address   || process.env.STUNNER_PUBLIC_ADDR   || STUNNER_PUBLIC_ADDR;
    let port      = options.port      || process.env.STUNNER_PUBLIC_PORT   || STUNNER_PUBLIC_PORT;
    let auth_type = options.auth_type || process.env.STUNNER_AUTH_TYPE     || STUNNER_AUTH_TYPE;
    let realm     = options.realm     || process.env.STUNNER_REALM         || STUNNER_REALM;
    let username  = options.username  || process.env.STUNNER_USERNAME      || STUNNER_USERNAME;
    let password  = options.password  || process.env.STUNNER_PASSWORD      || STUNNER_PASSWORD;
    let secret    = options.secret    || process.env.STUNNER_SHARED_SECRET || STUNNER_SHARED_SECRET;
    let duration  = options.duration  || process.env.STUNNER_DURATION      || DURATION;
    let ice_transport_policy = options.ice_transport_policy ||
            process.env.STUNNER_ICE_TRANSPORT_POLICY || STUNNER_ICE_TRANSPORT_POLICY;
    let algorithm = options.algorithm || ALGORITHM;
    let encoding  = options.encoding  || ENCODING;

    // special-case boolean conf
    let transport_udp_enable = STUNNER_TRANSPORT_UDP_ENABLE;
    if ("STUNNER_TRANSPORT_UDP_ENABLE" in process.env){
        transport_udp_enable = process.env.STUNNER_TRANSPORT_UDP_ENABLE;
        if(transport_udp_enable === "0") transport_udp_enable = false;
    }
    if (typeof options.transport_udp_enable !== 'undefined') {
        transport_udp_enable = options.transport_udp_enable;
    }

    let transport_tcp_enable = STUNNER_TRANSPORT_TCP_ENABLE;
    if ("STUNNER_TRANSPORT_TCP_ENABLE" in process.env){
        transport_tcp_enable = process.env.STUNNER_TRANSPORT_TCP_ENABLE;
        if(transport_tcp_enable === "0") transport_tcp_enable = false;
    }
    if (typeof options.transport_tcp_enable !== 'undefined') {
        transport_tcp_enable = options.transport_tcp_enable;
    }
    
    if(!address){
        console.error("getIceConfig: invalid STUNner public address, please set " +
                      "STUNNER_PUBLIC_ADDR or specify the address as an argument");
        return undefined;
    }
    
    const cred = getStunnerCredentials({
        auth_type: auth_type,
        realm: realm, 
        username: username,
        password: password,
        secret: secret,
        duration: duration,
        ice_transport_policy: ice_transport_policy,
        algorithm: algorithm,
        encoding: encoding,
    });
    
    var config = {
        iceServers: [],
        iceTransportPolicy: ice_transport_policy,
    };

    if(transport_udp_enable){
        config.iceServers.push(
            {
                url: `turn:${address}:${port}?transport=udp`,
                username: cred.username,
                credential: cred.credential,
            }
        );
    }

    if(transport_tcp_enable){
        config.iceServers.push(
            {
                url: `turn:${address}:${port}?transport=tcp`,
                username: cred.username,
                credential: cred.credential,
            }
        );
    }
    return config;
}

/**
 * Creates TURN credentials for STUNner
 * @param {TurnCredentialsOptions} [options]
 * @returns {TurnCredentials}
 */
// should get the same output as https://pkg.go.dev/github.com/pion/turn/v2#GenerateLongTermCredentials
function getStunnerCredentialsFallback(options){
    if(!options)options={};
    let auth_type = options.auth_type || process.env.STUNNER_AUTH_TYPE     || STUNNER_AUTH_TYPE;
    let realm     = options.realm     || process.env.STUNNER_REALM         || STUNNER_REALM;
    let username  = options.username  || process.env.STUNNER_USERNAME      || STUNNER_USERNAME;
    let password  = options.password  || process.env.STUNNER_PASSWORD      || STUNNER_PASSWORD;
    let secret    = options.secret    || process.env.STUNNER_SHARED_SECRET || STUNNER_SHARED_SECRET;
    let duration  = options.duration  || process.env.STUNNER_DURATION      || DURATION;
    let algorithm = options.algorithm || ALGORITHM;
    let encoding  = options.encoding  || ENCODING;

    switch (auth_type.toLowerCase()){
    case 'plaintext':
        return {
            username: username,
            credential: password,
            realm: realm,
        };
    case 'longterm':
        const timeStamp = Math.floor(Date.now() / 1000) + parseInt(duration);
        return getLongtermForTimeStamp(timeStamp, secret, realm, algorithm, encoding);
    default:
        console.error('getStunnerCredentialsFallback: invalid authentication type:', auth_type);
        return undefined;
    }
}

// separated out for testing
function getLongtermForTimeStamp(timeStamp, secret, realm, algorithm, encoding){
    // console.log(timeStamp, secret, realm, algorithm, encoding);
    const hmac = crypto.createHmac(algorithm, secret);
    const password = hmac.update(Buffer.from(`${timeStamp}`, 'utf-8'));
    // console.log(password.digest('hex'));
    const credential = password.digest(encoding);
    return {
        username: `${timeStamp}`,
        credential: credential,
        realm: realm,
    };
}

module.exports.getIceConfig = getIceConfig;
module.exports.getStunnerCredentials = getStunnerCredentials;
module.exports.getLongtermForTimeStamp = getLongtermForTimeStamp;
