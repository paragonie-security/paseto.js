const sodium = require('libsodium-wrappers-sumo');

const utils       = require('../utils')
const decapsulate = require('../decapsulate');

const PasetoError         = require('../error/PasetoError');
const InvalidVersionError = require('../error/InvalidVersionError');
const SecurityError = require("../error/SecurityError");


/***
 * V4
 *
 * protocol version 2
 *
 * @constructor
 * @api public
 */
module.exports = V4;
function V4() {
    this._repr = 'v4';

    this._constants = {
        INFO_ENCRYPT_KEY: "paseto-encryption-key",
        INFO_AUTH_KEY: "paseto-auth-key-for-aead",
        SYMMETRIC_KEY_BYTES: 32
    }
}


/***
 * private
 *
 * generate a private key for use with the protocol
 *
 * @function
 * @api public
 *
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
V4.prototype.private = pk;
function pk(cb) {
    const done = utils.ret(cb);

    // minor hack to mimic php api without circular dependency - probably a better way to do this
    const PrivateKey = require('../key/private');
    const pk = new PrivateKey(new V4());
    return pk.generate().then((err) => {
        if (err) { return done(err); }
        return done(null, pk);
    });
}


/***
 * symmetric
 *
 * generate a symmetric key for use with the protocol
 *
 * @function
 * @api public
 *
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
V4.prototype.symmetric = sk;
function sk(cb) {
    const done = utils.ret(cb);

    // minor hack to mimic php api without circular dependency - probably a better way to do this
    const SymmetricKey = require('../key/symmetric');
    const sk = new SymmetricKey(new V4());
    return sk.generate().then((err) => {
        if (err) { return done(err); }
        return done(null, sk);
    });
}


/***
 * repr
 *
 * get protocol representation
 *
 * @function
 * @api public
 *
 * @returns {String}
 */
V4.prototype.repr = repr;
function repr() {
    return this._repr;
}


/***
 * sklength
 *
 * get symmetric key length
 *
 * @function
 * @api public
 *
 * @returns {Number}
 */
V4.prototype.sklength = sklength;
function sklength() {
    return this._constants.SYMMETRIC_KEY_BYTES;
}


/***
 * __encrypt
 *
 * symmetric authenticated encryption
 *
 * @function
 * @api private
 *
 * @param {String|Buffer} data
 * @param {Object} key
 * @param {String|Buffer} footer
 * @param {String|Buffer} implicit
 * @param {String|Buffer} nonce
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
V4.prototype.__encrypt = __encrypt;
function __encrypt(data, key, footer, implicit, nonce, cb) {
    footer = footer || '';

    const self = this;
    const done = utils.ret(cb);

    if (key.purpose() !== 'local') {
        return done(new InvalidVersionError('The given key is not intended for local PASETO tokens.'));
    }
    if (!(key.protocol() instanceof V4)) {
        return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
    }

    return sodium.ready.then(() => {

        const header = utils.local(self);

        [ data, footer, nonce ] = (utils.parse('utf-8'))(data, footer, nonce);

        let token;
        try {
            token = aeadEncrypt(key, header, data, footer, implicit, nonce);
        } catch (ex) {
            return done(ex);
        }

        return done(null, token);
    });
}


/***
 * encrypt
 *
 * symmetric authenticated encryption (public api)
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} data
 * @param {Object} key
 * @param {String|Buffer} footer
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
V4.prototype.encrypt = encrypt;
function encrypt(data, key, footer, implicit, cb) {
    return this.__encrypt(data, key, footer, implicit, '', cb);
}


/***
 * decrypt
 *
 * symmetric authenticated decryption
 *
 * @function
 * @api public
 *
 * @param {String} token
 * @param {Object} key
 * @param {String|Buffer} footer
 * @param {String|Buffer} implicit
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
V4.prototype.decrypt = decrypt;
function decrypt(token, key, footer, implicit, cb) {
    const self = this;
    const done = utils.ret(cb);

    if (key.purpose() !== 'local') {
        return done(new InvalidVersionError('The given key is not intended for local PASETO tokens.'));
    }
    if (!(key.protocol() instanceof V4)) {
        return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
    }

    return sodium.ready.then(() => {

        let payload, data, header = utils.local(self);
        try {
            [ header, payload, footer ] = decapsulate(header, token, footer);

            data = aeadDecrypt(key, header, payload, footer, implicit);
        } catch (ex) {
            return done(ex);
        }

        return done(null, data);
    });
}


/***
 * sign
 *
 * asymmetric authentication
 *
 * @function
 * @api public
 *
 * @param {String|Buffer} data
 * @param {Object} key
 * @param {String|Buffer} footer
 * @param {String|Buffer} implicit
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
V4.prototype.sign = sign;
function sign(data, key, footer, implicit, cb) {
    footer = footer || '';

    const self = this;
    const done = utils.ret(cb);

    if (key.purpose() !== 'public') {
        return done(new InvalidVersionError('The given key is not intended for local PASETO tokens.'));
    }
    if (!(key.protocol() instanceof V4)) {
        return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
    }

    return sodium.ready.then(() => {

        const header = utils.public(self);

        [ data, footer ] = (utils.parse('utf-8'))(data, footer);

        // sign

        let payload;
        try {
            payload = utils.pae(header, data, footer, implicit);
        } catch (ex) {
            return done(ex);
        }

        const _signature = sodium.crypto_sign_detached(payload, key.raw());
        const signature  = Buffer.from(_signature);

        // format

        const token = header.toString('utf-8') + utils.toB64URLSafe(Buffer.concat([ data, signature ]));

        return (!Buffer.byteLength(footer))
            ? done(null, token)
            : done(null, token + '.' + utils.toB64URLSafe(footer));
    });
}


/***
 * verify
 *
 * asymmetric authentication
 *
 * @function
 * @api public
 *
 * @param {String} token
 * @param {Object} key
 * @param {String|Buffer} footer
 * @param {String|Buffer} implicit
 * @param {Function} cb
 * @returns {Callback|Promise}
 */
V4.prototype.verify = verify;
function verify(token, key, footer, implicit, cb) {
    const self = this;
    const done = utils.ret(cb);

    if (key.purpose() !== 'public') {
        return done(new InvalidVersionError('The given key is not intended for local PASETO tokens.'));
    }
    if (!(key.protocol() instanceof V4)) {
        return done(new InvalidVersionError('The given key is not intended for this version of PASETO.'));
    }

    return sodium.ready.then(() => {

        let payload, header = utils.public(self);
        try {
            [ header, payload, footer ] = decapsulate(header, token, footer);
        } catch (ex) {
            return done(ex);
        }

        // recover data

        const plen = Buffer.byteLength(payload);

        const data      = Buffer.from(payload).slice(0, plen - sodium.crypto_sign_BYTES);
        const signature = Buffer.from(payload).slice(plen - sodium.crypto_sign_BYTES);

        // verify signature

        let expected;
        try {
            expected = utils.pae(header, data, footer, implicit);
        } catch (ex) {
            return done(ex);
        }

        const valid = sodium.crypto_sign_verify_detached(signature, expected, key.raw());

        if (!valid) { return done(new PasetoError('Invalid signature for this message')); }

        // format

        return done(null, data.toString('utf-8'));
    });
}

/**
 * @param {object} key
 * @param {Buffer} nonce
 */
function splitKey(key, nonce)
{
    const tmp = Buffer.from(sodium.crypto_generichash(
        56,
        Buffer.concat([this._constants.INFO_ENCRYPT_KEY, nonce]),
        key
    ));
    const Ek = tmp.slice(0, 32);
    const n2 = tmp.slice(32, 24);

    const Ak = Buffer.from(sodium.crypto_generichash(
        32,
        Buffer.concat([this._constants.INFO_AUTH_KEY, nonce]),
        key
    ));
    return {Ek, Ak, n2};
}

/***
 * aeadEncrypt
 *
 * internals of symmetric authenticated encryption
 *
 * @function
 * @api private
 *
 * @param {Object} key
 * @param {Buffer} header
 * @param {Buffer} plaintext
 * @param {Buffer} footer
 * @param {Buffer} implicit
 * @param {Buffer} nonce
 * @returns {Callback|Promise}
 */
V4.prototype.aeadEncrypt = aeadEncrypt;
function aeadEncrypt(key, header, plaintext, footer, implicit, nonce) {
    // Step 2:
    nonce   = nonce || sodium.randombytes_buf(32);

    // Step 3:
    const {Ek, Ak, n2} = splitKey(key, nonce);

    // Step 4:
    const cipher = Buffer.from(sodium.crypto_stream_xchacha20_xor(
        plaintext,
        n2,
        Ek
    ));
    sodium.memzero(Ek);
    sodium.memzero(n2);

    // Step 5:
    let preAuth;
    try {
        preAuth = utils.pae(header, nonce, cipher, footer, implicit);
    } catch (ex) {
        return done(ex);
    }
    // Step 6:
    const tag = Buffer.from(sodium.crypto_generichash(32, preAuth, Ak));


    // Step 7:
    const payload = Buffer.concat([ nonce, cipher, tag ]);
    const token   = header.toString('utf-8') + utils.toB64URLSafe(payload);

    return (!Buffer.byteLength(footer))
        ? token
        : token + '.' + utils.toB64URLSafe(footer);
}


/***
 * aeadDecrypt
 *
 * internals of symmetric authenticated decryption
 *
 * @function
 * @api private
 *
 * @param {Object} key
 * @param {Buffer} header
 * @param {Buffer} payload
 * @param {Buffer} footer
 * @param {Buffer} implicit
 * @returns {Callback|Promise}
 */
V4.prototype.aeadDecrypt = aeadDecrypt;
function aeadDecrypt(key, header, payload, footer, implicit) {

    // Step 3:
    const plen = Buffer.byteLength(payload);
    const nonce = Buffer.from(payload).slice(0, 32);
    const cipher = Buffer.from(payload).slice(32, plen - 64);
    const tag = Buffer.from(payload).slice(plen - 32, 32);

    // Step 4:
    const {Ek, Ak, n2} = splitKey(key, nonce);

    // Step 5:
    let preAuth;
    try {
        preAuth = utils.pae(header, nonce, cipher, footer, implicit);
    } catch (ex) {
        return done(ex);
    }
    // Step 6:
    const calc = Buffer.from(sodium.crypto_generichash(32, preAuth, Ak));

    // Step 7:
    if (!utils.cnstcomp(tag, calc)) {
        return reject(new SecurityError('Invalid MAC for given ciphertext.'));
    }

    // Step 8:
    const plaintext = Buffer.from(sodium.crypto_stream_xchacha20_xor(
        cipher,
        n2,
        Ek
    ));

    // Step 9:
    return plaintext.toString('utf-8');
}
