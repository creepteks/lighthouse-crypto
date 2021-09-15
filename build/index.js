"use strict";
exports.__esModule = true;
var assert = require("assert");
var crypto = require("crypto");
var ethers = require("ethers");
var ff = require('ffjavascript');
var createBlakeHash = require('blake-hash');
var circomlib_1 = require("circomlib");
var IncrementalQuinTree_1 = require("./IncrementalQuinTree");
exports.IncrementalQuinTree = IncrementalQuinTree_1.IncrementalQuinTree;
var stringifyBigInts = ff.utils.stringifyBigInts;
exports.stringifyBigInts = stringifyBigInts;
var unstringifyBigInts = ff.utils.unstringifyBigInts;
exports.unstringifyBigInts = unstringifyBigInts;
var SNARK_FIELD_SIZE = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
exports.SNARK_FIELD_SIZE = SNARK_FIELD_SIZE;
// A nothing-up-my-sleeve zero value
// Should be equal to 8370432830353022751713833565135785980866757267633941821328460903436894336785
var NOTHING_UP_MY_SLEEVE = BigInt(ethers.utils.solidityKeccak256(['bytes'], [ethers.utils.toUtf8Bytes('Maci')])) % SNARK_FIELD_SIZE;
exports.NOTHING_UP_MY_SLEEVE = NOTHING_UP_MY_SLEEVE;
// The pubkey is the first Pedersen base point from iden3's circomlib
// See https://github.com/iden3/circomlib/blob/d5ed1c3ce4ca137a6b3ca48bec4ac12c1b38957a/src/pedersen_printbases.js
var NOTHING_UP_MY_SLEEVE_PUBKEY = [
    BigInt('10457101036533406547632367118273992217979173478358440826365724437999023779287'),
    BigInt('19824078218392094440610104313265183977899662750282163392862422243483260492317')
];
exports.NOTHING_UP_MY_SLEEVE_PUBKEY = NOTHING_UP_MY_SLEEVE_PUBKEY;
/*
 * Convert a BigInt to a Buffer
 */
var bigInt2Buffer = function (i) {
    var hexStr = i.toString(16);
    while (hexStr.length < 64) {
        hexStr = '0' + hexStr;
    }
    return Buffer.from(hexStr, 'hex');
};
exports.bigInt2Buffer = bigInt2Buffer;
// Hash up to 2 elements
var poseidonT3 = function (inputs) {
    assert(inputs.length === 2);
    return circomlib_1.poseidon(inputs);
};
// Hash up to 5 elements
var poseidonT6 = function (inputs) {
    assert(inputs.length === 5);
    return circomlib_1.poseidon(inputs);
};
var hash5 = function (elements) {
    var elementLength = elements.length;
    if (elements.length > 5) {
        throw new Error("elements length should not greater than 5, got " + elements.length);
    }
    var elementsPadded = elements.slice();
    if (elementLength < 5) {
        for (var i = elementLength; i < 5; i++) {
            elementsPadded.push(BigInt(0));
        }
    }
    return poseidonT6(elementsPadded);
};
exports.hash5 = hash5;
/*
 * A convenience function for to use Poseidon to hash a Plaintext with
 * no more than 11 elements
 */
var hash11 = function (elements) {
    var elementLength = elements.length;
    if (elementLength > 11) {
        throw new TypeError("elements length should not greater than 11, got " + elementLength);
    }
    var elementsPadded = elements.slice();
    if (elementLength < 11) {
        for (var i = elementLength; i < 11; i++) {
            elementsPadded.push(BigInt(0));
        }
    }
    return poseidonT3([
        poseidonT3([
            poseidonT6(elementsPadded.slice(0, 5)),
            poseidonT6(elementsPadded.slice(5, 10))
        ]),
        elementsPadded[10]
    ]);
};
exports.hash11 = hash11;
/*
 * Hash a single BigInt with the Poseidon hash function
 */
var hashOne = function (preImage) {
    return poseidonT3([preImage, BigInt(0)]);
};
exports.hashOne = hashOne;
/*
 * Hash two BigInts with the Poseidon hash function
 */
var hashLeftRight = function (left, right) {
    return poseidonT3([left, right]);
};
exports.hashLeftRight = hashLeftRight;
/*
 * Returns a BabyJub-compatible random value. We create it by first generating
 * a random value (initially 256 bits large) modulo the snark field size as
 * described in EIP197. This results in a key size of roughly 253 bits and no
 * more than 254 bits. To prevent modulo bias, we then use this efficient
 * algorithm:
 * http://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/lib/libc/crypt/arc4random_uniform.c
 * @return A BabyJub-compatible random value.
 */
var genRandomBabyJubValue = function () {
    // Prevent modulo bias
    //const lim = BigInt('0x10000000000000000000000000000000000000000000000000000000000000000')
    //const min = (lim - SNARK_FIELD_SIZE) % SNARK_FIELD_SIZE
    var min = BigInt('6350874878119819312338956282401532410528162663560392320966563075034087161851');
    var rand;
    while (true) {
        rand = BigInt('0x' + crypto.randomBytes(32).toString('hex'));
        if (rand >= min) {
            break;
        }
    }
    var privKey = rand % SNARK_FIELD_SIZE;
    assert(privKey < SNARK_FIELD_SIZE);
    return privKey;
};
/*
 * @return A BabyJub-compatible private key.
 */
var genPrivKey = function () {
    return genRandomBabyJubValue();
};
exports.genPrivKey = genPrivKey;
/*
 * @return A BabyJub-compatible salt.
 */
var genRandomSalt = function () {
    return genRandomBabyJubValue();
};
exports.genRandomSalt = genRandomSalt;
/*
 * An internal function which formats a random private key to be compatible
 * with the BabyJub curve. This is the format which should be passed into the
 * PublicKey and other circuits.
 */
var formatPrivKeyForBabyJub = function (privKey) {
    var sBuff = circomlib_1.eddsa.pruneBuffer(createBlakeHash("blake512").update(bigInt2Buffer(privKey)).digest().slice(0, 32));
    var s = ff.utils.leBuff2int(sBuff);
    return ff.Scalar.shr(s, 3);
};
exports.formatPrivKeyForBabyJub = formatPrivKeyForBabyJub;
/*
 * Losslessly reduces the size of the representation of a public key
 * @param pubKey The public key to pack
 * @return A packed public key
 */
var packPubKey = function (pubKey) {
    return circomlib_1.babyJub.packPoint(pubKey);
};
exports.packPubKey = packPubKey;
/*
 * Restores the original PubKey from its packed representation
 * @param packed The value to unpack
 * @return The unpacked public key
 */
var unpackPubKey = function (packed) {
    return circomlib_1.babyJub.unpackPoint(packed);
};
exports.unpackPubKey = unpackPubKey;
/*
 * @param privKey A private key generated using genPrivKey()
 * @return A public key associated with the private key
 */
var genPubKey = function (privKey) {
    privKey = BigInt(privKey.toString());
    assert(privKey < SNARK_FIELD_SIZE);
    return circomlib_1.eddsa.prv2pub(bigInt2Buffer(privKey));
};
exports.genPubKey = genPubKey;
var genKeypair = function () {
    var privKey = genPrivKey();
    var pubKey = genPubKey(privKey);
    var Keypair = { privKey: privKey, pubKey: pubKey };
    return Keypair;
};
exports.genKeypair = genKeypair;
/*
 * Generates an Elliptic-curve Diffie–Hellman shared key given a private key
 * and a public key.
 * @return The ECDH shared key.
 */
var genEcdhSharedKey = function (privKey, pubKey) {
    return circomlib_1.babyJub.mulPointEscalar(pubKey, formatPrivKeyForBabyJub(privKey))[0];
};
exports.genEcdhSharedKey = genEcdhSharedKey;
/*
 * Encrypts a plaintext using a given key.
 * @return The ciphertext.
 */
var encrypt = function (plaintext, sharedKey) {
    // Generate the IV
    var iv = circomlib_1.mimc7.multiHash(plaintext, BigInt(0));
    var ciphertext = {
        iv: iv,
        data: plaintext.map(function (e, i) {
            return e + circomlib_1.mimc7.hash(sharedKey, iv + BigInt(i));
        })
    };
    // TODO: add asserts here
    return ciphertext;
};
exports.encrypt = encrypt;
/*
 * Decrypts a ciphertext using a given key.
 * @return The plaintext.
 */
var decrypt = function (ciphertext, sharedKey) {
    var plaintext = ciphertext.data.map(function (e, i) {
        return BigInt(e) - BigInt(circomlib_1.mimc7.hash(sharedKey, BigInt(ciphertext.iv) + BigInt(i)));
    });
    return plaintext;
};
exports.decrypt = decrypt;
/*
 * Generates a signature given a private key and plaintext.
 * @return The signature.
 */
var sign = function (privKey, msg) {
    return circomlib_1.eddsa.signPoseidon(bigInt2Buffer(privKey), msg);
};
exports.sign = sign;
/*
 * Checks whether the signature of the given plaintext was created using the
 * private key associated with the given public key.
 * @return True if the signature is valid, and false otherwise.
 */
var verifySignature = function (msg, signature, pubKey) {
    return circomlib_1.eddsa.verifyPoseidon(msg, signature, pubKey);
};
exports.verifySignature = verifySignature;
//# sourceMappingURL=index.js.map