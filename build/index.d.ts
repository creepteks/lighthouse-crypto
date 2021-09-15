/// <reference types="node" />
import { IncrementalQuinTree } from './IncrementalQuinTree';
declare const stringifyBigInts: (obj: object) => any;
declare const unstringifyBigInts: (obj: object) => any;
declare type SnarkBigInt = BigInt;
declare type PrivKey = BigInt;
declare type PubKey = BigInt[];
declare type EcdhSharedKey = BigInt;
declare type Plaintext = BigInt[];
interface Keypair {
    privKey: PrivKey;
    pubKey: PubKey;
}
interface Ciphertext {
    iv: BigInt;
    data: BigInt[];
}
interface Signature {
    R8: BigInt[];
    S: BigInt;
}
declare const SNARK_FIELD_SIZE: bigint;
declare const NOTHING_UP_MY_SLEEVE: bigint;
declare const NOTHING_UP_MY_SLEEVE_PUBKEY: PubKey;
declare const bigInt2Buffer: (i: BigInt) => Buffer;
declare const hash5: (elements: Plaintext) => BigInt;
declare const hash11: (elements: Plaintext) => BigInt;
declare const hashOne: (preImage: BigInt) => BigInt;
declare const hashLeftRight: (left: BigInt, right: BigInt) => BigInt;
declare const genPrivKey: () => BigInt;
declare const genRandomSalt: () => BigInt;
declare const formatPrivKeyForBabyJub: (privKey: BigInt) => any;
declare const packPubKey: (pubKey: PubKey) => Buffer;
declare const unpackPubKey: (packed: Buffer) => PubKey;
declare const genPubKey: (privKey: BigInt) => PubKey;
declare const genKeypair: () => Keypair;
declare const genEcdhSharedKey: (privKey: BigInt, pubKey: PubKey) => BigInt;
declare const encrypt: (plaintext: Plaintext, sharedKey: BigInt) => Ciphertext;
declare const decrypt: (ciphertext: Ciphertext, sharedKey: BigInt) => Plaintext;
declare const sign: (privKey: BigInt, msg: BigInt) => Signature;
declare const verifySignature: (msg: BigInt, signature: Signature, pubKey: PubKey) => boolean;
export { genRandomSalt, genPrivKey, genPubKey, genKeypair, genEcdhSharedKey, encrypt, decrypt, sign, hashOne, hash5, hash11, hashLeftRight, verifySignature, Signature, PrivKey, PubKey, Keypair, EcdhSharedKey, Ciphertext, Plaintext, SnarkBigInt, stringifyBigInts, unstringifyBigInts, formatPrivKeyForBabyJub, IncrementalQuinTree, NOTHING_UP_MY_SLEEVE, NOTHING_UP_MY_SLEEVE_PUBKEY, SNARK_FIELD_SIZE, bigInt2Buffer, packPubKey, unpackPubKey, };
