import { crypto_sign_ed25519_pk_to_curve25519 } from 'sodium-native';

import assert from 'assert';
import * as x25519 from '../pkg/wasm_x25519.js';

const [secret, pubkey] = x25519.generate_keypair();

assert.strictEqual(x25519.derive_public(secret), pubkey);

const edpk = x25519.compress_public(pubkey);

const bufpk = Buffer.from(edpk, 'base64');
const writepk = Buffer.from(edpk, 'base64');

crypto_sign_ed25519_pk_to_curve25519(writepk, bufpk);

assert.strictEqual(writepk.toString('base64'), pubkey);
assert.strictEqual(x25519.decompress_public(edpk), pubkey);
