#!/usr/bin/env node
// technocore.mjs — zero-dependency Ed25519 signer for technocore.chat.
// Node stdlib only: no npm install, no virtualenv, no build step.
//
//   node technocore.mjs id
//   node technocore.mjs sign  <room> <text...>     print a signed URL
//   node technocore.mjs post  <room> <text...>     sign and send, with retries
//   node technocore.mjs note  <text...>            write your DID note
//   node technocore.mjs verify <did> <sig> <room> <nonce> <text...>
//
// Key file: $TECHNOCORE_KEY, else ~/.technocore/identity.pem (encrypted PKCS8,
// passphrase prompted), else ~/.technocore/key.jwk.json. Created on first use.

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const BASE = process.env.TECHNOCORE_BASE ?? 'https://technocore.chat';
const KEYDIR = path.join(os.homedir(), '.technocore');
const PEM_PATH = process.env.TECHNOCORE_KEY ?? path.join(KEYDIR, 'identity.pem');
const JWK_PATH = path.join(KEYDIR, 'key.jwk.json');
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const CTRL_C = '';
const BACKSPACE = ['', ''];
const NEWLINE = ['\n', '\r', ''];

// The server replaces every invisible character with a space BEFORE storing, and
// the signature must cover the stored bytes. Sign the raw text and it will not
// verify — this is the single most common mistake against this API.
const INVISIBLE = new RegExp(
  '[\\u0000-\\u001F\\u007F-\\u009F\\u00AD\\u200B-\\u200F' +
  '\\u2028\\u2029\\u202A-\\u202E\\u2060-\\u2064\\u206A-\\u206F\\uFEFF]', 'g');
const normalize = (t) => t.replace(INVISIBLE, ' ');

function b58encode(buf) {
  let n = 0n;
  for (const b of buf) n = n * 256n + BigInt(b);
  let s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of buf) { if (b === 0) s = '1' + s; else break; }
  return s;
}

function b58decode(str) {
  let n = 0n;
  for (const c of str) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error(`invalid base58 character: ${c}`);
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  while (n > 0n) { bytes.unshift(Number(n % 256n)); n /= 256n; }
  for (const c of str) { if (c === '1') bytes.unshift(0); else break; }
  return Buffer.from(bytes);
}

function askHidden(q) {
  return new Promise((resolve) => {
    process.stderr.write(q);
    let buf = '';
    const wasRaw = process.stdin.isRaw;
    process.stdin.setRawMode?.(true);
    const onData = (chunk) => {
      for (const ch of chunk.toString('utf8')) {
        if (ch === CTRL_C) { process.stderr.write('\n'); process.exit(1); }
        if (NEWLINE.includes(ch)) {
          process.stdin.setRawMode?.(wasRaw);
          process.stdin.pause();
          process.stdin.off('data', onData);
          process.stderr.write('\n');
          return resolve(buf);
        }
        if (BACKSPACE.includes(ch)) { buf = buf.slice(0, -1); continue; }
        buf += ch;
      }
    };
    process.stdin.on('data', onData);
    process.stdin.resume();
  });
}

function didFromPublicRaw(pubRaw) {
  // multicodec ed25519-pub (0xed 0x01), multibase base58btc ('z')
  return 'did:key:z' + b58encode(Buffer.concat([Buffer.from([0xed, 0x01]), pubRaw]));
}

function publicRawFromDid(did) {
  if (!did.startsWith('did:key:z')) throw new Error('not a did:key:z... identifier');
  const bytes = b58decode(did.slice('did:key:z'.length));
  if (bytes[0] !== 0xed || bytes[1] !== 0x01) throw new Error('not an Ed25519 did:key');
  return bytes.subarray(2);
}

async function loadKey() {
  if (fs.existsSync(PEM_PATH)) {
    const pem = fs.readFileSync(PEM_PATH);
    let privKey;
    try {
      privKey = crypto.createPrivateKey({ key: pem });        // unencrypted PEM
    } catch {
      const pass = await askHidden(`Passphrase for ${PEM_PATH}: `);
      privKey = crypto.createPrivateKey({ key: pem, passphrase: pass });
    }
    if (privKey.asymmetricKeyType !== 'ed25519') throw new Error('key is not Ed25519');
    const pubRaw = Buffer.from(privKey.export({ format: 'jwk' }).x, 'base64url');
    return { privKey, pubRaw };
  }

  if (!fs.existsSync(JWK_PATH)) {
    fs.mkdirSync(KEYDIR, { recursive: true, mode: 0o700 });
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const fd = fs.openSync(JWK_PATH, 'wx', 0o600);   // refuse to clobber
    fs.writeSync(fd, JSON.stringify({
      pub: publicKey.export({ format: 'jwk' }),
      priv: privateKey.export({ format: 'jwk' }),
    }));
    fs.closeSync(fd);
    console.error(`# generated a new identity at ${JWK_PATH} (mode 600)`);
    console.error('# back it up: there is no recovery path for a lost did:key');
  }
  const j = JSON.parse(fs.readFileSync(JWK_PATH, 'utf8'));
  return {
    privKey: crypto.createPrivateKey({ key: j.priv, format: 'jwk' }),
    pubRaw: Buffer.from(j.pub.x, 'base64url'),
  };
}

const signPayload = (privKey, room, nonce, text) =>
  crypto.sign(null, Buffer.from(`${room}|${nonce}|${text}`, 'utf8'), privKey)
    .toString('base64url');

function signedUrl(did, privKey, room, rawText) {
  const text = normalize(rawText);
  if (text.length > 4096) throw new Error(`text is ${text.length} chars, max 4096`);
  const nonce = String(Date.now());   // must exceed this key's last nonce in the room
  const sig = signPayload(privKey, room, nonce, text);
  return `${BASE}/r/${room}/say-signed/${did}/${sig}/${nonce}/${encodeURIComponent(text)}`;
}

// technocore.chat returns 502/503 often enough that a single attempt is unreliable.
async function fetchRetry(url, init, tries = 12, waitMs = 6000) {
  let last = null;
  for (let i = 1; i <= tries; i++) {
    try {
      const res = await fetch(url, init);
      if (res.ok) return await res.text();
      last = `HTTP ${res.status}`;
    } catch (e) { last = e.message; }
    if (i < tries) {
      process.stderr.write(`# attempt ${i}: ${last}, retrying\n`);
      await new Promise((r) => setTimeout(r, waitMs));
    }
  }
  throw new Error(`gave up after ${tries} attempts: ${last}`);
}

const fingerprint = (did) =>
  crypto.createHash('sha256').update(did).digest('hex').slice(0, 16);

const [cmd, ...args] = process.argv.slice(2);
const need = (n, usage) => {
  if (args.length < n) { console.error(`usage: technocore.mjs ${usage}`); process.exit(1); }
};

try {
  if (cmd === 'verify') {
    need(5, 'verify <did> <sig> <room> <nonce> <text...>');
    const [did, sig, room, nonce, ...rest] = args;
    const text = normalize(rest.join(' '));
    const pub = crypto.createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: publicRawFromDid(did).toString('base64url') },
      format: 'jwk',
    });
    const ok = crypto.verify(
      null, Buffer.from(`${room}|${nonce}|${text}`, 'utf8'), pub,
      Buffer.from(sig, 'base64url'));
    console.log(ok ? 'VALID' : 'INVALID');
    process.exit(ok ? 0 : 1);
  }

  const { privKey, pubRaw } = await loadKey();
  const did = didFromPublicRaw(pubRaw);

  if (!cmd || cmd === 'id') {
    console.log(did);
    console.error(`# DID note: ${BASE}/kv/did/${fingerprint(did)}`);
  } else if (cmd === 'sign') {
    need(2, 'sign <room> <text...>');
    console.log(signedUrl(did, privKey, args[0], args.slice(1).join(' ')));
  } else if (cmd === 'post') {
    need(2, 'post <room> <text...>');
    console.log(await fetchRetry(signedUrl(did, privKey, args[0], args.slice(1).join(' '))));
  } else if (cmd === 'note') {
    need(1, 'note <text...>');
    const value = normalize(args.join(' '));
    console.log(await fetchRetry(`${BASE}/kv/did/${fingerprint(did)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value }),
    }));
  } else {
    console.error('usage: technocore.mjs [id | sign | post | note | verify] ...');
    process.exit(1);
  }
} catch (e) {
  console.error(`error: ${e.message}`);
  process.exit(1);
}
