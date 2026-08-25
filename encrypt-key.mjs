#!/usr/bin/env node
// Re-encrypt the EXISTING technocore did:key as a passphrase-protected PKCS8 PEM,
// in the format zunmax/technocore-did-starter expects. Keeps the SAME DID.
// The passphrase is read from the terminal and never leaves this process.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const SRC = path.join(os.homedir(), '.technocore', 'key.jwk.json');
const OUT = path.join(os.homedir(), '.technocore', 'identity.pem');
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const CTRL_C = '';
const BACKSPACE_CHARS = ['', ''];
const NEWLINE_CHARS = ['\n', '\r', ''];

function b58(buf) {
  let n = 0n;
  for (const b of buf) n = n * 256n + BigInt(b);
  let s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of buf) { if (b === 0) s = '1' + s; else break; }
  return s;
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
        if (NEWLINE_CHARS.includes(ch)) {
          process.stdin.setRawMode?.(wasRaw);
          process.stdin.pause();
          process.stdin.off('data', onData);
          process.stderr.write('\n');
          return resolve(buf);
        }
        if (BACKSPACE_CHARS.includes(ch)) { buf = buf.slice(0, -1); continue; }
        buf += ch;
      }
    };
    process.stdin.on('data', onData);
    process.stdin.resume();
  });
}

if (!fs.existsSync(SRC)) { console.error(`no key at ${SRC}`); process.exit(1); }
if (fs.existsSync(OUT)) { console.error(`refusing to overwrite ${OUT}`); process.exit(1); }

const j = JSON.parse(fs.readFileSync(SRC, 'utf8'));
const privKey = crypto.createPrivateKey({ key: j.priv, format: 'jwk' });
const pubRaw = Buffer.from(j.pub.x, 'base64url');
const did = 'did:key:z' + b58(Buffer.concat([Buffer.from([0xed, 0x01]), pubRaw]));

const pass = await askHidden('New passphrase (min 12 chars): ');
const again = await askHidden('Confirm passphrase: ');
if (pass !== again) { console.error('passphrases do not match'); process.exit(1); }
if (pass.length < 12) { console.error('passphrase must be at least 12 characters'); process.exit(1); }

const pem = privKey.export({
  type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: pass,
});
fs.writeFileSync(OUT, pem, { mode: 0o600 });
fs.chmodSync(OUT, 0o600);

// Prove it round-trips before reporting success.
const reloaded = crypto.createPrivateKey({ key: fs.readFileSync(OUT), passphrase: pass });
const check = 'did:key:z' + b58(Buffer.concat([
  Buffer.from([0xed, 0x01]),
  Buffer.from(reloaded.export({ format: 'jwk' }).x, 'base64url'),
]));
console.log(check === did
  ? `OK  ${OUT}\nsame DID: ${did}`
  : 'MISMATCH - do not use this file');
