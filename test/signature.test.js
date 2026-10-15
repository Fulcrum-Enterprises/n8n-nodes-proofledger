// Unit tests for the webhook signature check. Run `npm run build` first; `npm test` runs these.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHmac } = require('node:crypto');

const { verifySignature } = require('../dist/nodes/ProofLedgerTrigger/ProofLedgerTrigger.node.js');

const secret = 'whsec_test_secret';
const body = JSON.stringify({ id: 'evt_1', type: 'proof.polygon.anchored', data: { proof: { id: 42 } } });
const now = 1_800_000_000;
const sign = (t, s = secret, b = body) => `t=${t},v1=${createHmac('sha256', s).update(`${t}.${b}`).digest('hex')}`;

test('accepts a fresh, correctly signed body', () => {
	assert.equal(verifySignature(secret, sign(now), body, now), true);
});

test('accepts a signature up to 5 minutes old or ahead', () => {
	assert.equal(verifySignature(secret, sign(now - 300), body, now), true);
	assert.equal(verifySignature(secret, sign(now + 300), body, now), true);
});

test('rejects a signature older than 5 minutes (replay)', () => {
	assert.equal(verifySignature(secret, sign(now - 301), body, now), false);
});

test('rejects a body that was changed after signing', () => {
	assert.equal(verifySignature(secret, sign(now), body.replace('42', '43'), now), false);
});

test('rejects a signature made with another secret', () => {
	assert.equal(verifySignature(secret, sign(now, 'whsec_other'), body, now), false);
});

test('rejects a missing, malformed or wrong-length header', () => {
	assert.equal(verifySignature(secret, undefined, body, now), false);
	assert.equal(verifySignature(secret, '', body, now), false);
	assert.equal(verifySignature(secret, 'v1=abc', body, now), false);
	assert.equal(verifySignature(secret, `t=${now}`, body, now), false);
	assert.equal(verifySignature(secret, `t=${now},v1=${'0'.repeat(63)}`, body, now), false);
	assert.equal(verifySignature(secret, `t=abc,v1=${'0'.repeat(64)}`, body, now), false);
});

test('ignores extra header parts and spacing, as the spec allows', () => {
	const sig = sign(now);
	assert.equal(verifySignature(secret, ` ${sig} , v0=ignored`, body, now), true);
});
