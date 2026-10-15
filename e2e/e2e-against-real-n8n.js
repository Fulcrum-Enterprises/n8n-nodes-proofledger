// Proof that the package works against a real n8n (2.43.5) and the ProofLedger app.
// Not part of `npm test`: it needs a scratch checkout of ProofLedger.io with a fake signer
// (scratchpad/pltest in Craig's session), an n8n install beside it, and the test https cert.
// Kept here so the method is on record; run from that scratch directory. 34 checks on 2026-10-15.

// End-to-end check of n8n-nodes-proofledger against a real n8n (installed here) and the
// scratch ProofLedger app (fake signer, scratch DB). Nothing live.
//   part 1: `n8n execute` runs a workflow through every operation of the ProofLedger node
//   part 2: `n8n start` activates a ProofLedger Trigger workflow; the app registers the
//           webhook (through a local https proxy with the test cert), a forged signature is
//           refused with 401, a signed test event and a real anchored-proof event each start
//           an execution.
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');

const SCRATCH = path.resolve(__dirname, '..');
const PLTEST = path.join(SCRATCH, 'pltest');
const Database = require(path.join(PLTEST, 'node_modules', 'better-sqlite3'));
const PKG = 'C:/Users/csolo/Documents/HomeLab/n8n-nodes-proofledger';
const N8N_BIN = path.join(__dirname, 'node_modules', 'n8n', 'bin', 'n8n');
const HOME = path.join(__dirname, 'n8nhome');
const SIGNER_PORT = 9791, APP_PORT = 3995, HOOK_PORT = 9443, N8N_PORT = 5681;
const CERT = path.join(PLTEST, 'hookcert', 'cert.pem'), KEY = path.join(PLTEST, 'hookcert', 'key.pem');
const CRED_ID = 'plcred0000000001', WF1 = 'plwf000000000001', WF2 = 'plwf000000000002';
const TRIGGER_WEBHOOK_ID = '3f0c2a1e-9d4b-4c7a-8e21-5b6d7c8e9f01';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rnd = () => crypto.randomBytes(32).toString('hex');
const results = [];
const check = (name, ok, detail) => { results.push(ok); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail !== undefined ? '  ' + String(detail).slice(0, 300) : ''}`); };

function httpJson(opts, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const mod = opts.protocol === 'https:' ? https : http;
    const req = mod.request({ ...opts, headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) } }, (res) => {
      let out = ''; res.on('data', (c) => { out += c; });
      res.on('end', () => { try { resolve({ code: res.statusCode, json: JSON.parse(out) }); } catch (_) { resolve({ code: res.statusCode, text: out.slice(0, 300) }); } });
    });
    req.on('error', reject); if (data) req.write(data); req.end();
  });
}
const app = (method, p, body, headers) => httpJson({ host: '127.0.0.1', port: APP_PORT, path: p, method, headers }, body);

// ------------------------------------------------------------------ scratch app + signer
const signer = http.createServer((req, res) => {
  let body = ''; req.on('data', (c) => { body += c; });
  req.on('end', () => {
    const { sha256Hex } = JSON.parse(body || '{}');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, txHash: '0x' + sha256Hex, chainName: 'polygon-test' }));
  });
});
let appProc, appLog = '';
async function startApp() {
  await new Promise((r) => signer.listen(SIGNER_PORT, '127.0.0.1', r));
  appProc = spawn(process.execPath, ['src/server.js'], {
    cwd: PLTEST,
    env: { ...process.env, PORT: String(APP_PORT), NODE_ENV: 'development',
           POLYGON_ANCHORING_MODE: 'signer', SIGNER_BASE_URL: `http://127.0.0.1:${SIGNER_PORT}`, SIGNER_TOKEN: 'test', POLYGON_SIGNING_MODE: '',
           STRIPE_SECRET_KEY: 'sk_test_placeholder', STRIPE_WEBHOOK_SECRET: 'whsec_placeholder', JWT_SECRET: 'test-only-secret', SESSION_SECRET: 'test-only-secret',
           NODE_EXTRA_CA_CERTS: CERT, WEBHOOKS_TEST_ALLOW_LOOPBACK: '1', WEBHOOKS_RETRY_MINUTES: '0.05,0.05,0.05' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  appProc.stdout.on('data', (d) => { appLog += d; }); appProc.stderr.on('data', (d) => { appLog += d; });
  for (let i = 0; i < 60; i++) { await sleep(500); try { const r = await app('GET', '/api/health'); if (r.code < 500 || r.code === 503) return; } catch (_) {} }
  throw new Error('app did not start\n' + appLog.slice(-2000));
}
function makeKey() {
  const db = new Database(path.join(PLTEST, 'proofs.db')); db.pragma('busy_timeout = 5000');
  const now = new Date().toISOString();
  const u = db.prepare(`INSERT INTO users (email, subscription_status, created_at) VALUES (?, 'BUSINESS', ?)`).run(`n8n-${Date.now()}@local.test`, now);
  const rawKey = 'sk_' + crypto.randomBytes(20).toString('hex');
  db.prepare(`INSERT INTO api_keys (user_id, name, key_prefix, key_hash, created_at, is_active, usage_count, terms_accepted_at) VALUES (?, 'n8n', ?, ?, ?, 1, 0, ?)`)
    .run(u.lastInsertRowid, rawKey.slice(0, 11), crypto.createHash('sha256').update(rawKey).digest('hex'), now, now);
  db.close();
  return { userId: Number(u.lastInsertRowid), rawKey };
}

// ------------------------------------------------------------------ n8n helpers
const n8nEnv = {
  ...process.env,
  N8N_USER_FOLDER: HOME, N8N_ENCRYPTION_KEY: 'n8n-test-only-key', N8N_CUSTOM_EXTENSIONS: path.join(PKG, 'dist'),
  N8N_PORT: String(N8N_PORT), N8N_LISTEN_ADDRESS: '127.0.0.1', WEBHOOK_URL: `https://hooks.proofledger.test:${HOOK_PORT}/`, N8N_WEBHOOK_URL: `https://hooks.proofledger.test:${HOOK_PORT}/`,
  N8N_LOG_LEVEL: 'warn', N8N_DIAGNOSTICS_ENABLED: 'false', N8N_VERSION_NOTIFICATIONS_ENABLED: 'false', N8N_PERSONALIZATION_ENABLED: 'false',
  N8N_RUNNERS_ENABLED: 'false', N8N_SECURE_COOKIE: 'false', N8N_TEMPLATES_ENABLED: 'false', N8N_HIRING_BANNER_ENABLED: 'false',
  N8N_BLOCK_ENV_ACCESS_IN_NODE: 'false', N8N_RESTRICT_FILE_ACCESS_TO: path.join(__dirname, 'tplfile'), NODE_EXTRA_CA_CERTS: CERT, DB_SQLITE_POOL_SIZE: '1',
};
function n8n(args, opts = {}) {
  const r = spawnSync(process.execPath, [N8N_BIN, ...args], { env: n8nEnv, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...opts });
  return r;
}
const pl = (name, parameters, extra = {}) => ({
  id: crypto.randomUUID(), name, type: 'CUSTOM.proofLedger', typeVersion: 1, position: [0, 0], parameters,
  credentials: { proofLedgerApi: { id: CRED_ID, name: 'ProofLedger scratch' } }, ...extra,
});
function chain(names) {
  const connections = {};
  for (let i = 0; i < names.length - 1; i++) connections[names[i]] = { main: [[{ node: names[i + 1], type: 'main', index: 0 }]] };
  return connections;
}

(async () => {
  fs.rmSync(HOME, { recursive: true, force: true }); fs.mkdirSync(HOME, { recursive: true });
  await startApp();
  const { userId, rawKey } = makeKey();
  const ext = 'n8n-' + Date.now();
  const text = 'hello proofledger ' + rnd();
  const textHash = crypto.createHash('sha256').update(text, 'utf8').digest('hex');
  const batchHashes = [rnd(), rnd(), rnd()];

  // ---- credentials + part 1 workflow ------------------------------------------------------
  const credFile = path.join(__dirname, 'creds.json');
  fs.writeFileSync(credFile, JSON.stringify([{ id: CRED_ID, name: 'ProofLedger scratch', type: 'proofLedgerApi', data: { apiKey: rawKey, baseUrl: `http://127.0.0.1:${APP_PORT}` } }]));
  let r = n8n(['import:credentials', `--input=${credFile}`]);
  check('n8n import:credentials', r.status === 0, (r.stdout + r.stderr).trim().split('\n').slice(-3).join(' | '));

  const names = ['Manual', 'Edit Fields', 'Convert to File', 'Create From File', 'Get', 'Wait', 'Get Bundle', 'Verify', 'Get by External ID', 'Get Many', 'Webhook Create', 'Webhook List', 'Webhook Test', 'Webhook Delete', 'Branding'];
  const wf1 = {
    id: WF1, name: 'ProofLedger node e2e', active: false, settings: { executionOrder: 'v1' },
    nodes: [
      { id: crypto.randomUUID(), name: 'Manual', type: 'n8n-nodes-base.manualTrigger', typeVersion: 1, position: [0, 0], parameters: {} },
      { id: crypto.randomUUID(), name: 'Edit Fields', type: 'n8n-nodes-base.set', typeVersion: 3.4, position: [0, 0], parameters: { assignments: { assignments: [
        { id: 'a1', name: 'text', value: text, type: 'string' },
        { id: 'a2', name: 'ext', value: ext, type: 'string' },
        { id: 'a3', name: 'hashes', value: `={{ ${JSON.stringify(batchHashes)} }}`, type: 'array' },
      ] }, options: {} } },
      { id: crypto.randomUUID(), name: 'Convert to File', type: 'n8n-nodes-base.convertToFile', typeVersion: 1.1, position: [0, 0], parameters: { operation: 'toText', sourceProperty: 'text', binaryPropertyName: 'data', options: { fileName: 'hello.txt' } } },
      pl('Create From File', { resource: 'proof', operation: 'createFromFile', binaryPropertyName: 'data', additionalFields: { externalId: '={{ $("Edit Fields").item.json.ext }}' } }),
      pl('Get', { resource: 'proof', operation: 'get', proofId: '={{ $json.id }}' }),
      { id: crypto.randomUUID(), name: 'Wait', type: 'n8n-nodes-base.wait', typeVersion: 1.1, position: [0, 0], parameters: { resume: 'timeInterval', amount: 4, unit: 'seconds' }, webhookId: crypto.randomUUID() },
      pl('Get Bundle', { resource: 'proof', operation: 'getBundle', proofId: '={{ $json.id }}' }),
      pl('Verify', { resource: 'proof', operation: 'verify', sha256: '={{ $json.hash }}' }),
      pl('Get by External ID', { resource: 'proof', operation: 'getByExternalId', externalId: '={{ $("Edit Fields").item.json.ext }}' }),
      pl('Get Many', { resource: 'proof', operation: 'getMany', returnAll: false, limit: 5, filters: {} }),
      pl('Webhook Create', { resource: 'webhook', operation: 'create', url: 'https://example.com/n8n-e2e' }, { executeOnce: true }),
      pl('Webhook List', { resource: 'webhook', operation: 'getAll' }),
      pl('Webhook Test', { resource: 'webhook', operation: 'test', webhookId: '={{ $("Webhook Create").item.json.endpoint.id }}' }, { executeOnce: true }),
      pl('Webhook Delete', { resource: 'webhook', operation: 'delete', webhookId: '={{ $("Webhook Create").item.json.endpoint.id }}' }, { executeOnce: true }),
      pl('Branding', { resource: 'account', operation: 'getBranding' }),
      { id: crypto.randomUUID(), name: 'Split Out', type: 'n8n-nodes-base.splitOut', typeVersion: 1, position: [0, 0], parameters: { fieldToSplitOut: 'hashes', options: {} } },
      pl('Create Many', { resource: 'proof', operation: 'createMany', sha256: '={{ $json.hashes }}', additionalFields: {} }),
    ],
    connections: { ...chain(names), 'Split Out': { main: [[{ node: 'Create Many', type: 'main', index: 0 }]] } },
  };
  wf1.connections['Edit Fields'].main[0].push({ node: 'Split Out', type: 'main', index: 0 });
  const wf2 = {
    id: WF2, name: 'ProofLedger trigger e2e', active: true, settings: { executionOrder: 'v1' },
    nodes: [
      { id: crypto.randomUUID(), name: 'ProofLedger Trigger', type: 'CUSTOM.proofLedgerTrigger', typeVersion: 1, position: [0, 0], parameters: { includeTestEvents: true }, webhookId: TRIGGER_WEBHOOK_ID,
        credentials: { proofLedgerApi: { id: CRED_ID, name: 'ProofLedger scratch' } } },
      { id: crypto.randomUUID(), name: 'No Op', type: 'n8n-nodes-base.noOp', typeVersion: 1, position: [200, 0], parameters: {} },
    ],
    connections: { 'ProofLedger Trigger': { main: [[{ node: 'No Op', type: 'main', index: 0 }]] } },
  };
  const wfFile = path.join(__dirname, 'workflows.json');
  fs.writeFileSync(wfFile, JSON.stringify([wf1, wf2]));
  r = n8n(['import:workflow', `--input=${wfFile}`]);
  check('n8n import:workflow', r.status === 0, (r.stdout + r.stderr).trim().split('\n').slice(-3).join(' | '));
  // n8n 2.x: an imported workflow is a draft until published; publishing is what activates the trigger
  r = n8n(['publish:workflow', `--id=${WF2}`]);
  check('n8n publish:workflow (trigger workflow)', r.status === 0, (r.stdout + r.stderr).trim().split('\n').filter((l) => !/deprecat|->|^\s*$/i.test(l)).slice(-3).join(' | '));

  // ---- the two shipped templates, imported as a user would (types mapped to the custom loader) --
  const TPL = path.join(PKG, 'templates');
  const tplDir = path.join(__dirname, 'tplfile'); fs.mkdirSync(tplDir, { recursive: true });
  const tplFile = path.join(tplDir, 'evidence.txt'); const tplText = 'template evidence ' + rnd(); fs.writeFileSync(tplFile, tplText);
  const tplHash = crypto.createHash('sha256').update(tplText).digest('hex');
  const loadTpl = (file, id) => {
    const wf = JSON.parse(fs.readFileSync(path.join(TPL, file), 'utf8').replace(/n8n-nodes-proofledger\./g, 'CUSTOM.'));
    wf.id = id; wf.active = false;
    for (const n of wf.nodes) if (n.type.startsWith('CUSTOM.')) n.credentials = { proofLedgerApi: { id: CRED_ID, name: 'ProofLedger scratch' } };
    return wf;
  };
  const WF3 = 'plwf000000000003', WF4 = 'plwf000000000004';
  const tpl1 = loadTpl('anchor-file-and-save-bundle.json', WF3);
  tpl1.nodes.find((n) => n.name === 'Read File').parameters.fileSelector = tplFile.replace(/\\/g, '/');
  tpl1.nodes.find((n) => n.name === 'Wait for the anchor').parameters.amount = 3;
  const tpl2 = loadTpl('when-proof-anchored.json', WF4);
  const tplFileOut = path.join(__dirname, 'templates.json');
  fs.writeFileSync(tplFileOut, JSON.stringify([tpl1, tpl2]));
  r = n8n(['import:workflow', `--input=${tplFileOut}`]);
  check('templates import', r.status === 0, (r.stdout + r.stderr).trim().split('\n').slice(-2).join(' | '));
  r = n8n(['publish:workflow', `--id=${WF4}`]);
  check('template "when a proof is anchored" published', r.status === 0, '');
  r = n8n(['execute', `--id=${WF3}`, '--rawOutput'], { env: { ...n8nEnv, N8N_LOG_LEVEL: 'info' } });
  const tplJsonLine = r.stdout.split('\n').findIndex((l) => l.trim().startsWith('{'));
  let tplRun = null; try { tplRun = JSON.parse(r.stdout.split('\n').slice(tplJsonLine).join('\n')); } catch (_) {}
  const tplErr = (r.stdout + r.stderr).split('\n').filter((l) => /error|refused|failed/i.test(l) && !/^\s+at /.test(l) && !/Python task runner/.test(l)).slice(0, 6).join(' | ');
  check('template "anchor a file and save its bundle" executes', r.status === 0 && tplRun && !tplRun.data.resultData.error, tplRun && tplRun.data.resultData.error ? tplRun.data.resultData.error.message : tplErr);
  const proofFile = tplFile + '.proof.json';
  let savedBundle = null; try { savedBundle = JSON.parse(fs.readFileSync(proofFile, 'utf8')); } catch (_) {}
  check('template wrote <file>.proof.json with the file hash in verify-proof format', savedBundle && savedBundle.format === 'verify-proof/1' && savedBundle.hash === tplHash, savedBundle ? JSON.stringify(savedBundle).slice(0, 160) : 'no file at ' + proofFile);

  r = n8n(['execute', `--id=${WF1}`, '--rawOutput'], { env: { ...n8nEnv, N8N_LOG_LEVEL: 'info' } });
  const jsonLine = r.stdout.split('\n').findIndex((l) => l.trim().startsWith('{'));
  let run = null;
  try { run = JSON.parse(r.stdout.split('\n').slice(jsonLine).join('\n')); } catch (_) {}
  const execErr = (r.stdout + r.stderr).split('\n').filter((l) => /error|refused|failed/i.test(l) && !/^\s+at /.test(l)).slice(0, 8).join(' | ');
  check('n8n execute finished', r.status === 0 && run && !run.data.resultData.error, run && run.data.resultData.error ? run.data.resultData.error.message : execErr);
  if (!run) { console.log('--- execute output tail\n' + (r.stdout + r.stderr).slice(-3000)); appProc.kill(); signer.close(); process.exit(1); }
  const out = (name) => { const d = run && run.data.resultData.runData[name]; return d && d[0] && d[0].data && d[0].data.main[0].map((i) => i.json); };
  const err = (name) => { const d = run && run.data.resultData.runData[name]; return d && d[0] && d[0].error && d[0].error.message; };
  const cff = out('Create From File') || [];
  check('Create From File: 201-style response with the local hash', cff[0] && cff[0].sha256 === textHash && cff[0].id, err('Create From File') || JSON.stringify(cff[0]).slice(0, 200));
  const got = out('Get') || [];
  check('Get: same proof', got[0] && got[0].id === cff[0].id && got[0].sha256 === textHash, err('Get') || JSON.stringify(got[0]).slice(0, 160));
  const bundle = out('Get Bundle') || [];
  check('Get Bundle: verify-proof format for the same hash', bundle[0] && bundle[0].format === 'verify-proof/1' && bundle[0].hash === textHash, err('Get Bundle') || JSON.stringify(bundle[0]).slice(0, 200)); console.log('      bundle anchored =', bundle[0] && bundle[0].anchored, 'tx =', bundle[0] && bundle[0].tx_id);
  const ver = out('Verify') || [];
  check('Verify: found', ver[0] && ver[0].found === true && ver[0].proof && ver[0].proof.sha256 === textHash, err('Verify') || JSON.stringify(ver[0]).slice(0, 160));
  const byExt = out('Get by External ID') || [];
  check('Get by External ID: the proof itself', byExt[0] && byExt[0].external_id === ext && byExt[0].id === cff[0].id, err('Get by External ID') || JSON.stringify(byExt[0]).slice(0, 160));
  const many = out('Get Many') || [];
  check('Get Many: list, limit respected', many.length >= 1 && many.length <= 5 && many[0].id !== undefined, err('Get Many') || many.length);
  const whc = out('Webhook Create') || [];
  check('Webhook Create: endpoint + secret', whc[0] && whc[0].endpoint && whc[0].endpoint.id && typeof whc[0].secret === 'string', err('Webhook Create') || JSON.stringify(whc[0]).slice(0, 160));
  const whl = out('Webhook List') || [];
  check('Webhook List: lists it without the secret', whl.some((e) => e.id === whc[0].endpoint.id) && whl.every((e) => e.secret === undefined), err('Webhook List') || JSON.stringify(whl).slice(0, 160));
  const wht = out('Webhook Test') || [];
  check('Webhook Test: answered (example.com, delivery result reported)', wht[0] && 'ok' in wht[0] && 'status_code' in wht[0], err('Webhook Test') || JSON.stringify(wht[0]).slice(0, 160));
  const whd = out('Webhook Delete') || [];
  check('Webhook Delete: ok', whd[0] && whd[0].ok === true, err('Webhook Delete') || JSON.stringify(whd[0]).slice(0, 160));
  const br = out('Branding') || [];
  check('Branding: approved flag present', br[0] && typeof br[0].approved === 'boolean', err('Branding') || JSON.stringify(br[0]).slice(0, 160));
  const cm = out('Create Many') || [];
  check('Create Many: 3 items, each created, paired', cm.length === 3 && cm.every((x) => x.result === 'created' && x.proof && x.proof.id), err('Create Many') || JSON.stringify(cm).slice(0, 300));
  const cmPairs = run && run.data.resultData.runData['Create Many'] && run.data.resultData.runData['Create Many'][0].data.main[0].map((i) => i.pairedItem && i.pairedItem.item);
  check('Create Many: pairedItem 0,1,2', JSON.stringify(cmPairs) === '[0,1,2]', JSON.stringify(cmPairs));

  // ---- part 2: trigger lifecycle through a running n8n ------------------------------------
  const proxy = https.createServer({ key: fs.readFileSync(KEY), cert: fs.readFileSync(CERT) }, (req, res) => {
    const p = http.request({ host: '127.0.0.1', port: N8N_PORT, path: req.url, method: req.method, headers: { ...req.headers, host: `127.0.0.1:${N8N_PORT}` } }, (pr) => { res.writeHead(pr.statusCode, pr.headers); pr.pipe(res); });
    p.on('error', (e) => { res.writeHead(502); res.end(String(e)); });
    req.pipe(p);
  });
  await new Promise((rs) => proxy.listen(HOOK_PORT, '127.0.0.1', rs));
  let n8nLog = '';
  const n8nProc = spawn(process.execPath, [N8N_BIN, 'start'], { env: n8nEnv, stdio: ['ignore', 'pipe', 'pipe'] });
  n8nProc.stdout.on('data', (d) => { n8nLog += d; }); n8nProc.stderr.on('data', (d) => { n8nLog += d; });
  let up = false;
  for (let i = 0; i < 180 && !up; i++) { await sleep(1000); try { const h = await httpJson({ host: '127.0.0.1', port: N8N_PORT, path: '/healthz', method: 'GET' }); up = h.code === 200; } catch (_) {} }
  check('n8n start: healthy', up, up ? '' : n8nLog.slice(-1500));

  // activation registers the webhook with the app
  const pldb = new Database(path.join(PLTEST, 'proofs.db')); pldb.pragma('busy_timeout = 5000');
  let ep = null;
  for (let i = 0; i < 30 && !ep; i++) { await sleep(1000); ep = pldb.prepare(`SELECT id, url, secret, events, is_active FROM webhook_endpoints WHERE user_id = ? AND url LIKE '%hooks.proofledger.test%' ORDER BY id DESC`).get(userId); }
  check('Trigger activation registered a ProofLedger webhook at the n8n URL', ep && ep.url === `https://hooks.proofledger.test:${HOOK_PORT}/webhook/${TRIGGER_WEBHOOK_ID}/webhook` && ep.is_active === 1, ep ? ep.url : n8nLog.slice(-1500));

  // forged signature is refused
  const forged = await httpJson({ protocol: 'https:', host: 'localhost', servername: 'hooks.proofledger.test', port: HOOK_PORT, path: `/webhook/${TRIGGER_WEBHOOK_ID}/webhook`, method: 'POST', rejectUnauthorized: false, headers: { 'ProofLedger-Signature': `t=${Math.floor(Date.now() / 1000)},v1=${'0'.repeat(64)}` } }, { id: 'evt_forged', type: 'proof.polygon.anchored', data: {} });
  check('Forged signature answered 401', forged.code === 401, forged.code + ' ' + (forged.text || JSON.stringify(forged.json)));
  const unsigned = await httpJson({ protocol: 'https:', host: 'localhost', servername: 'hooks.proofledger.test', port: HOOK_PORT, path: `/webhook/${TRIGGER_WEBHOOK_ID}/webhook`, method: 'POST', rejectUnauthorized: false }, { id: 'evt_unsigned', type: 'proof.polygon.anchored', data: {} });
  check('Unsigned delivery answered 401', unsigned.code === 401, unsigned.code);

  // signed test event via the API -> execution
  const H = { Authorization: `Bearer ${rawKey}` };
  const t = await app('POST', `/api/v1/webhooks/${ep.id}/test`, null, H);
  check('Signed webhook.test delivered to n8n (app saw 200)', t.code === 200 && t.json && t.json.ok === true && t.json.status_code === 200, JSON.stringify(t.json || t.text));

  // real anchored-proof event -> execution
  const liveHash = rnd();
  const created = await app('POST', '/api/v1/proof', { sha256: liveHash, filename: 'trigger.txt', external_id: ext + '-trigger' }, H);
  check('Proof created for the trigger test', created.code === 201, created.code);
  const n8ndb = new Database(path.join(HOME, '.n8n', 'database.sqlite'), { readonly: true });
  let execs = [];
  for (let i = 0; i < 90; i++) {
    await sleep(1000);
    execs = n8ndb.prepare(`SELECT e.id, e.status, d.data FROM execution_entity e JOIN execution_data d ON d.executionId = e.id WHERE e.workflowId = ? ORDER BY e.id`).all(WF2);
    if (execs.length >= 2 && execs.some((x) => x.data.includes('proof.polygon.anchored') && x.data.includes(liveHash))) break;
  }
  check('Executions recorded for the trigger workflow: test event + anchored event', execs.length >= 2, execs.map((x) => x.id + ':' + x.status).join(','));
  check('All trigger executions succeeded', execs.length > 0 && execs.every((x) => x.status === 'success'), execs.map((x) => x.status).join(','));
  check('Anchored event carries the proof hash', execs.some((x) => x.data.includes('proof.polygon.anchored') && x.data.includes(liveHash)), '');
  check('Test event started a run (includeTestEvents)', execs.some((x) => x.data.includes('webhook.test')), '');
  let tplExecs = [];
  for (let i = 0; i < 30; i++) {
    tplExecs = n8ndb.prepare(`SELECT e.id, e.status, d.data FROM execution_entity e JOIN execution_data d ON d.executionId = e.id WHERE e.workflowId = ? ORDER BY e.id`).all(WF4);
    if (tplExecs.length >= 1) break;
    await sleep(1000);
  }
  check('template trigger workflow ran once (anchored event only; test event filtered out)', tplExecs.length === 1 && tplExecs[0].status === 'success', tplExecs.map((x) => x.id + ':' + x.status).join(','));
  check('template "Tidy the event" produced the flat item', tplExecs.some((x) => x.data.includes('proof_id') && x.data.includes('certificate_url') && x.data.includes(liveHash)), '');
  check('No delivery failed at the app', (pldb.prepare(`SELECT COUNT(*) c FROM webhook_deliveries dl JOIN webhook_endpoints e ON e.id = dl.endpoint_id WHERE e.id = ? AND dl.status = 'failed'`).get(ep.id) || {}).c === 0, '');

  n8nProc.kill(); proxy.close(); n8ndb.close(); pldb.close();
  appProc.kill(); signer.close();
  const failed = results.filter((x) => !x).length;
  console.log(`\n${results.length - failed}/${results.length} checks passed`);
  if (failed) console.log('--- n8n log tail\n' + n8nLog.slice(-2500) + '\n--- app log tail\n' + appLog.slice(-1500));
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.log('E2E ERROR', e); if (appProc) appProc.kill(); process.exit(1); });
