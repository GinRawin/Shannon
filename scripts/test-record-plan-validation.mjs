/**
 * Offline regression for Record/HTTP plan validation parity.
 *
 * Run `pnpm --filter @shannon/worker build` first, then:
 *   node scripts/test-record-plan-validation.mjs
 *
 * Covers the 2026-11-25 batch losses documented in diagnosis/record_stage_analysis.md:
 *   A) save_json / save_headers variable names must match the runner rule (uppercase, not reserved).
 *   B) large integer literals in body_json must be rejected (JSON/JS cannot represent them exactly).
 *   C) characterises the over-broad secret matcher so a future policy fix flips the expectation.
 */
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const load = (name) => import(pathToFileURL(path.join(root, 'apps/worker/dist', `${name}.js`)));
const {
  replayPlanError,
  containsReplaySecret,
  hasLiteralReplayAuthentication,
  credentialReplayVariableValues,
} = await load('services/http-replay');
const { credentialCaptureRedactions } = await load('services/http-evidence');
const { browserReplayPlanError } = await load('services/browser-replay');
const { createExploitReviewCollector } = await load('collectors/exploit-review-collector');

let passed = 0;
const ok = (label, condition, detail) => {
  assert.ok(condition, detail ? `${label}: ${detail}` : label);
  passed += 1;
  console.log(`  ok  ${label}`);
};

const baseStep = (extra) => ({ method: 'POST', url: '${BASE_URL}/api/thing', expect: { status: 200, body_contains: 'ok' }, ...extra });
const plan = (step) => ({ steps: [step] });

// --- A) save variable naming -------------------------------------------------------------
const lowerSaveJson = replayPlanError(plan(baseStep({ save_json: { created_media_id: 'data.mediaId' } })));
ok('A: lowercase save_json key is rejected', typeof lowerSaveJson === 'string' && /save_json/.test(lowerSaveJson), lowerSaveJson);
const lowerSaveHeaders = replayPlanError(plan(baseStep({ save_headers: { acao: 'Access-Control-Allow-Origin' } })));
ok('A: lowercase save_headers key is rejected', typeof lowerSaveHeaders === 'string' && /save_headers/.test(lowerSaveHeaders), lowerSaveHeaders);
const reserved = replayPlanError(plan(baseStep({ save_json: { COOKIE: 'data.cookie' } })));
ok('A: reserved operator variable name is rejected', typeof reserved === 'string' && /COOKIE/.test(reserved), reserved);
const upperOk = replayPlanError(plan(baseStep({ save_json: { CREATED_MEDIA_ID: 'data.mediaId' } })));
ok('A: uppercase save_json key passes', upperOk === undefined, upperOk);
const badInSetup = replayPlanError({ setup: [baseStep({ save_json: { tok: 'data.token' } })], steps: [baseStep({})] });
ok('A: lowercase key in setup is rejected', typeof badInSetup === 'string', badInSetup);

// --- B) large integer literals -----------------------------------------------------------
const bigId = Number('1774725156766629890');
ok('B: fixture id is not a safe integer', Number.isSafeInteger(bigId) === false);
const bigIntPlan = replayPlanError(plan(baseStep({ body_json: { copyWritingId: bigId } })));
ok('B: unsafe integer in body_json is rejected', typeof bigIntPlan === 'string' && /cannot represent exactly/.test(bigIntPlan), bigIntPlan);
const nestedBig = replayPlanError(plan(baseStep({ body_json: { items: [{ copyWritingId: bigId }] } })));
ok('B: unsafe integer nested in body_json is rejected', typeof nestedBig === 'string', nestedBig);
const stringIdOk = replayPlanError(plan(baseStep({ body_json: { copyWritingId: '1774725156766629890' } })));
ok('B: large id quoted as a string passes', stringIdOk === undefined, stringIdOk);
const safeIntOk = replayPlanError(plan(baseStep({ body_json: { count: 9 } })));
ok('B: small integer passes', safeIntOk === undefined, safeIntOk);

// --- C) identity values are not credential secrets (report is internal; owner decision) ----
const operatorId = 'cqpv8a';
const token = 'eyJhbGciOiJIUzUxMiJ9.IAM-token-value';
const redactions = [
  { value: operatorId, placeholder: '$username' },
  { value: token, placeholder: '$password' },
];
const credentialRedactions = credentialCaptureRedactions(redactions).map((item) => item.value);
ok(
  'C: username/email redactions are no longer plan-rejecting secrets',
  !credentialRedactions.includes(operatorId) && credentialRedactions.includes(token),
  JSON.stringify(credentialRedactions),
);
ok(
  'C: identity replay variable values are dropped while credential values are kept',
  JSON.stringify(
    credentialReplayVariableValues({ VICTIM_ACCOUNT_NO: operatorId, TOKEN: token, BASE_URL: 'https://x' }, 'https://x'),
  ) === JSON.stringify([token]),
);
const assertionPlan = plan({ method: 'GET', url: '${BASE_URL}/api/statistics', expect: { status: 200, body_contains: `"createdUser":"${operatorId}"` } });
ok('C: literal lives only in expect (not a credential header)', hasLiteralReplayAuthentication(assertionPlan) === false);
ok(
  'C: an identity literal in an assertion passes once secrets are credential-only',
  containsReplaySecret(assertionPlan, credentialReplayVariableValues({ VICTIM_ACCOUNT_NO: operatorId }, 'https://x').concat(credentialRedactions)) === false,
);
const tokenPlan = plan({ method: 'GET', url: '${BASE_URL}/x', headers: { Authorization: `Bearer ${token}` }, expect: { status: 200, body_contains: 'ok' } });
ok('C: a literal credential value is still rejected', containsReplaySecret(tokenPlan, credentialRedactions) === true);

// --- D) an explicit DOM assertion is an accepted browser receipt path --------------------
const payload = '${BASE_URL}/page?q=%3Cimg%20src%3Dx%20onerror%3Dalert(%22${XSS_MARKER}%22)%3E';
const domPlan = {
  steps: [
    { action: 'goto', url: payload },
    { action: 'assert_text', selector: 'body', value: '${XSS_MARKER}' },
  ],
};
ok('D: an assert_text DOM plan is accepted', browserReplayPlanError(domPlan) === undefined, browserReplayPlanError(domPlan));
ok(
  'D: assert_text must assert exactly ${XSS_MARKER}',
  typeof browserReplayPlanError({ steps: [domPlan.steps[0], { action: 'assert_text', selector: 'body', value: 'other' }] }) ===
    'string',
);

// --- D) exploit-review collector surfaces the same rule to the review agent ---------------
const collector = createExploitReviewCollector(new Set(['AUTH-01']));
const [tool] = collector.tools;
const reviewResult = await tool.execute('id', {
  finding_id: 'AUTH-01',
  verdict: 'retry',
  reason: 'retry with corrected plan',
  revised_http_replay: plan(baseStep({ save_json: { tok: 'data.token' } })),
  variable_requirements: {},
  record_instructions: ['run verify_http_replay'],
  expected_evidence: { marker: 'x' },
});
const reviewText = JSON.stringify(reviewResult.content);
ok('D: exploit-review rejects a revised plan with a lowercase save key', /save_json/.test(reviewText), reviewText);
ok('D: rejected review is not stored', collector.getAll().length === 0);

console.log(`\nall ${passed} checks passed`);
