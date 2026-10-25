import { test } from 'node:test';
import assert from 'node:assert/strict';

// Required lazily, like schedule.test.ts, so the Nest decorators load only here.
const { sharedSpecTemplates } = require('../src/audit/audit.service');

test('shared spec template: banks with identical operations are named, unique specs say so, info only', () => {
  const a = ['GET /v2/accounts', 'POST /v2/consents'];
  const specOps = new Map<string, string[]>([
    ['silk-sandbox', a],
    ['cartu-sandbox', [...a]],
    ['pasha-spec', [...a]],
    ['bog-sandbox', ['GET /0.8/v1/accounts']],
  ]);
  const targets = [
    { id: 'silk-sandbox', name: 'Silk Bank (sandbox)', bank: 'Silk Bank' },
    { id: 'cartu-sandbox', name: 'Cartu Bank (sandbox)', bank: 'Cartu Bank' },
    { id: 'pasha-spec', name: 'PASHA (spec)', bank: 'PASHA Bank Georgia' },
    { id: 'bog-sandbox', name: 'BoG (sandbox)', bank: 'Bank of Georgia' },
  ];
  const f = sharedSpecTemplates(specOps, targets);
  assert.equal(f.length, 4);
  assert.ok(f.every((x: any) => x.status === 'info' && x.severity === 'none' && x.checkId === 'spec.shared-template'));
  const silk = f.find((x: any) => x.targetId === 'silk-sandbox');
  assert.deepEqual(silk.evidence.sharedWith, ['cartu-sandbox', 'pasha-spec']);
  assert.match(silk.message, /Cartu Bank, PASHA Bank Georgia/);
  assert.match(f.find((x: any) => x.targetId === 'bog-sandbox').message, /No other audited bank/);
});

test('shared spec template: two targets of the same bank do not count as sharing', () => {
  const ops = ['GET /v1/accounts'];
  const f = sharedSpecTemplates(new Map([['tbc-mock', ops], ['tbc-test', [...ops]]]), [
    { id: 'tbc-mock', name: 'TBC mock', bank: 'TBC Bank' },
    { id: 'tbc-test', name: 'TBC test', bank: 'TBC Bank' },
  ]);
  assert.ok(f.every((x: any) => x.evidence.sharedWith.length === 0));
});
