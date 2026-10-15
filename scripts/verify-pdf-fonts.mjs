// Run after the worker build, with Typst on PATH (or inside the worker image).
// This compiles actual PDFs without network access; text extraction alone would
// miss the original defect because missing glyphs still had correct Unicode.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdtemp, readFile, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { renderReportPdf, readPdfProvenance, pdfProvenanceIsCurrent } from '../apps/worker/dist/services/pdf-renderer.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const dir = await mkdtemp('/tmp/shannon-pdf-font-check-');
const templatePath = path.join(dir, 'template/report.typ');
await cp(path.join(root, 'apps/worker/templates/typst'), path.dirname(templatePath), { recursive: true });
const chinese = '中文安全报告：浏览器验证、请求响应与人工复验';
const reportData = {
  report_meta: { target: 'https://example.invalid/', assessment_date: '2026-10-15', scope: chinese, executive_summary: chinese },
  findings: [{
    finding_id: 'XSS-01', title: chinese, category: 'XSS', severity: 'high',
    owasp_category: 'A03:2021', auth_state: '无需认证', prerequisites: '打开浏览器',
    vulnerable_location: '/中文路径', overview: chinese, impact: chinese, remediation: '修复输入校验',
    verification_method: 'browser', http_evidence_display: 'omit',
    exploitation_steps: [{ items: [{ kind: 'prose', text: chinese }, { kind: 'code', block: { language: 'text', content: '中文代码和响应：验证成功' } }] }],
    additional_sections: [{ heading: '浏览器验证证据', items: [{ kind: 'prose', text: chinese }] }],
  }],
};
const outputPath = path.join(dir, 'report.pdf');
await renderReportPdf({ reportData, templatePath, outputPath });
const pdf = (await readFile(outputPath)).toString('latin1');
// Check the embedded font identities, including bold titles and raw code blocks.
for (const font of ['NotoSansCJKsc-Regular', 'NotoSansCJKsc-Bold', 'NotoSansMonoCJKsc-Regular']) {
  assert.ok(pdf.includes(font), `Missing embedded Chinese face: ${font}`);
}
console.log('PASS Chinese regular, bold, and monospace fonts embedded in actual PDF');
const canonicalReportSha256 = createHash('sha256').update(JSON.stringify(reportData)).digest('hex');
const provenance = await readPdfProvenance({ pdfPath: outputPath, canonicalReportSha256, templatePath });
const current = () => pdfProvenanceIsCurrent({ pdfPath: outputPath, canonicalReportSha256, templatePath, provenance });
assert.equal(await current(), true);
const fontPath = path.join(path.dirname(templatePath), 'assets/fonts/NotoSansCJK-Regular.ttc');
const font = await readFile(fontPath);
await writeFile(fontPath, Buffer.concat([font, Buffer.from('\0')]));
assert.equal(await current(), false);
await writeFile(fontPath, font);
console.log('PASS font changes invalidate PDF reuse');

await unlink(fontPath);
const missingOutput = path.join(dir, 'missing-font.pdf');
await assert.rejects(renderReportPdf({ reportData, templatePath, outputPath: missingOutput }), /Required PDF font is missing/);
await assert.rejects(readFile(missingOutput), { code: 'ENOENT' });
assert.equal(await current(), false);
console.log('PASS missing fonts prevent publication even when system fonts are available');
await writeFile(fontPath, font);

// Typst exits successfully on an unknown font family. Do not publish that PDF.
await writeFile(templatePath, (await readFile(templatePath, 'utf8')).replaceAll('Noto Sans CJK SC', 'Missing CJK Fixture'));
await assert.rejects(renderReportPdf({ reportData, templatePath, outputPath: missingOutput }), /PDF font configuration is invalid/);
await assert.rejects(readFile(missingOutput), { code: 'ENOENT' });
console.log('PASS unknown-font warnings prevent publication');

// Ensure the regression check itself is not relying on a host font installation.
const { stdout } = await promisify(execFile)('typst', ['fonts', '--ignore-system-fonts']);
assert.ok(!stdout.includes('Noto Sans CJK SC'));
console.log(`PASS isolated font check complete: ${outputPath}`);
