// Copyright (C) 2026 Keygraph, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import type { AddFindingInput, AdditionalSection, StepItem } from '../collectors/finding-collector.js';

/** Project the exploit agent's evidence choice; never infer it from available files. */
export function projectFindingEvidence(finding: AddFindingInput): {
  capturedHttpEvidence?: AdditionalSection;
  verificationEvidence?: AdditionalSection;
  additionalSections: readonly AdditionalSection[];
} {
  const sections = finding.additional_sections ?? [];
  const captures = sections.filter((section) => section.heading === '捕获的 HTTP 请求与响应');
  const proofs = sections.filter((section) =>
    /^(?:浏览器验证证据|验证证据|Proof of Impact)$/i.test(section.heading.trim()),
  );
  const legacy = (finding as AddFindingInput & { proof_of_impact?: StepItem[] | string }).proof_of_impact;
  const verificationEvidence = proofs.length
    ? {
        heading:
          finding.verification_method === 'browser' || finding.verification_method === 'mixed'
            ? '浏览器验证证据'
            : '验证证据',
        items: proofs.flatMap((section) => section.items),
      }
    : legacy && finding.http_evidence_display !== 'include'
      ? { heading: '验证证据', items: typeof legacy === 'string' ? [{ kind: 'prose' as const, text: legacy }] : legacy }
      : undefined;
  return {
    ...(finding.http_evidence_display === 'include' && captures.length
      ? {
          capturedHttpEvidence: {
            heading: '捕获的 HTTP 请求与响应',
            items: captures.flatMap((section) => section.items),
          },
        }
      : {}),
    ...(verificationEvidence ? { verificationEvidence } : {}),
    additionalSections: sections.filter(
      (section) =>
        !/^(?:捕获的 HTTP 请求与响应|Proof of Impact|浏览器验证证据|验证证据)$/i.test(section.heading.trim()),
    ),
  };
}
