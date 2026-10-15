// Copyright (C) 2026 Keygraph, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import type { AddFindingInput, AdditionalSection } from '../collectors/finding-collector.js';

/** Display only captured HTTP evidence; explicitly disclose missing captures. */
export function projectFindingEvidence(finding: AddFindingInput): {
  capturedHttpEvidence: AdditionalSection;
  additionalSections: readonly AdditionalSection[];
} {
  const sections = finding.additional_sections ?? [];
  const captures = sections.filter((section) => section.heading === '捕获的 HTTP 请求与响应');
  const capturedHttpEvidence = captures.length
    ? { heading: '捕获的 HTTP 请求与响应', items: captures.flatMap((section) => section.items) }
    : {
        heading: '捕获的 HTTP 请求与响应',
        items: [{ kind: 'prose' as const, text: '此漏洞没有已关联的 HTTP 请求与响应捕获记录。' }],
      };
  return {
    capturedHttpEvidence,
    additionalSections: sections.filter(
      (section) => !/^(?:捕获的 HTTP 请求与响应|Proof of Impact|验证证据)$/i.test(section.heading.trim()),
    ),
  };
}
