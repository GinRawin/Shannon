// Copyright (C) 2026 Keygraph, Inc.
// curl application-level trace decoding. The original trace remains the byte source of truth.

export interface HttpTracePart {
  direction: 'request' | 'response';
  kind: 'header' | 'data';
  byte_length: number;
  base64: string;
}

export interface HttpExchange {
  request: string;
  response: string;
  request_base64: string;
  response_base64: string;
}

export interface ParsedHttpTrace {
  parts: HttpTracePart[];
  exchanges: HttpExchange[];
  errors: string[];
}

/** Decode only the fixed hex column, using the marker's byte count rather than ASCII text. */
export function parseCurlTrace(trace: string): ParsedHttpTrace {
  const parts: HttpTracePart[] = [];
  const errors: string[] = [];
  let current:
    | { direction: 'request' | 'response'; kind: 'header' | 'data'; expected: number; bytes: number[] }
    | undefined;
  const flush = () => {
    if (!current) return;
    if (current.bytes.length !== current.expected)
      errors.push(`Expected ${current.expected} bytes, decoded ${current.bytes.length}`);
    parts.push({
      direction: current.direction,
      kind: current.kind,
      byte_length: current.bytes.length,
      base64: Buffer.from(current.bytes).toString('base64'),
    });
    current = undefined;
  };
  for (const line of trace.split(/\r?\n/)) {
    const marker = /^(=>|<=) (?:Send|Recv) (header|data|SSL data|SSL handshake data), (\d+) bytes/.exec(line);
    if (marker) {
      flush();
      if (marker[2] === 'header' || marker[2] === 'data') {
        current = {
          direction: marker[1] === '=>' ? 'request' : 'response',
          kind: marker[2],
          expected: Number(marker[3]),
          bytes: [],
        };
      }
      continue;
    }
    if (!current || line.startsWith('==')) continue;
    const row = /^([0-9a-f]{4,}): /.exec(line);
    if (!row) continue;
    const offset = Number.parseInt(row[1] as string, 16);
    if (offset !== current.bytes.length) {
      errors.push(`Unexpected trace offset ${offset}`);
      continue;
    }
    const count = Math.min(16, current.expected - current.bytes.length);
    for (let index = 0; index < count; index++) {
      const hex = line.slice(row[0].length + index * 3, row[0].length + index * 3 + 2);
      if (!/^[0-9a-f]{2}$/i.test(hex)) {
        errors.push('Invalid trace hex column');
        break;
      }
      current.bytes.push(Number.parseInt(hex, 16));
    }
  }
  flush();

  const exchanges: HttpExchange[] = [];
  let request: Buffer[] = [];
  let response: Buffer[] = [];
  const finish = () => {
    if (request.length === 0 && response.length === 0) return;
    const req = Buffer.concat(request),
      res = Buffer.concat(response);
    const display = (bytes: Buffer) => {
      const decoded = bytes.toString('utf8');
      return Buffer.from(decoded).equals(bytes) && !decoded.includes('\0')
        ? decoded
        : `[Binary HTTP content: ${bytes.length} bytes; base64]\n${bytes.toString('base64')}`;
    };
    exchanges.push({
      request: display(req),
      response: display(res),
      request_base64: req.toString('base64'),
      response_base64: res.toString('base64'),
    });
    request = [];
    response = [];
  };
  for (const part of parts) {
    // A new outgoing header after a response starts a redirect/authentication/proxy exchange.
    if (part.direction === 'request' && part.kind === 'header' && response.length > 0) finish();
    (part.direction === 'request' ? request : response).push(Buffer.from(part.base64, 'base64'));
  }
  finish();
  return { parts, exchanges, errors };
}
