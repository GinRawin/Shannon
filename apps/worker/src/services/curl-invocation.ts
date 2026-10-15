// Preserve the executed argv privately and package its inputs for manual reproduction.
import { readFile } from 'node:fs/promises';
import path from 'node:path';

export interface InvocationInput {
  path: string;
  base64?: string;
  variable?: string;
}

export interface CurlInvocation {
  argv: string[];
  cwd: string;
  timeout_seconds: number;
  inputs: InvocationInput[];
  /** Indices containing authentication or configured credentials. Values stay in private argv. */
  variables: Record<string, string>;
  manual_reasons: string[];
  /** Private values used to redact narrative when exporting a reproduction script. */
  secret_values: string[];
  stdin_base64?: string;
  stdin_variable?: string;
}

export interface CurlArgument {
  option: string;
  index: number;
  value?: string;
  prefix: string;
}

const longValues = new Set([
  'data',
  'data-binary',
  'data-raw',
  'data-urlencode',
  'json',
  'form',
  'form-string',
  'header',
  'cookie',
  'cookie-jar',
  'user-agent',
  'referer',
  'user',
  'proxy',
  'proxy-user',
  'request',
  'output',
  'dump-header',
  'write-out',
  'url',
  'upload-file',
  'max-time',
  'connect-timeout',
  'cacert',
  'cert',
  'key',
  'resolve',
  'connect-to',
  'request-target',
  'url-query',
  'oauth2-bearer',
  'aws-sigv4',
  'range',
  'max-redirs',
  'trace',
]);
const shortValues: Record<string, string> = {
  A: 'user-agent',
  b: 'cookie',
  c: 'cookie-jar',
  d: 'data',
  e: 'referer',
  E: 'cert',
  F: 'form',
  H: 'header',
  m: 'max-time',
  o: 'output',
  D: 'dump-header',
  x: 'proxy',
  U: 'proxy-user',
  X: 'request',
  u: 'user',
  T: 'upload-file',
  w: 'write-out',
  r: 'range',
  t: 'telnet-option',
  z: 'time-cond',
  Y: 'speed-limit',
  y: 'speed-time',
  C: 'continue-at',
  P: 'ftp-port',
  Q: 'quote',
};
const simpleFlags = new Set([
  'silent',
  'show-error',
  'insecure',
  'location',
  'location-trusted',
  'head',
  'get',
  'compressed',
  'globoff',
  'path-as-is',
  'http1.0',
  'http1.1',
  'http2',
  'http2-prior-knowledge',
  'ipv4',
  'ipv6',
  'include',
  'fail',
  'fail-with-body',
  'no-keepalive',
  'no-buffer',
  'verbose',
  'basic',
  'digest',
  'ntlm',
  'anyauth',
  'disable',
  'tcp-nodelay',
  'no-progress-meter',
]);
const simpleShort = new Set('sSkLgGIivfNq046'.split(''));

/** Conservative parsing: an unfamiliar option is captured, but cannot become an executable recipe. */
export function curlArguments(argv: readonly string[]): { arguments: CurlArgument[]; unsupported: string[] } {
  const args: CurlArgument[] = [],
    unsupported: string[] = [];
  for (let index = 0; index < argv.length; index++) {
    const token = argv[index] as string;
    if (token.startsWith('--')) {
      const equal = token.indexOf('=');
      const option = token.slice(2, equal < 0 ? undefined : equal);
      if (longValues.has(option)) {
        if (equal >= 0)
          args.push({ option, index, value: token.slice(equal + 1), prefix: `${token.slice(0, equal + 1)}` });
        else {
          index++;
          args.push({ option, index, value: argv[index] ?? '', prefix: '' });
        }
      } else if (!simpleFlags.has(option)) unsupported.push(token);
    } else if (token.startsWith('-')) {
      for (let offset = 1; offset < token.length; offset++) {
        const flag = token[offset] as string,
          option = shortValues[flag];
        if (option) {
          if (offset + 1 < token.length)
            args.push({ option, index, value: token.slice(offset + 1), prefix: token.slice(0, offset + 1) });
          else {
            index++;
            args.push({ option, index, value: argv[index] ?? '', prefix: '' });
          }
          break;
        }
        if (!simpleShort.has(flag)) unsupported.push(`-${flag}`);
      }
    } else args.push({ option: 'url', index, value: token, prefix: '' });
  }
  return { arguments: args, unsupported };
}

export async function snapshotCurlInvocation(
  argv: readonly string[],
  cwd: string,
  timeoutSeconds: number,
  secrets: readonly string[] = [],
  stdin?: Buffer,
): Promise<CurlInvocation> {
  const parsed = curlArguments(argv);
  const invocation: CurlInvocation = {
    argv: [...argv],
    cwd: path.resolve(cwd),
    timeout_seconds: timeoutSeconds,
    inputs: [],
    variables: {},
    manual_reasons: parsed.unsupported.map((option) => `Unsupported dependency semantics for curl option ${option}`),
    secret_values: [...secrets],
  };
  if (stdin) {
    if (
      secrets.some((secret) => secret && stdin.includes(Buffer.from(secret))) ||
      /"(?:password|token|secret|username)"\s*:/i.test(stdin.toString('utf8'))
    )
      invocation.stdin_variable = 'REQUEST_STDIN';
    else invocation.stdin_base64 = stdin.toString('base64');
  }
  let variableNumber = 0;
  const variable = (index: number, name: string) => {
    invocation.variables[index] = `${name}_${++variableNumber}`;
  };
  const containsSecret = (value: string) =>
    secrets.some(
      (secret) =>
        secret &&
        [secret, encodeURIComponent(secret), JSON.stringify(secret).slice(1, -1)].some((variant) =>
          value.includes(variant),
        ),
    );
  const input = async (filename: string, sensitive: boolean) => {
    if (filename === '-') {
      if (!stdin) invocation.manual_reasons.push('stdin input was not captured; provide the original input manually.');
      return;
    }
    const absolute = path.resolve(cwd, filename);
    if (invocation.inputs.some((item) => item.path === absolute)) return;
    try {
      const bytes = await readFile(absolute);
      if (bytes.length > 16 * 1024 * 1024) throw new Error('input exceeds 16 MiB snapshot limit');
      invocation.inputs.push(
        sensitive ||
          containsSecret(bytes.toString('utf8')) ||
          /["&]?(?:password|passwd|token|access_token|secret|username|otp)["\s]*[:=]/i.test(bytes.toString('utf8'))
          ? { path: absolute, variable: `INPUT_FILE_${++variableNumber}` }
          : { path: absolute, base64: bytes.toString('base64') },
      );
    } catch (error) {
      invocation.manual_reasons.push(`Cannot snapshot input ${filename}: ${(error as Error).message}`);
    }
  };
  for (const arg of parsed.arguments) {
    const value = arg.value ?? '';
    // Keep authentication values private even when they appear again in manual observations.
    if (['data', 'data-raw', 'data-binary', 'json', 'form', 'form-string', 'data-urlencode'].includes(arg.option)) {
      try {
        const visit = (item: unknown): void => {
          if (Array.isArray(item)) item.forEach(visit);
          else if (item && typeof item === 'object')
            for (const [key, child] of Object.entries(item)) {
              if (/password|token|secret|username|session|otp/i.test(key) && typeof child === 'string')
                invocation.secret_values.push(child);
              else visit(child);
            }
        };
        visit(JSON.parse(value));
      } catch {
        for (const [key, item] of new URLSearchParams(value))
          if (/password|token|secret|username|session|otp/i.test(key)) invocation.secret_values.push(item);
      }
    }
    if (['header'].includes(arg.option)) {
      if (value.startsWith('@')) await input(value.slice(1), true);
      else if (
        /^[^:]*?(?:authorization|cookie|token|session|secret|api.?key)[^:]*:/i.test(value) ||
        containsSecret(value)
      )
        variable(arg.index, 'HEADER');
    } else if (['user', 'proxy-user', 'oauth2-bearer'].includes(arg.option)) variable(arg.index, 'AUTH');
    else if (arg.option === 'cookie') {
      if (value.includes('=')) variable(arg.index, 'COOKIE');
      else await input(value.replace(/^@/, ''), true);
    } else if (['cacert', 'cert', 'key', 'upload-file'].includes(arg.option)) {
      if (arg.option === 'cert' && value.includes(':'))
        invocation.manual_reasons.push('Client certificate password/path requires manual preparation.');
      else await input(value, ['cert', 'key'].includes(arg.option));
    } else if (['data', 'data-binary', 'data-urlencode', 'json'].includes(arg.option)) {
      const match = arg.option === 'data-urlencode' ? /^(?:[^=@]*?)?@(.*)$/.exec(value) : /^@(.*)$/.exec(value);
      if (match) await input(match[1] as string, false);
      else if (
        containsSecret(value) ||
        /["&]?(?:password|passwd|token|access_token|refresh_token|secret|otp|username)["\s]*[:=]/i.test(value)
      )
        variable(arg.index, 'REQUEST_BODY');
    } else if (arg.option === 'data-raw' || arg.option === 'form-string') {
      if (containsSecret(value) || /(?:password|token|secret|username)\s*=/i.test(value))
        variable(arg.index, 'REQUEST_BODY');
    } else if (arg.option === 'form') {
      if (/[=][@<]/.test(value)) {
        const match = /^[^=]+=([@<])([^;]+)(.*)$/.exec(value);
        if (!match || (match[2] as string).includes(',') || /["\\]/.test(match[2] as string))
          invocation.manual_reasons.push('Complex multipart file lists or quoted paths require manual preparation.');
        else await input(match[2] as string, false);
      } else if (containsSecret(value) || /(?:password|token|secret|username)\s*=/i.test(value))
        variable(arg.index, 'FORM');
    } else if (arg.option === 'url') {
      try {
        const url = new URL(value);
        if (!['http:', 'https:'].includes(url.protocol))
          invocation.manual_reasons.push('Only HTTP(S) invocations can be replayed.');
        if (
          url.username ||
          url.password ||
          containsSecret(url.search) ||
          [...url.searchParams.keys()].some((key) => /token|password|secret|api.?key|session|otp/i.test(key))
        )
          variable(arg.index, 'REQUEST_URL');
      } catch {
        invocation.manual_reasons.push('URL requires manual preparation.');
      }
    } else if (['referer', 'proxy', 'url-query', 'request-target', 'aws-sigv4'].includes(arg.option)) {
      let sensitive =
        containsSecret(value) || /(?:^|[?&])(?:password|token|access_token|secret|api.?key|session|otp)=/i.test(value);
      if (arg.option === 'proxy' && /^[^/]*@/.test(value)) sensitive = true;
      try {
        const url = new URL(value);
        if (url.username || url.password) sensitive = true;
      } catch {
        /* Non-URL option values are handled above. */
      }
      if (sensitive) variable(arg.index, 'ARGUMENT');
    }
    if (['write-out'].includes(arg.option) && value.startsWith('@')) await input(value.slice(1), false);
  }
  return invocation;
}
