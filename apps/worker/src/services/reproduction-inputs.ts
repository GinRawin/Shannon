// Operator instructions derived from private invocation structure, never credential values.
import type { CurlArgument } from './curl-invocation.js';
import { type HttpReplayPlan, REPLAY_VARIABLES } from './http-replay.js';

export interface ReproductionInput {
  variable: string;
  label: string;
  source: string;
  format: string;
  example: string;
  header_name?: string;
  file?: boolean;
}

const loginSource =
  '使用该复现步骤要求的账号和权限登录目标系统，在浏览器 F12 → Network（网络）中选择对应请求，查看 Request Headers（请求头）。不同账号或会话的值不要混用。';

function cookieExample(value: string): string {
  const names = value
    .split(';')
    .map((part) => /^\s*([A-Za-z0-9_.-]+)=/.exec(part)?.[1])
    .filter(Boolean);
  return names.length ? [...new Set(names)].map((name) => `${name}=<COOKIE_VALUE>`).join('; ') : '<完整Cookie值>';
}

export function describeArgumentInput(variable: string, arg: CurlArgument): ReproductionInput {
  const value = arg.value ?? '';
  if (arg.option === 'header') {
    const header = /^([A-Za-z0-9!#$%&'*+.^_`|~-]+):\s*(.*)$/s.exec(value);
    if (header) {
      const name = header[1] as string;
      const body = header[2] as string;
      const cookie = name.toLowerCase() === 'cookie';
      const scheme = name.toLowerCase() === 'authorization' ? /^(Bearer|Basic|Digest)\s/i.exec(body)?.[1] : undefined;
      return {
        variable,
        label: `${name} 请求头`,
        source: `${loginSource} 复制 ${name} 的完整值。`,
        format: `完整请求头，必须包含前缀 ${name}:；curl 的 -H/--header 不要填入变量。`,
        example: `${name}: ${cookie ? cookieExample(body) : `${scheme ? `${scheme} ` : ''}<HEADER_VALUE>`}`,
        header_name: name,
      };
    }
  }
  if (arg.option === 'cookie')
    return {
      variable,
      label: 'Cookie 值',
      source: `${loginSource} 复制 Cookie 的完整值。`,
      format: 'cookie名=值；多个 Cookie 用分号分隔，不包含 Cookie: 前缀。',
      example: cookieExample(value),
    };
  if (arg.option === 'oauth2-bearer')
    return {
      variable,
      label: 'Bearer 令牌',
      source: `${loginSource} 从 Authorization: Bearer 后复制当前有效令牌，或按报告步骤取得令牌。`,
      format: '仅令牌本身，不包含 Authorization: 或 Bearer。',
      example: '<ACCESS_TOKEN>',
    };
  if (arg.option === 'user' || arg.option === 'proxy-user')
    return {
      variable,
      label: arg.option === 'user' ? 'HTTP 认证账号与密码' : '代理认证账号与密码',
      source: '从该步骤使用的账号或代理配置取得凭据，具体身份要求见复现步骤。',
      format: '完整 username:password；不要填入 -u/--user 等 curl 选项。',
      example: '<USERNAME>:<PASSWORD>',
    };
  if (arg.option === 'url')
    return {
      variable,
      label: '含认证信息的请求 URL',
      source:
        '按复现步骤重新取得当前有效的链接，或从浏览器 Network 中复制对应请求的 Request URL，并保留复现所需路径和参数。',
      format: '完整 HTTP(S) URL，替换其中过期的认证值。',
      example: 'https://<TARGET_HOST>/<原请求路径>?<原参数名>=<当前有效值>',
    };
  if (
    ['data', 'data-raw', 'data-binary', 'json', 'data-urlencode', 'form', 'form-string', 'stdin'].includes(arg.option)
  )
    return {
      variable,
      label: arg.option === 'stdin' ? '标准输入内容' : '请求体或表单参数',
      source:
        '查看下方复现步骤；在浏览器 Network → Payload（载荷）中复制对应请求内容，按步骤保留测试载荷并替换账号、密码、令牌等当前有效值。',
      format: '完整的原参数内容；JSON 须保留字段名和结构，表单须保留字段名与编码。不是只填写一个密码或令牌。',
      example: '<按复现步骤准备的完整请求内容>',
    };
  return {
    variable,
    label: `curl ${arg.option} 参数`,
    source: '按照下方复现步骤，从当前有效请求或相应配置中取得该参数；查看 Recorded command 确认参数位置。',
    format: '完整参数值，不包含 curl 选项名；不同步骤的参数不要直接混用。',
    example: '<当前有效的完整参数值>',
  };
}

export function describeFileInput(variable: string, filename: string): ReproductionInput {
  return {
    variable,
    label: '本地输入文件路径',
    file: true,
    source: `按复现步骤重新准备对应文件。原始输入文件：${filename}。脚本未内嵌该文件的敏感内容。`,
    format: '本机可读取的文件路径，不是文件内容；例如请求体文件、Cookie jar 或客户端证书。',
    example: '/absolute/path/to/<准备好的输入文件>',
  };
}

export function describeVerificationInputs(plan: HttpReplayPlan): ReproductionInput[] {
  const used = new Set([...JSON.stringify(plan).matchAll(/\$\{([A-Z][A-Z0-9_]*)\}/g)].map((match) => match[1]));
  const descriptions: Record<string, Omit<ReproductionInput, 'variable'>> = {
    COOKIE: {
      label: '影响验证使用的 Cookie 值',
      source: `${loginSource} 复制 Cookie 的完整值。`,
      format: '仅 cookie名=值，多个 Cookie 用分号分隔，不包含 Cookie: 前缀。',
      example: '<完整Cookie值>',
    },
    BEARER_TOKEN: {
      label: '影响验证使用的 Bearer 令牌',
      source: `${loginSource} 从 Authorization: Bearer 后复制令牌，或按步骤取得令牌。`,
      format: '仅令牌本身，不包含 Authorization: 或 Bearer。',
      example: '<ACCESS_TOKEN>',
    },
    USERNAME: {
      label: '登录账号',
      source: '使用复现步骤指定身份的测试账号。',
      format: '完整用户名。',
      example: '<USERNAME>',
    },
    PASSWORD: {
      label: '登录密码',
      source: '使用上述测试账号的当前有效密码。',
      format: '原始密码，保留特殊字符。',
      example: '<PASSWORD>',
    },
    OTP: {
      label: '一次性验证码',
      source: '从测试账号的认证器、短信或邮件中获取当前验证码，具体方式见步骤。',
      format: '当前验证码，不是 TOTP 秘钥；过期后需重新获取。',
      example: '<CURRENT_OTP>',
    },
  };
  // BASE_URL has a default; extracted flow variables are supplied by the plan itself.
  return REPLAY_VARIABLES.filter((name) => name !== 'BASE_URL' && used.has(name)).map((variable) => ({
    variable,
    ...descriptions[variable],
  })) as ReproductionInput[];
}
