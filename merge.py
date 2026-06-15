#!/usr/bin/env python3
"""聚合多个 Surge/Shadowrocket .sgmodule 去广告模块为单个模块，带安全校验。

流程：
1. 拉取 sources.txt 中所有上游模块。
2. 解析段落（[Rule]/[URL Rewrite]/[Map Local]/[Body Rewrite]/[Script]/[Host]/[MITM] 等）。
3. 抽取所有 script-path（远程脚本）并拉取其内容。
4. 安全校验（见 security_audit）：MITM 危险通配/敏感域、脚本源域名白名单、脚本外发特征、与基线对比。
5. 若发现高危风险 -> 写 security-report.txt 并 exit 2（不生成/不覆盖产物，保留上一版良品）。
6. 否则 -> 写 dist/merged.sgmodule + dist/manifest.json，并刷新 baseline.json，exit 0。

退出码：0 安全通过；1 运行错误（全部源失败等）；2 检测到供应链/安全风险（停更）。
"""
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from collections import OrderedDict

ROOT = os.path.dirname(os.path.abspath(__file__))
SOURCES_FILE = os.path.join(ROOT, "sources.txt")
OUTPUT = os.path.join(ROOT, "dist", "merged.sgmodule")
MANIFEST = os.path.join(ROOT, "dist", "manifest.json")
BASELINE = os.path.join(ROOT, "baseline.json")
REPORT = os.path.join(ROOT, "security-report.txt")

PREFERRED_ORDER = ["Rule", "URL Rewrite", "Map Local", "Body Rewrite", "Host", "Script"]
HEADER_NAME = "聚合去广告"

# ── 安全策略 ───────────────────────────────────────────────────────────────

# 允许托管远程脚本(script-path)的域名。新域名出现即视为供应链风险并停更。
ALLOWED_SCRIPT_HOSTS = {
    "raw.githubusercontent.com",  # fmz200 / kokoryh 等 GitHub 源
    "github.com",
    "klraw.pages.dev",            # 闲鱼脚本第三方源（已知、内容仍逐次扫描）
}

# MITM 命中这些关键词(银行/支付/账号体系)即停更——绝不该解密这些域名。
MITM_SENSITIVE = [
    "alipay", "alipayobjects", "mypay", "tenpay", "wechatpay", "unionpay", "95516",
    "icbc", "ccb.com", "abchina", "boc.cn", "bankcomm", "cmbchina", "psbc", "cebbank",
    "spdb", "citicbank", "pingan", "10086.cn",  # 运营商账单等
    "icloud", "apple.com", "accounts.google", "paypal", "stripe",
]

# 脚本内容外发/投毒高危特征（命中即停更）。
SCRIPT_DANGER = [
    r"api\.telegram\.org",                       # TG bot 外发
    r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b",          # TG bot token
    r"discord(?:app)?\.com/api/webhooks",        # discord webhook
    r"hooks\.slack\.com",                         # slack webhook
    r"eval\s*\(\s*atob\s*\(",                     # 混淆执行
    r"Function\s*\(\s*atob\s*\(",
    r"new\s+Function\s*\(\s*['\"]return",         # 动态构造
    r"pastebin\.com/raw",
    r"webhook\.site",
    r"\beval\s*\(\s*unescape\s*\(",
]


def fetch(url, retries=3, binary=False):
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read()
                return data if binary else data.decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(2 * (i + 1))
    raise RuntimeError(f"fetch failed after {retries}: {last}")


def sha256(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def parse_sections(text):
    sections = OrderedDict()
    cur = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^\[(.+?)\]\s*$", line)
        if m:
            cur = m.group(1).strip()
            sections.setdefault(cur, [])
            continue
        if cur is not None:
            sections[cur].append(line)
    return sections


def extract_script_paths(script_lines):
    paths = []
    for ln in script_lines:
        m = re.search(r"script-path\s*=\s*([^,\s]+)", ln)
        if m:
            paths.append(m.group(1).strip())
    return paths


def host_of(url):
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:  # noqa: BLE001
        return ""


def mitm_hosts_from(lines):
    out = []
    for ln in lines:
        if "hostname" not in ln.lower():
            continue
        rhs = ln.split("=", 1)[1] if "=" in ln else ""
        rhs = rhs.replace("%APPEND%", "")
        for h in rhs.split(","):
            h = h.strip()
            if h:
                out.append(h)
    return out


def is_dangerous_wildcard(host):
    """限定域通配(*.amap.com / m*.amap.com)安全；全 TLD 通配(* / *.com)危险。"""
    if host == "*":
        return True
    if re.fullmatch(r"\*\.\w+", host):   # *.com / *.cn 这类，星号后只剩一段
        return True
    return False


def security_audit(mitm_hosts, scripts):
    """返回 (risks:list[str], notes:list[str])。risks 非空即停更。"""
    risks, notes = [], []

    # 1. MITM 危险通配
    for h in mitm_hosts:
        if is_dangerous_wildcard(h):
            risks.append(f"[MITM] 危险通配域名: {h!r}（会解密过大范围流量）")

    # 2. MITM 敏感域
    for h in mitm_hosts:
        low = h.lower()
        for kw in MITM_SENSITIVE:
            if kw in low:
                risks.append(f"[MITM] 命中敏感域(银行/支付/账号): {h!r} ~ '{kw}'")
                break

    # 3 & 4. 脚本源白名单 + 内容外发特征
    for sp in scripts:
        url = sp["url"]
        host = sp["host"]
        if host not in ALLOWED_SCRIPT_HOSTS:
            risks.append(f"[Script] 脚本来自白名单外域名(疑似供应链投毒): {host} <- {url}")
        body = sp.get("body", "")
        if sp.get("fetch_error"):
            notes.append(f"[Script] 拉取失败，无法扫描: {url} ({sp['fetch_error']})")
            continue
        for pat in SCRIPT_DANGER:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                snippet = m.group(0)[:80]
                risks.append(f"[Script] 命中外发/投毒特征 /{pat}/ -> {snippet!r}  ({url})")
    return risks, notes


def load_baseline():
    if os.path.exists(BASELINE):
        try:
            with open(BASELINE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:  # noqa: BLE001
            return {}
    return {}


def diff_notes(baseline, source_hashes, script_index):
    notes = []
    old_src = baseline.get("source_hashes", {})
    for url, h in source_hashes.items():
        if url in old_src and old_src[url] != h:
            notes.append(f"[变更] 上游模块内容已更新: {url}")
        elif url not in old_src:
            notes.append(f"[新增] 新上游模块: {url}")
    old_scripts = baseline.get("scripts", {})
    for url, h in script_index.items():
        if url in old_scripts and old_scripts[url] != h:
            notes.append(f"[变更] 远程脚本内容已更新(请留意): {url}")
        elif url not in old_scripts:
            notes.append(f"[新增] 新远程脚本: {url}")
    return notes


def write_report(risks, notes, ok, total):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    lines = [
        "shadowrocket-adblock 安全校验报告",
        f"时间(UTC): {ts}",
        f"拉取源: {ok}/{total}",
        "",
        f"风险(停更触发): {len(risks)}",
    ]
    lines += [f"  - {r}" for r in risks] or ["  （无）"]
    lines += ["", f"提示/变更: {len(notes)}"]
    lines += [f"  - {n}" for n in notes] or ["  （无）"]
    with open(REPORT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    with open(SOURCES_FILE, encoding="utf-8") as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    buckets, seen = OrderedDict(), {}
    mitm_hosts = []
    source_hashes = {}
    script_urls = []
    ok, failed = 0, []

    for url in urls:
        try:
            txt = fetch(url)
        except Exception as e:  # noqa: BLE001
            print(f"WARN: 源拉取失败 {url}\n      {e}", file=sys.stderr)
            failed.append(url)
            continue
        ok += 1
        source_hashes[url] = sha256(txt)
        for name, lines in parse_sections(txt).items():
            if name.lower() == "mitm":
                mitm_hosts += mitm_hosts_from(lines)
                continue
            if name.lower() == "script":
                script_urls += extract_script_paths(lines)
            buckets.setdefault(name, [])
            seen.setdefault(name, set())
            for ln in lines:
                if ln not in seen[name]:
                    seen[name].add(ln)
                    buckets[name].append(ln)

    if ok == 0:
        print("ERROR: 全部源拉取失败，保留旧产物", file=sys.stderr)
        sys.exit(1)

    # 去重 MITM / 脚本
    mitm_hosts = list(dict.fromkeys(mitm_hosts))
    script_urls = list(dict.fromkeys(script_urls))

    # 拉取并扫描每个远程脚本
    scripts = []
    script_index = {}
    for su in script_urls:
        entry = {"url": su, "host": host_of(su)}
        try:
            body = fetch(su)
            entry["body"] = body
            script_index[su] = sha256(body)
        except Exception as e:  # noqa: BLE001
            entry["fetch_error"] = str(e)
        scripts.append(entry)

    # 安全校验
    risks, audit_notes = security_audit(mitm_hosts, scripts)
    baseline = load_baseline()
    notes = audit_notes + diff_notes(baseline, source_hashes, script_index)

    write_report(risks, notes, ok, len(urls))

    if risks:
        print("SECURITY RISK: 检测到风险，停止更新，保留上一版产物。", file=sys.stderr)
        for r in risks:
            print("  RISK " + r, file=sys.stderr)
        sys.exit(2)

    # ── 安全通过：写产物 ──
    ordered = [s for s in PREFERRED_ORDER if s in buckets]
    ordered += [s for s in buckets if s not in PREFERRED_ORDER]
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    out = [
        f"#!name={HEADER_NAME}",
        f"#!desc=每日自动合并+安全校验 | 源 {ok} | MITM {len(mitm_hosts)} | 脚本 {len(scripts)} | {ts} UTC",
        "#!category=广告拦截",
        "#!author=memoryttt (auto-merge, security-checked)",
        "",
    ]
    for name in ordered:
        if not buckets[name]:
            continue
        out.append(f"[{name}]")
        out.extend(buckets[name])
        out.append("")
    if mitm_hosts:
        out.append("[MITM]")
        out.append("hostname = %APPEND% " + ", ".join(mitm_hosts))
        out.append("")

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump({
            "generated": ts + " UTC",
            "sources_ok": ok, "sources_total": len(urls),
            "mitm_hosts": mitm_hosts,
            "scripts": [{"url": s["url"], "host": s["host"]} for s in scripts],
        }, f, ensure_ascii=False, indent=2)

    # 刷新基线（仅在安全通过时更新，作为下次比对的可信参照）
    with open(BASELINE, "w", encoding="utf-8") as f:
        json.dump({
            "updated": ts + " UTC",
            "source_hashes": source_hashes,
            "scripts": script_index,
            "mitm_hosts": mitm_hosts,
        }, f, ensure_ascii=False, indent=2)

    print(f"OK: 安全通过，合并 {ok}/{len(urls)} 源 -> {OUTPUT}")
    print(f"    段落: {', '.join(ordered)} | MITM {len(mitm_hosts)} | 脚本 {len(scripts)}")
    if notes:
        print(f"    变更提示 {len(notes)} 条（见 security-report.txt）")
    if failed:
        print(f"    失败源 {len(failed)}: {failed}")


if __name__ == "__main__":
    main()
