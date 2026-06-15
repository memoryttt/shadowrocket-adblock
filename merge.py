#!/usr/bin/env python3
"""聚合多个 Surge/Shadowrocket .sgmodule 去广告模块为单个模块。

- 逐源拉取，按段落（[Rule] / [URL Rewrite] / [Map Local] / [Body Rewrite]
  / [Script] / [Host] / [MITM] 等）收集并去重。
- [MITM] 的 hostname 全部抽出、去重，合并成一行 `hostname = %APPEND% ...`。
- 输出 dist/merged.sgmodule，保留各源 script-path（远程脚本运行时拉取）。
"""
import os
import re
import sys
import time
import urllib.request
from collections import OrderedDict

SOURCES_FILE = os.path.join(os.path.dirname(__file__), "sources.txt")
OUTPUT = os.path.join(os.path.dirname(__file__), "dist", "merged.sgmodule")

# 输出段落顺序；未列出的段落按出现顺序追加在 MITM 之前
PREFERRED_ORDER = ["Rule", "URL Rewrite", "Map Local", "Body Rewrite", "Host", "Script"]

HEADER_NAME = "聚合去广告"


def fetch(url, retries=3):
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(2 * (i + 1))
    raise RuntimeError(f"fetch failed after {retries}: {last}")


def parse_sections(text):
    """返回 OrderedDict{section_name: [行,...]}，跳过空行与注释/元数据。"""
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


def merge_mitm_hosts(lines, acc):
    for ln in lines:
        if "hostname" not in ln.lower():
            continue
        rhs = ln.split("=", 1)[1] if "=" in ln else ""
        rhs = rhs.replace("%APPEND%", "")
        for h in rhs.split(","):
            h = h.strip()
            if h and h not in acc:
                acc.append(h)


def main():
    with open(SOURCES_FILE, encoding="utf-8") as f:
        urls = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    buckets = OrderedDict()          # section -> list(行)
    seen = {}                        # section -> set(行)
    mitm_hosts = []
    ok, failed = 0, []

    for url in urls:
        try:
            txt = fetch(url)
        except Exception as e:  # noqa: BLE001
            print(f"WARN: {url}\n      {e}", file=sys.stderr)
            failed.append(url)
            continue
        ok += 1
        for name, lines in parse_sections(txt).items():
            if name.lower() == "mitm":
                merge_mitm_hosts(lines, mitm_hosts)
                continue
            buckets.setdefault(name, [])
            seen.setdefault(name, set())
            for ln in lines:
                if ln not in seen[name]:
                    seen[name].add(ln)
                    buckets[name].append(ln)

    if ok == 0:
        print("ERROR: 全部源拉取失败，保留旧产物不覆盖", file=sys.stderr)
        sys.exit(1)

    # 段落排序：PREFERRED_ORDER 在前，其余保持出现顺序
    ordered = [s for s in PREFERRED_ORDER if s in buckets]
    ordered += [s for s in buckets if s not in PREFERRED_ORDER]

    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    out = [
        f"#!name={HEADER_NAME}",
        f"#!desc=GitHub Actions 每日自动合并 | 源 {ok} 个 | MITM 域名 {len(mitm_hosts)} 个 | 更新 {ts} UTC",
        "#!category=广告拦截",
        "#!author=memoryttt (auto-merge)",
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

    print(f"OK: 合并 {ok}/{len(urls)} 源 -> {OUTPUT}")
    print(f"    段落: {', '.join(ordered)}")
    print(f"    MITM 域名: {len(mitm_hosts)}")
    if failed:
        print(f"    失败源: {len(failed)} -> {failed}")


if __name__ == "__main__":
    main()
