# shadowrocket-adblock

把多个去广告模块（秋风 AWAvenue + fmz200 逐 App 模块）每日自动合并成**单个** Shadowrocket 模块，合并前带安全校验。

## 用法

Shadowrocket → 配置 → 模块 → 添加远程模块：

```
https://raw.githubusercontent.com/memoryttt/shadowrocket-adblock/main/dist/merged.sgmodule
```

模块自带 `[MITM]` 段（hostname 已合并），开 MITM、装并信任证书即可，无需手动填解密域名。

## 覆盖

QQ音乐、高德地图、淘宝、京东、中国联通、美团、哔哩哔哩、滴滴出行、闲鱼 的开屏/弹窗广告，
外加秋风 AWAvenue 的全 App 第三方广告域名拦截。

## 自动更新

`.github/workflows/merge.yml` 每天 19:17 UTC（北京 03:17）拉取上游、安全校验、合并、提交。
也可在 Actions 页手动 `Run workflow`；改 `sources.txt` 后自动重合并。

## 安全校验（merge.py）

每次合并前检测，命中任一即**停止更新**（保留上一版，不发布被投毒内容）并触发告警：

1. **MITM 危险通配** —— `*`、`*.com` 这类全 TLD 解密（`*.amap.com` 等限定域放行）。
2. **MITM 敏感域** —— 银行/支付/账号体系域名。
3. **脚本源白名单** —— `script-path` 指向白名单外域名。
4. **脚本外发特征** —— 拉取远程脚本扫描外发/混淆特征。
5. **基线对比** —— `baseline.json` 记录上游与脚本内容哈希，变更入报告。

退出码：`0` 通过；`1` 运行错误；`2` 安全风险（停更）。

## 增删 App

编辑 `sources.txt`（每行一个模块 URL）后 push。新增非 GitHub 来源脚本会触发停更，
确属可信需在 `merge.py` 的 `ALLOWED_SCRIPT_HOSTS` 显式加入。
fmz200 模块目录：<https://github.com/fmz200/wool_scripts/tree/main/Surge/module/split>
