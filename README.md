# shadowrocket-adblock

把多个去广告模块（秋风 AWAvenue + fmz200 逐 App 模块）每日自动合并成**单个** Shadowrocket 模块，**合并前带安全校验与供应链攻击感知**。

## 用法

Shadowrocket → 配置 → 模块 → 添加远程模块，填：

```
https://raw.githubusercontent.com/memoryttt/shadowrocket-adblock/main/dist/merged.sgmodule
```

模块自带 `[MITM]` 段，hostname 自动合并，**无需手动填解密域名**。装完开 MITM、装并信任证书即可。

## 覆盖

QQ音乐、高德地图、淘宝、京东、中国联通、美团、哔哩哔哩、滴滴出行、闲鱼 的开屏/弹窗广告，
外加秋风 AWAvenue 的全 App 第三方广告域名拦截。

## 自动更新

`.github/workflows/merge.yml` 每天 19:17 UTC（北京 03:17）跑 `merge.py`，
重新拉取 `sources.txt` 里的上游模块、**安全校验**、合并、提交 `dist/merged.sgmodule`。
也可在 Actions 页手动 `Run workflow`。

## 安全校验与供应链感知（merge.py）

每次合并前自动检测，命中任一即**停止更新**（保留上一版良品，绝不发布被投毒内容）并发邮件告警：

1. **MITM 危险通配** —— `*`、`*.com` 这类全 TLD 通配（`*.amap.com` 等限定域放行）。
2. **MITM 敏感域** —— 银行/支付/Apple/Google 账号等域名（不该被解密）。
3. **脚本源白名单** —— `script-path` 指向白名单外域名（供应链投毒经典手法）。
4. **脚本外发特征** —— 拉取每个远程脚本扫描 `api.telegram.org`、bot token、
   discord/slack webhook、`eval(atob(` 等外发/混淆特征。
5. **基线对比** —— `baseline.json` 记录上游模块与脚本内容哈希，变更会在报告中提示。

风险清单写入 `security-report.txt`，作为告警邮件附件。
退出码：`0` 安全通过；`1` 运行错误；`2` 安全风险（停更 + 邮件）。

### 邮件告警配置

告警发往 `cyg02032015@126.com`。需在 repo **Settings → Secrets → Actions** 配置发件 SMTP：

| Secret | 说明 | 示例 |
|---|---|---|
| `MAIL_SERVER` | SMTP 服务器 | `smtp.qq.com` / `smtp.163.com` / `smtp.126.com` |
| `MAIL_PORT` | SSL 端口 | `465` |
| `MAIL_USERNAME` | 发件邮箱 | `you@qq.com` |
| `MAIL_PASSWORD` | SMTP 授权码（非登录密码） | `xxxxxxxx` |

> 国内邮箱（QQ/163/126）需在邮箱设置里开启 SMTP 并生成「授权码」，密码填授权码。

## 增删 App

编辑 `sources.txt`（每行一个模块 URL），push 后自动重新合并。
fmz200 模块目录：<https://github.com/fmz200/wool_scripts/tree/main/Surge/module/split>

## 白名单维护

新增非 GitHub 来源的脚本会触发停更（防投毒）。确属可信的新脚本源，
需在 `merge.py` 的 `ALLOWED_SCRIPT_HOSTS` 显式加入后再合并。
当前白名单含第三方 `klraw.pages.dev`（闲鱼脚本），其内容仍逐次扫描。
