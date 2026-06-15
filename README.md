# shadowrocket-adblock

把多个去广告模块（秋风 AWAvenue + fmz200 逐 App 模块）每日自动合并成**单个** Shadowrocket 模块。

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
重新拉取 `sources.txt` 里的上游模块、合并、提交 `dist/merged.sgmodule`。
也可在 Actions 页手动 `Run workflow`。

## 增删 App

编辑 `sources.txt`（每行一个模块 URL），push 后自动重新合并。
fmz200 模块目录：<https://github.com/fmz200/wool_scripts/tree/main/Surge/module/split>

## 安全说明

- 合并只做文本拼接 + 去重，不改写脚本内容。
- 闲鱼模块的脚本托管在第三方域名（klraw.pages.dev），运行时实时拉取，存在供应链风险；
  介意可在 `sources.txt` 删除该行。
- 切勿把 `[MITM] hostname` 改成 `*`，那会解密全部 HTTPS 流量。
