# AdGuard Privacy · GL-MT3600BE

面向 **AdGuard Home DNS 过滤**，合并 anti-AD、秋风广告规则、AdGuard DNS Popup Hosts filter、HaGeZi Multi PRO mini。

## 订阅

https://raw.githubusercontent.com/dijunux/adguard-privacy/main/adguard.txt

在 AdGuard Home → 过滤器 → DNS 黑名单 → 添加自定义列表，粘贴上述地址，并将更新间隔设为 **24 小时**。路由器只需下载这一份合并文件，请停用原来单独订阅的四套列表，避免重复占用空间。不适用于浏览器广告扩展。

## 自动更新及失败保护

- GitHub Actions 每天 **北京时间 03:23（UTC 19:23）**运行，可在 Actions 手动运行。
- 每个来源超时 45 秒，最多尝试 3 次；拒绝空文件、HTML、未知格式、过小列表及相较上一版骤减超过 30% 的列表。
- 各源上一份有效原文持久保存在 `sources/*.txt.gz`，有 SHA-256 校验；下载或校验失败时使用该源缓存。首次无缓存则停止，不发布残缺列表。
- 合并、测试和体积检查全部通过后，单次 Git 提交原子发布。失败时线上 `adguard.txt` 保持上一份有效版本。
- 白名单、正则、通配符以及 `$dnsrewrite`、`$important`、`$badfilter` 等修饰符完整保留。不把规则简化成纯域名。
- 先按完整规则去重，再删除已被有效父域名规则覆盖的普通子域名拦截规则；不改动特殊规则和白名单，不以截断文件来满足上限。
- `status.json` 记录规则数、字节数、哈希、来源更新时间及 fresh/cached 状态。Actions 页面保存构建、故障模拟和在线订阅校验结果。
- GitHub 定时任务可能排队延迟，并非严格实时保证；若长期无仓库活动导致计划被停用，请在 Actions 重新启用。正常每日状态提交会持续产生仓库活动。

## 资源预算

- 单订阅硬上限 **4,100,000 字节（4.1 MB）**，最多 **200,000 条规则**。两份规则文件最多 8.2 MB，给所述 8.5 MB 规则存储空间保留约 0.3 MB 余量。
- 构建、下载四份原始规则和压缩缓存均在 GitHub 完成；路由器仅下载合并订阅。
- 512 MB 是整机内存，过滤器实际占用还受 AdGuard Home 版本、DNS 缓存、查询日志和其他服务影响。服务器上的加载测试不能替代路由器实测；应只启用需要的列表，并检查路由器实际剩余空间和内存。
- 超出预算会拒绝新版本并保留旧版，不会悄悄丢弃规则。若上游长期增长导致拒绝，需要调整列表或存储预算。

## 来源与许可

| 来源 | 官方原文 | 许可原文 |
|---|---|---|
| anti-AD | [AdGuard Home 版](https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-easylist.txt) | [LICENSE-anti-ad](LICENSE-anti-ad) |
| 秋风广告规则 | [完整防护版](https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt) | [LICENSE-awavenue](LICENSE-awavenue) |
| AdGuard DNS Popup Hosts filter | [DNS Popup](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/adguard_popup_filter.txt) | [LICENSE-popup](LICENSE-popup) |
| HaGeZi Multi PRO mini | [Adblock 版](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.mini.txt) | [LICENSE-hagezi](LICENSE-hagezi) |

原始规则的版权与许可归各上游作者所有。`sources/` 保存包含上游注释和署名的完整原文压缩快照；合并规则沿用上游适用许可。秋风完整防护方案也包含隐私和不受欢迎连接规则，可能影响部分推送或更新功能。可在 AdGuard Home 的自定义规则中按需添加白名单。

## 维护

- 更新程序：`update_rules.py`（仅 Python 标准库）。
- 离线安全测试：`python update_rules.py --test`。
- 构建：`python update_rules.py`。
- 工作流：`.github/workflows/update.yml`。
- 权限仅为本仓库 `contents: write`，使用 GitHub 自动提供的短期 `GITHUB_TOKEN`；不需要个人令牌或其他私有仓库权限。
