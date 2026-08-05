# 运动世界（运动世界校园）去广告

针对「运动世界（运动世界校园）」Android App 的 AdGuard 广告过滤列表与构建器。

**核心结论：T1+T2 共 21 条域名级规则即可去广告，无需安装 CA 证书、无需 HTTPS 过滤**——
广告素材/请求/上报源全部位于第三方广告域名，被拦后广告位自然加载失败。

## 特性

- **免 CA**：T1（优帆/天目/有米主通道）+ T2（穿山甲/快手/OPPO/小米/腾讯/百度联盟）共 21 条域名级规则，DNS/连接层生效
- **安全边界**：28 项业务域 deny 名单交叉校验（0 碰撞）——不影响极验风控、业务 API、OBS 上传、推送、登录支付、地图
- **可选增强**：T3 路径级规则拦截 app 自研广告接口（ad/config、banner/list、ad/pv），需 HTTPS 过滤；T4 激进规则默认注释（开启会误伤业务图片 CDN/友盟推送）
- **可复现**：`tools/build_ad_filter.py` 支持从反编译源码 + classes.dex 重新扫描证据并重新生成列表
- **证据可溯源**：`docs/evidence.md` 中每条规则均有 java/dex 命中计数

## 快速开始

### 方法一：导入过滤列表（推荐）

1. AdGuard → 过滤规则 → 用户规则 / 自定义过滤器
2. 导入 `filters/ydsjxy_ads_adguard.txt`（完整版，含 T1-T4 全部注释说明）
3. 开启防护，完成

> 精简版 `filters/ydsjxy_ads_adguard_min.txt`（T1+T2+3 条 T3，无注释）用于不想看说明文件的场景。
> T3 需在 AdGuard 设置中开启「HTTPS 过滤」并信任 AdGuard CA（本 App 无证书固定）；不开启不影响 T1+T2 效果。

### 方法二：自行构建

```powershell
# 使用仓库内置静态证据（默认）
py -3.12 tools\build_ad_filter.py

# 提供反编译产物后重新扫描证据（可复现性验证）
py -3.12 tools\build_ad_filter.py --dex path\to\classes.dex --sources path\to\jadx_sources
```

输出：

| 产物 | 说明 |
| --- | --- |
| `filters/ydsjxy_ads_adguard.txt` | AdGuard 过滤列表（唯一交付物） |
| `docs/evidence.json` | 结构化证据（host → java/dex 聚合计数） |
| `docs/evidence.md` | 每条规则 → 证据计数报告 |

## 规则结构

| 层 | 数量 | 类型 | 生效条件 | 说明 |
| --- | --- | --- | --- | --- |
| T1 主通道 | 3 | 域名级 | 无需 CA | 优帆聚合（Guandian 提供方）/ 天目 / 有米 |
| T2 内嵌联盟 | 18 | 域名级 | 无需 CA | 穿山甲 / 快手 / OPPO / 小米 / 腾讯 / 百度 |
| T3 自研广告 API | 3+1 | 路径级 | 需 HTTPS 过滤 | ad/config、banner/list、ad/pv、startup/pv（可选） |
| T4 可选激进 | 4 | 域名级 | 手动开启 | 友盟系 / 业务图片 CDN（默认注释） |

## 验证情况

- 构建自检：24 条激活规则语法 0 错误、业务域 deny 交叉校验 0 碰撞、证据无缺失
- 证据规模：扫描 322 个域名 / 1,431 次命中（JADX 反编译源码 + classes.dex 原始字节）
- 反编译实测结论（分析依据，未实测设备）：
  - 广告位加载失败时 `AdvertiseControl` / `BannerViewModel` 均有异常兜底，广告位静默隐藏
  - 广告位可由服务端开关配置（SdkAdSwitchBean），列表按域名拦截不受开关影响
- 已知边界：运行时可能出现未收录的新广告域名——用 AdGuard 过滤日志收集后追加到 `DOMAIN_RULES` 并重跑构建器

## 目录结构

```
.
├── filters/
│   ├── ydsjxy_ads_adguard.txt        # 完整版过滤列表（24 条激活 + 4 条可选注释）
│   └── ydsjxy_ads_adguard_min.txt    # 精简版
├── tools/
│   └── build_ad_filter.py            # 过滤列表构建器（证据扫描 + deny 校验 + 生成）
├── docs/
│   ├── evidence.json                 # 结构化证据
│   └── evidence.md                   # 证据报告
├── LICENSE
└── README.md
```

## 免责声明

- 本项目的过滤列表基于对「运动世界（运动世界校园）」App 的静态分析（反编译文本与 DEX 字节扫描）生成，仅用于个人去广告用途。
- 列表中不包含任何 App 敏感材料：无密钥、无 token、无账号数据、无 APK 本体。
- 规则可能随 App 版本更新失效；误伤问题欢迎提 issue。
- 请遵守当地法律法规与相关平台条款。

## License

MIT
