# 运动世界校园 广告过滤规则 证据报告

生成器: `tools/build_ad_filter.py`；证据模式: `builtin`。

## 汇总

| 项 | 值 |
| --- | --- |
| generated_at | 2026-08-03 |
| tier1_domains | 3 |
| tier2_domains | 18 |
| tier3_urls | 3 |
| optional_tier4 | 4 |
| rules_total | 24 |
| evidence_hosts_scanned | 25 |
| evidence_total_hits | 222 |
| evidence_mode | builtin |

## 已收录规则及证据

| tier | 类型 | 规则 | 证据(java/dex 命中) | 说明 |
| --- | --- | --- | --- | --- |
| T1 | domain | `tianmu.mobi` | java:0 / dex:2 | 天目广告 SDK（TianMu 提供方 com.tianmu.ad）：sdk.tianmu.mobi |
| T1 | domain | `ubox.cn` | java:3 / dex:1 | 有米广告（v.ubox.cn，qr 落地页） |
| T1 | domain | `yfanads.com` | java:2 / dex:1 | 优帆 YFAN 聚合广告 SDK（Guandian 提供方）：api/tracker/adx-data/log 四个子域均在源码与 classes.dex 命中 |
| T2 | domain | `ad.toutiao.com` | java:0 / dex:1 | 字节广告域（ad.toutiao.com） |
| T2 | domain | `adkwai.com` | java:4 / dex:11 | 快手广告（p1-p5-lm.adkwai.com） |
| T2 | domain | `ads.heytapmobi.com` | java:5 / dex:5 | OPPO/欢太广告域（uapi.ads/adx.ads/ssp-adx.ads/stg-data.ads） |
| T2 | domain | `adsfs.heytapimage.com` | java:2 / dex:2 | OPPO 广告素材 CDN |
| T2 | domain | `cpro.baidustatic.com` | java:0 / dex:2 | 百度联盟广告素材 |
| T2 | domain | `csjplatform.com` | java:0 / dex:2 | 穿山甲广告平台域（www.csjplatform.com） |
| T2 | domain | `gifshow.com` | java:0 / dex:1 | 快手 SDK 广告测试/日志域（ad-open-api.test/log-sdk.gifshow.com；不影响 open.kuaishou.com 登录） |
| T2 | domain | `mqqad.html5.qq.com` | java:0 / dex:1 | 腾讯广告联盟落地页 |
| T2 | domain | `pangolin-sdk-toutiao-b.com` | java:0 / dex:2 | 穿山甲 Pangle 备用通道 |
| T2 | domain | `pangolin-sdk-toutiao.com` | java:0 / dex:5 | 穿山甲 Pangle 聚合：api-access/log-api/gromore |
| T2 | domain | `pangolin-sdk-toutiao1.com` | java:0 / dex:2 | 穿山甲 Pangle 备用通道 |
| T2 | domain | `pglstatp-toutiao.com` | java:0 / dex:62 | 穿山甲素材/上报（sf3-fe-tos.pglstatp-toutiao.com） |
| T2 | domain | `phoniex.toutiao.com` | java:0 / dex:1 | 穿山甲备用上报域 |
| T2 | domain | `sdkconfig.ad.xiaomi.com` | java:0 / dex:1 | 小米广告 SDK 配置 |
| T2 | domain | `snssdk.com` | java:0 / dex:3 | 字节系统计/广告相关域（log.snssdk.com） |
| T2 | domain | `toutiaopage.com` | java:0 / dex:1 | 穿山甲广告落地页（www.toutiaopage.com） |
| T2 | domain | `union.baidu.com` | java:0 / dex:2 | 百度联盟广告 |
| T2 | domain | `yximgs.com` | java:2 / dex:3 | 快手生态素材 CDN（static.yximgs.com；快手分享场景图片） |
| T3 | url | `/^https?:\/\/datapoint\.gxapp\.iydsj\.com\/api\/v70260\/datacollection\/ad\//` | 路径级（请求构建映射表证据） | 广告曝光上报：POST api/v70260/datacollection/ad/pv（DiscoveryApiManager.pvDataAd / ADTrackingModel） |
| T3 | url | `/^https?:\/\/discovery\.gxapp\.iydsj\.com\/api\/v50\/banner\/list/` | 路径级（请求构建映射表证据） | 首页 banner 广告位：POST api/v50/banner/list（BannerViewModel.requestBanner / DiscoveryApiManager.getBannerList） |
| T3 | url | `/^https?:\/\/discovery\.gxapp\.iydsj\.com\/api\/v70260\/ad\//` | 路径级（请求构建映射表证据） | 自研广告系统：GET api/v70260/ad/config（AdvertiseControl.requestAdConfig / DiscoveryApiManager.getAdMatchConfig） |


