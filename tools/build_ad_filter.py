# -*- coding: utf-8 -*-
"""运动世界（运动世界校园）广告过滤规则构建器（独立版）。

离线静态产物：从 JADX 反编译源码 + classes.dex 提取广告域名证据，
按层级（T1 主通道 / T2 内嵌联盟 / T3 自研广告 API 路径 / T4 可选激进）
生成 AdGuard 过滤列表，并与业务 deny 名单交叉校验防误拦。

两种证据模式：
  1) 内置静态证据（默认）：读取 docs/evidence.json（已随仓库发布，
     证据为反编译源码 + classes.dex 的聚合命中计数，不含任何源码片段）；
  2) 重新扫描（可复现）：提供 --dex <classes.dex> 与 --sources <jadx根>，
     会重新扫描并覆盖 docs/evidence.json。

用法:
    py -3.12 tools\\build_ad_filter.py
    py -3.12 tools\\build_ad_filter.py --dex path/to/classes.dex --sources path/to/jadx_sources

产物:
    filters/ydsjxy_ads_adguard.txt   AdGuard 过滤列表（唯一交付物）
    docs/evidence.json               结构化证据（host -> java/dex 聚合计数）
    docs/evidence.md                 每条规则 -> 证据计数 报告
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict

try:
    sys.stdout.reconfigure(encoding="utf-8")
except AttributeError:
    pass

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_EVIDENCE = os.path.join(REPO_ROOT, "docs", "evidence.json")
DEFAULT_OUT = os.path.join(REPO_ROOT, "filters", "ydsjxy_ads_adguard.txt")
DEFAULT_MD = os.path.join(REPO_ROOT, "docs", "evidence.md")

# ---------------------------------------------------------------- 规则定义

# 每条规则: (pattern, tier, note)
#   type=domain -> AdGuard 主机规则 ||pattern^
#   type=url    -> AdGuard 正则规则 /pattern/（内部 / 以 \/ 转义）
DOMAIN_RULES = [
    # ---- T1 第三方广告主通道 ----
    ("yfanads.com", 1, "优帆 YFAN 聚合广告 SDK（Guandian 提供方）：api/tracker/adx-data/log 四个子域均在源码与 classes.dex 命中"),
    ("tianmu.mobi", 1, "天目广告 SDK（TianMu 提供方 com.tianmu.ad）：sdk.tianmu.mobi"),
    ("ubox.cn", 1, "有米广告（v.ubox.cn，qr 落地页）"),
    # ---- T2 聚合内部广告联盟 ----
    ("pangolin-sdk-toutiao.com", 2, "穿山甲 Pangle 聚合：api-access/log-api/gromore"),
    ("pangolin-sdk-toutiao1.com", 2, "穿山甲 Pangle 备用通道"),
    ("pangolin-sdk-toutiao-b.com", 2, "穿山甲 Pangle 备用通道"),
    ("pglstatp-toutiao.com", 2, "穿山甲素材/上报（sf3-fe-tos.pglstatp-toutiao.com）"),
    ("ad.toutiao.com", 2, "字节广告域（ad.toutiao.com）"),
    ("phoniex.toutiao.com", 2, "穿山甲备用上报域"),
    ("toutiaopage.com", 2, "穿山甲广告落地页（www.toutiaopage.com）"),
    ("snssdk.com", 2, "字节系统计/广告相关域（log.snssdk.com）"),
    ("csjplatform.com", 2, "穿山甲广告平台域（www.csjplatform.com）"),
    ("adkwai.com", 2, "快手广告（p1-p5-lm.adkwai.com）"),
    ("gifshow.com", 2, "快手 SDK 广告测试/日志域（ad-open-api.test/log-sdk.gifshow.com；不影响 open.kuaishou.com 登录）"),
    ("yximgs.com", 2, "快手生态素材 CDN（static.yximgs.com；快手分享场景图片）"),
    ("ads.heytapmobi.com", 2, "OPPO/欢太广告域（uapi.ads/adx.ads/ssp-adx.ads/stg-data.ads）"),
    ("adsfs.heytapimage.com", 2, "OPPO 广告素材 CDN"),
    ("sdkconfig.ad.xiaomi.com", 2, "小米广告 SDK 配置"),
    ("mqqad.html5.qq.com", 2, "腾讯广告联盟落地页"),
    ("cpro.baidustatic.com", 2, "百度联盟广告素材"),
    ("union.baidu.com", 2, "百度联盟广告"),
]

URL_RULES = [
    # ---- T3 app 自研广告 API（需 AdGuard HTTPS 过滤）----
    (r"^https?://discovery\.gxapp\.iydsj\.com/api/v70260/ad/", 3,
     "自研广告系统：GET api/v70260/ad/config（AdvertiseControl.requestAdConfig / DiscoveryApiManager.getAdMatchConfig）"),
    (r"^https?://discovery\.gxapp\.iydsj\.com/api/v50/banner/list", 3,
     "首页 banner 广告位：POST api/v50/banner/list（BannerViewModel.requestBanner / DiscoveryApiManager.getBannerList）"),
    (r"^https?://datapoint\.gxapp\.iydsj\.com/api/v70260/datacollection/ad/", 3,
     "广告曝光上报：POST api/v70260/datacollection/ad/pv（DiscoveryApiManager.pvDataAd / ADTrackingModel）"),
    # ---- T3 可选（默认注释）----
    (r"^https?://datapoint\.gxapp\.iydsj\.com/api/v76/startup/pv", 3,
     "启动页曝光统计（DiscoveryApiManager.getSplashPv；仅遥测，可选关闭）"),
]

OPTIONAL_RULES = [
    # ---- T4 可选激进（默认注释，误伤风险高）----
    ("domain", "umeng.com", "友盟统计/推送全系（含广告上报 log.umsns.com；拦后友盟推送渠道失效）"),
    ("domain", "umengcloud.com", "友盟统计备用域"),
    ("domain", "umsns.com", "友盟社媒广告统计"),
    ("domain", "gxapp-images.iydsj.com", "业务图片 CDN（可能含广告素材，但拦整域会丢失头像/活动图）"),
]

# 业务 deny 名单：整域禁止进入拦截列表（上述规则的 host 部分不得整域拦截）
BUSINESS_ALLOW = [
    "iydsj.com",                    # 全部业务域仅允许路径级拦截（T3）
    "myhuaweicloud.com",            # OBS 上传桶（轨迹/头像/视频）
    "geetest.com",                  # 极验风控 dkapi.geetest.com
    "getui.com",                    # 个推推送
    "mobileservice.cn",             # 移动认证 zxid-m.mobileservice.cn
    "amap.com",                     # 高德地图/定位
    "openmobile.qq.com",            # QQ 登录
    "api.weixin.qq.com",            # 微信登录
    "api.weibo.com",                # 微博登录
    "alipay.com",                   # 支付宝
    "aip.baidubce.com",             # 百度人脸（业务）
    "cmpassport.com",               # 移动一键登录
    "wosms.cn",                     # 移动短信
    "ccidcall.cn",                  # 移动认证
    "10010.com",                    # 联通
    "sj.qq.com",                    # 应用宝
    "a.app.qq.com",                 # 应用宝
    "huawei.com",                   # 华为 HMS/推送
    "resolver.msg.xiaomi.net",      # 小米推送
    "qq.com",                       # QQ 生态（仅 ad.html5.qq.com 子域可拦）
    "xiaomi.com",                   # 小米生态（仅 sdkconfig.ad.xiaomi.com 子域可拦）
    "baidu.com",                    # 百度生态（仅 cpro.baidustatic/union.baidu 子域可拦）
    "bytedance.net",                # 字节（未收录）
    "volces.com",                   # 火山引擎（未收录）
    "kuaishou.com",                 # 快手开放平台（未收录）
    "heytapmobi.com",               # OPPO 生态（仅 ads.* 子域可拦）
    "heytapimage.com",              # OPPO 素材（仅 adsfs 子域可拦）
    "toutiao.com",                  # 字节（仅 ad.toutiao.com/phoniex.toutiao.com 子域可拦）
]

# ---------------------------------------------------------------- 证据获取


def scan_java_sources(sources):
    """返回 {host: {file: count}}，来自 JADX 反编译文本。"""
    pat = re.compile(r"https?://([a-zA-Z0-9][a-zA-Z0-9\-.]*)", re.I)
    hits = defaultdict(Counter)
    for root in sources:
        if not os.path.isdir(root):
            continue
        for dp, _, fs in os.walk(root):
            for f in fs:
                if not f.endswith(".java"):
                    continue
                fp = os.path.join(dp, f)
                try:
                    t = open(fp, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                rel = os.path.relpath(fp, sources[0]).replace("\\", "/")
                for m in pat.finditer(t):
                    host = m.group(1).lower()
                    hits[host][rel] += 1
    return hits


def scan_dex(dex_path):
    """返回 {host: int}，来自 classes.dex 原始字节（latin-1 解码扫描）。"""
    if not dex_path or not os.path.isfile(dex_path):
        return {}
    pat = re.compile(r"([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.){1,4}"
                     r"(?:com|cn|net|mobi|top|xyz|cc|info|site|tv)\b")
    with open(dex_path, "rb") as fh:
        data = fh.read().decode("latin-1")
    hits = Counter()
    for m in pat.finditer(data):
        hits[m.group(0).lower()] += 1
    return dict(hits)


def load_static_evidence(path):
    """读取仓库内置证据（聚合计数，host -> {java, dex, total}）。"""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("hosts", {}), data.get("summary", {})


def is_subdomain_of(host, parent):
    """host == parent 或 host 以 parent. 结尾。"""
    return host == parent or host.endswith("." + parent)


def domain_evidence(evidence, host):
    """证据查找：精确命中或取证据最强的子域。"""
    cand = [(h, e) for h, e in evidence.items()
            if (h == host or is_subdomain_of(h, host)) and e["total"] > 0]
    if not cand:
        return {"java": 0, "dex": 0, "total": 0}
    return max(cand, key=lambda x: x[1]["total"])[1]


# ---------------------------------------------------------------- 生成


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dex", default=None,
                    help="classes.dex 路径（提供后重新扫描证据；缺省用内置静态证据）")
    ap.add_argument("--sources", nargs="*", default=None,
                    help="JADX 反编译源码根（可多个；提供后重新扫描证据）")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--json", default=DEFAULT_EVIDENCE)
    ap.add_argument("--md", default=DEFAULT_MD)
    args = ap.parse_args()

    if args.dex or args.sources:
        java = scan_java_sources(args.sources or [])
        dex = scan_dex(args.dex)
        evidence = {}
        for h in set(java) | set(dex):
            java_n = sum(java.get(h, {}).values())
            evidence[h] = {"java": java_n, "dex": dex.get(h, 0),
                           "total": java_n + dex.get(h, 0)}
        summary_extra = {"evidence_mode": "rescanned",
                         "evidence_hosts_scanned": len(evidence)}
    else:
        evidence, summary_extra = load_static_evidence(args.json)
        evidence = dict(evidence)
        summary_extra = dict(summary_extra)
        summary_extra["evidence_mode"] = "builtin"

    def fmt_evidence(host):
        ev = domain_evidence(evidence, host)
        src = []
        if ev["java"]:
            src.append("java:" + str(ev["java"]))
        if ev["dex"]:
            src.append("dex:" + str(ev["dex"]))
        return "/".join(src) if src else "none", ev

    lines = []
    rules_out = []
    errors = []

    def add_domain(host, tier, note, enabled):
        src_txt, ev = fmt_evidence(host)
        if src_txt == "none":
            errors.append("no-evidence: " + host)
        if not enabled:
            lines.append("! ||" + host + "^  " + note + "  [证据: " + src_txt + "]")
            return
        lines.append("! " + note + "  [证据: " + src_txt + "]")
        lines.append("||" + host + "^")
        rules_out.append({"type": "domain", "pattern": host, "tier": tier,
                          "note": note, "evidence": ev})

    def add_url(pattern, tier, note, enabled):
        escaped = pattern.replace("/", r"\/")
        if not enabled:
            lines.append("! /" + escaped + "/  " + note)
            return
        lines.append("! " + note)
        lines.append("/" + escaped + "/")
        rules_out.append({"type": "url", "pattern": pattern, "tier": tier, "note": note})

    header = [
        "! Title: YDSJXY 运动世界校园 广告过滤规则",
        "! Description: 拦截运动世界校园 (com.zjwh.android_wh_physicalfitness) 广告流量",
        "!   用法: AdGuard → 过滤规则 → 用户规则/自定义过滤器 → 导入本文件 → 开启防护",
        "!   无需安装 CA 证书/无需 HTTPS 过滤: T1+T2 域名规则在 DNS/连接层生效，",
        "!     覆盖全部广告素材/请求/上报来源（优帆/天目/穿山甲/快手/OPPO/小米/腾讯/百度/有米），",
        "!     广告位因素材源被拦而自然加载失败，即可达到去广告效果",
        "!   T3 路径级规则（可选增强）: 拦 app 自研广告接口 ad/config、banner/list、ad/pv",
        "!     ——需在 AdGuard 设置开启「HTTPS 过滤」并信任 AdGuard CA（app 无证书固定）",
        "!     不开启时 T3 不生效，但不影响 T1+T2 的去广告效果",
        "!   T4 可选激进规则默认注释；开启会误伤业务图片（gxapp-images CDN）或推送统计（友盟）",
        "! 安全边界: 不拦截 partner.iydsj.com（极验 deviceVerify 风控）、run/discovery 业务 API、getui/华为推送、AMap、QQ/微信/支付宝",
        "! 证据: docs/evidence.json / .md（域名均可在反编译源码或 classes.dex 溯源，聚合计数）",
        "! 生成器: tools/build_ad_filter.py",
        "! Version: 1.0.1",
        "",
        "[Adblock Plus 2.0]",
        "",
        "! ============ T1 第三方广告主通道（无需 CA，DNS/连接层生效）============",
    ]
    out = list(header)
    for host, tier, note in DOMAIN_RULES:
        if tier == 1:
            add_domain(host, tier, note, True)
    out.extend(lines); lines = []
    out += ["",
            "! ============ T2 聚合内部广告联盟（无需 CA，DNS/连接层生效）============"]
    for host, tier, note in DOMAIN_RULES:
        if tier == 2:
            add_domain(host, tier, note, True)
    out.extend(lines); lines = []
    out += ["",
            "! ============ T3 app 自研广告 API（需 HTTPS 过滤）============",
            "! 命中后连接直接丢弃：app 广告加载回调走失败分支，广告位静默隐藏（AdvertiseControl/BannerViewModel 均有异常兜底）"]
    for pattern, tier, note in URL_RULES:
        if note.startswith("启动页"):
            add_url(pattern, tier, note, False)
        else:
            add_url(pattern, tier, note, True)
    out.extend(lines); lines = []
    out += ["",
            "! ============ T4 可选激进（默认关闭，去掉行首 ! 生效）============"]
    for rtype, pattern, note in OPTIONAL_RULES:
        if rtype == "domain":
            add_domain(pattern, 4, note, False)
        else:
            add_url(pattern, 4, note, False)
    out.extend(lines)

    # ---- deny 交叉校验：仅当拦截域名覆盖了业务域名（业务域是被拦域的整域子域）才算碰撞 ----
    for rule in rules_out:
        if rule["type"] != "domain":
            continue
        for biz in BUSINESS_ALLOW:
            if is_subdomain_of(biz, rule["pattern"]):
                errors.append("deny-collision: %s <-> %s" % (rule["pattern"], biz))

    # ---- 语法自检 ----
    for rule in rules_out:
        if rule["type"] == "domain" and not re.fullmatch(r"[a-z0-9](?:[a-z0-9\-.]*[a-z0-9])?", rule["pattern"]):
            errors.append("bad-domain: " + rule["pattern"])
        if rule["type"] == "url" and (not rule["pattern"].startswith("^") or "//" not in rule["pattern"]):
            errors.append("bad-url: " + rule["pattern"])

    # ---- 落盘 ----
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(out) + "\n")

    summary = {
        "generated_at": "2026-08-03",
        "tier1_domains": sum(1 for r in rules_out if r["tier"] == 1),
        "tier2_domains": sum(1 for r in rules_out if r["tier"] == 2),
        "tier3_urls": sum(1 for r in rules_out if r["tier"] == 3),
        "optional_tier4": len(OPTIONAL_RULES),
        "rules_total": len(rules_out),
        "evidence_hosts_scanned": len(evidence),
        "evidence_total_hits": sum(e["total"] for e in evidence.values()),
        "evidence_mode": summary_extra.get("evidence_mode", "builtin"),
    }
    payload = {"summary": summary, "rules": rules_out, "errors": errors,
               "business_allow": BUSINESS_ALLOW, "optional_rules": OPTIONAL_RULES,
               "hosts": evidence}
    os.makedirs(os.path.dirname(args.json), exist_ok=True)
    with open(args.json, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)

    # ---- 证据 md ----
    md = []
    md.append("# 运动世界校园 广告过滤规则 证据报告")
    md.append("")
    md.append("生成器: `tools/build_ad_filter.py`；证据模式: `%s`。"
              % summary["evidence_mode"])
    md.append("")
    md.append("## 汇总")
    md.append("")
    md.append("| 项 | 值 |")
    md.append("| --- | --- |")
    for k, v in summary.items():
        md.append("| %s | %s |" % (k, v))
    md.append("")
    md.append("## 已收录规则及证据")
    md.append("")
    md.append("| tier | 类型 | 规则 | 证据(java/dex 命中) | 说明 |")
    md.append("| --- | --- | --- | --- | --- |")
    for r in sorted(rules_out, key=lambda x: (x["tier"], x["pattern"])):
        ev = r.get("evidence") or {}
        j = ev.get("java", 0)
        d = ev.get("dex", 0)
        if r["type"] == "url":
            esc = r["pattern"].replace("/", r"\/")
            md.append("| T%d | %s | `/%s/` | 路径级（请求构建映射表证据） | %s |"
                      % (r["tier"], r["type"], esc, r["note"]))
        else:
            md.append("| T%d | %s | `%s` | java:%d / dex:%d | %s |"
                      % (r["tier"], r["type"], r["pattern"], j, d, r["note"]))
    md.append("")
    if errors:
        md.append("## 校验错误")
        md.append("")
        for e in errors:
            md.append("- `%s`" % e)
    md.append("")
    with open(args.md, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(md) + "\n")

    # ---- 控制台 ----
    print("rules_total=%d" % len(rules_out))
    print("output=%s" % os.path.relpath(args.out, REPO_ROOT))
    print("json=%s" % os.path.relpath(args.json, REPO_ROOT))
    print("md=%s" % os.path.relpath(args.md, REPO_ROOT))
    if errors:
        print("ERRORS:")
        for e in errors:
            print("  " + e)
        sys.exit(1)
    print("OK: no evidence/deny/syntax errors")


if __name__ == "__main__":
    main()
