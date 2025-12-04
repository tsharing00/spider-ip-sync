import requests
import os
import datetime

# ================= 配置区域 =================

# 输出文件名
FILE_WHITE = "spider_white_ips.txt"
FILE_BLACK = "bad_black_ips.txt"

# 请求头 (防止被某些接口拦截)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; FeedMyWafIP/1.0; +https://github.com/)"
}

# ----------------- 数据源定义 -----------------

# 1. 爬虫白名单 - JSON 格式源 (Google, Bing, Apple)
# 这些源返回 JSON，且结构通常包含 "prefixes" -> "ipv4Prefix"
WHITE_JSON_SOURCES = {
    "Bing": "https://www.bing.com/toolbox/bingbot.json",
    "Apple": "https://search.developer.apple.com/applebot.json",
    "Google": "https://developers.google.com/static/search/apis/ipranges/googlebot.json"
}

# 2. 爬虫白名单 - 文本/CIDR 格式源
# 这些源直接返回 IP 段，一行一个
WHITE_TEXT_SOURCES = {
    "Baidu": "https://ip-22617.rivers.chaitin.cn/api/share/ip_group/74a45de2d0f04f739ca73b2ecc05930d?format=cidr"
}

# 3. 恶意黑名单 - 文本/CIDR 格式源 (全部聚合到 bad_black_ips.txt)
BLACK_TEXT_SOURCES = {
    "MaliciousOps": "https://ip-22617.rivers.chaitin.cn/api/share/ip_group/9c1a54395c174e94af2b704eda610d95?format=cidr",
    "ThreatIntel": "https://ip-22617.rivers.chaitin.cn/api/share/ip_group/d13d2a3f9bb34fc4b2c846e3e0bc03bc?format=cidr",
    "ScannersAttacks": "https://ip-22617.rivers.chaitin.cn/api/share/ip_group/0ae14d75480842899342104743d2fc56?format=cidr"
}

# ================= 功能函数 =================

def fetch_json_cidrs(name, url):
    """处理返回 JSON 格式的接口 (Google/Bing/Apple)"""
    cidrs = set()
    print(f"[-] 正在抓取 [JSON]: {name} ...")
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        
        # 提取 ipv4Prefix
        if "prefixes" in data:
            for item in data["prefixes"]:
                if "ipv4Prefix" in item:
                    cidrs.add(item["ipv4Prefix"])
        print(f"    √ {name} 获取到 {len(cidrs)} 个 IP 段")
    except Exception as e:
        print(f"    × {name} 失败: {e}")
    return cidrs

def fetch_text_cidrs(name, url):
    """处理返回纯文本/CIDR 格式的接口 (Chaitin Rivers/Baidu)"""
    cidrs = set()
    print(f"[-] 正在抓取 [TEXT]: {name} ...")
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        
        # 按行分割，去除空白字符
        lines = resp.text.splitlines()
        for line in lines:
            line = line.strip()
            # 简单的校验，确保行不为空且看起来像 IP/CIDR
            if line and not line.startswith("#"): 
                cidrs.add(line)
        print(f"    √ {name} 获取到 {len(cidrs)} 个 IP 段")
    except Exception as e:
        print(f"    × {name} 失败: {e}")
    return cidrs

def save_to_file(filename, cidr_set):
    """保存数据到文件，始终覆盖"""
    try:
        # 排序以保持文件整洁
        sorted_cidrs = sorted(list(cidr_set))
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted_cidrs))
            # 可以在末尾加个换行
            f.write("\n")
        print(f"[SUCCESS] 已写入 {filename} (共 {len(sorted_cidrs)} 条数据)")
    except Exception as e:
        print(f"[ERROR] 写入 {filename} 失败: {e}")

# ================= 主程序 =================

def main():
    print(f"=== 开始执行 feed-mywaf-ip 更新任务: {datetime.datetime.now()} ===\n")

    # --- 1. 处理白名单 ---
    white_ips_all = set()
    
    # 1.1 JSON 源
    for name, url in WHITE_JSON_SOURCES.items():
        white_ips_all.update(fetch_json_cidrs(name, url))
        
    # 1.2 文本 源 (百度)
    for name, url in WHITE_TEXT_SOURCES.items():
        white_ips_all.update(fetch_text_cidrs(name, url))

    # 保存白名单
    save_to_file(FILE_WHITE, white_ips_all)
    print("-" * 30)

    # --- 2. 处理黑名单 ---
    black_ips_all = set()
    
    # 2.1 文本 源 (威胁情报等)
    for name, url in BLACK_TEXT_SOURCES.items():
        black_ips_all.update(fetch_text_cidrs(name, url))
        
    # 保存黑名单
    save_to_file(FILE_BLACK, black_ips_all)
    print("-" * 30)
    
    print("\n=== 更新完成 ===")

if __name__ == "__main__":
    main()
