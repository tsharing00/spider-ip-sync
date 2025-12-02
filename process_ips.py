import requests
import json
import os

SOURCES = {
    "bing_ips.txt": "https://www.bing.com/toolbox/bingbot.json",
    "apple_ips.txt": "https://search.developer.apple.com/applebot.json",
    "google_ips.txt": "https://developers.google.com/static/search/apis/ipranges/googlebot.json"
}

def fetch_and_parse():
    for filename, url in SOURCES.items():
        print(f"正在处理: {url} ...")
        try:
            # 1. 下载 JSON
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()

            # 2. 提取 IPv4 CIDR
            # 根据你提供的 googlebot.json、applebot.json、bingbot.json
            # 它们的结构都是 {"prefixes": [{"ipv4Prefix": "..."}]}
            ipv4_cidrs = []
            if "prefixes" in data:
                for item in data["prefixes"]:
                    if "ipv4Prefix" in item:
                        ipv4_cidrs.append(item["ipv4Prefix"])
            
            # 3. 写入 txt 文件
            if ipv4_cidrs:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write("\n".join(ipv4_cidrs))
                print(f" 成功写入 {len(ipv4_cidrs)} 个 IP 段到 {filename}")
            else:
                print(f" {url} 未找到 IPv4 数据")

        except Exception as e:
            print(f" 处理 {url} 失败: {e}")

if __name__ == "__main__":
    fetch_and_parse()
