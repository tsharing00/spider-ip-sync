import requests
import os
import datetime
from datetime import timedelta
import warnings
from bs4 import BeautifulSoup
import ipaddress

# 忽略 HTTPS 证书警告
warnings.filterwarnings("ignore")

# ================= 配置区域 =================

# 输出文件名
FILE_WHITE = "spider_white_ips.txt"
FILE_BLACK = "bad_black_ips.txt"

# 请求头 (防止被某些接口拦截)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; FeedMyWafIP/2.0; +https://github.com/)"
}

# ----------------- 数据源定义 -----------------

# 1. 爬虫白名单 - JSON 格式源 (Google, Bing, Apple)
WHITE_JSON_SOURCES = {
    "Bing": "https://www.bing.com/toolbox/bingbot.json",
    "Apple": "https://search.developer.apple.com/applebot.json",
    "Google": "https://developers.google.com/static/search/apis/ipranges/googlebot.json"
}

# 2. 爬虫白名单 - 文本/CIDR 格式源
WHITE_TEXT_SOURCES = {
    "Baidu": "https://ip-22617.rivers.chaitin.cn/api/share/ip_group/74a45de2d0f04f739ca73b2ecc05930d?format=cidr",
    "MyCollect": "https://www.52txr.cn/tools/spider_collect.spider"
}

# 3. 恶意黑名单 - 文本/CIDR 格式源 (长亭)
BLACK_TEXT_SOURCES = {
    "MaliciousOps": "https://ip-22617.rivers.chaitin.cn/api/share/ip_group/9c1a54395c174e94af2b704eda610d95?format=cidr",
    "ThreatIntel": "https://ip-22617.rivers.chaitin.cn/api/share/ip_group/d13d2a3f9bb34fc4b2c846e3e0bc03bc?format=cidr",
    "ScannersAttacks": "https://ip-22617.rivers.chaitin.cn/api/share/ip_group/0ae14d75480842899342104743d2fc56?format=cidr",
    "ALiScan":"https://ip-22617.rivers.chaitin.cn/api/share/ip_group/d7f3432bc67645e2ab5fb777726a9eb5?format=cidr"
}

# 4. 恶意黑名单 - FireHOL 源 (文本/netset 格式)
FIREHOL_SOURCES = {
    "FireHOL_L1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "FireHOL_L2": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",

    # blocklist.de
    "Blocklist_DE": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de.ipset",
    "Blocklist_DE_SSH": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/blocklist_de_ssh.ipset",

    # dshield
    "DShield_1d": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield_1d.netset",

    # greensnow
    "GreenSnow": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/greensnow.ipset",

    # spamhaus
    "Spamhaus_DROP": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset",

    # EmergingThreats Compromised Hosts
    "ET_Compromised": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/et_compromised.ipset"
}


# ================= 功能函数 =================

def normalize_cidr(cidr_str):
    """标准化CIDR表示"""
    try:
        # 清理空格
        cidr_str = cidr_str.strip()
        if not cidr_str:
            return None
            
        # 处理单独的IP地址
        if '/' not in cidr_str:
            return str(ipaddress.ip_network(cidr_str + '/32', strict=False))
        
        # 处理CIDR表示
        network = ipaddress.ip_network(cidr_str, strict=False)
        return str(network)
    except (ValueError, ipaddress.AddressValueError):
        # 静默失败，不打印过多日志
        return None

def merge_cidrs(cidr_set):
    """合并重叠的CIDR段"""
    networks = []
    
    # 1. 标准化所有CIDR
    for cidr in cidr_set:
        normalized = normalize_cidr(cidr)
        if normalized:
            try:
                networks.append(ipaddress.ip_network(normalized, strict=False))
            except Exception:
                pass
    
    if not networks:
        return set()
    
    # 2. 按网络地址排序
    networks.sort(key=lambda x: (x.network_address, x.prefixlen))
    
    # 3. 合并重叠的网络
    merged = []
    for net in networks:
        if not merged:
            merged.append(net)
            continue
            
        # 检查当前网络是否被最后一个网络包含
        last_net = merged[-1]
        if last_net.supernet_of(net):
            # 当前网络已经被更大的网络包含，跳过
            continue
        elif net.supernet_of(last_net):
            # 当前网络包含最后一个网络，替换
            merged[-1] = net
            # 继续向前检查可能的重叠
            while len(merged) > 1 and merged[-2].supernet_of(merged[-1]):
                merged.pop(-2)
        else:
            # 没有重叠，添加新网络
            merged.append(net)
    
    # 4. 尝试进一步合并相邻的网络
    further_merged = []
    i = 0
    while i < len(merged):
        current = merged[i]
        if i < len(merged) - 1:
            next_net = merged[i + 1]
            # 尝试合并相邻的/24段为更大的段
            if current.prefixlen == next_net.prefixlen and current.prefixlen >= 8:
                try:
                    # 尝试将它们合并为更大的前缀
                    supernet = current.supernet(new_prefix=current.prefixlen - 1)
                    if supernet.network_address == current.network_address and \
                       supernet.broadcast_address >= next_net.broadcast_address:
                        further_merged.append(supernet)
                        i += 2
                        continue
                except ValueError:
                    pass
        
        further_merged.append(current)
        i += 1
    
    # 转换回字符串表示
    return {str(net) for net in further_merged}

def fetch_json_cidrs(name, url):
    """处理返回 JSON 格式的接口 (Google/Bing/Apple)"""
    cidrs = set()
    print(f"[-] 正在抓取 [JSON]: {name} ...")
    try:
        resp = requests.get(url, headers=HEADERS, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        
        if "prefixes" in data:
            for item in data["prefixes"]:
                if "ipv4Prefix" in item:
                    cidr_str = item["ipv4Prefix"]
                    normalized = normalize_cidr(cidr_str)
                    if normalized:
                        cidrs.add(normalized)
        print(f"    √ {name} 获取到 {len(cidrs)} 个 IP 段")
    except Exception as e:
        print(f"    × {name} 失败: {e}")
    return cidrs

def fetch_text_cidrs(name, url):
    """处理返回纯文本/CIDR 格式的接口 (Chaitin Rivers/Baidu/FireHOL)"""
    cidrs = set()
    print(f"[-] 正在抓取 [TEXT]: {name} ...")
    try:
        resp = requests.get(url, headers=HEADERS, timeout=60)
        resp.raise_for_status()
        
        lines = resp.text.splitlines()
        for line in lines:
            line = line.split('#')[0].strip()
            if line:
                normalized = normalize_cidr(line)
                if normalized:
                    cidrs.add(normalized)
        print(f"    √ {name} 获取到 {len(cidrs)} 个 IP 段")
    except Exception as e:
        print(f"    × {name} 失败: {e}")
    return cidrs

def fetch_badip_recent_days(days=7):
    """抓取 BadIP 最近 N 天的恶意 IP 列表"""
    cidrs = set()
    print(f"[-] 正在抓取 [BadIP]: 最近 {days} 天的数据 ...")
    
    today = datetime.datetime.today()
    
    for i in range(days):
        date_obj = today - timedelta(days=i)
        date_str = date_obj.strftime('%Y-%m-%d')
        url = f'https://www.badip.com/d-{date_str}.html'
        
        try:
            response = requests.get(url, headers=HEADERS, verify=False, timeout=30)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                table = soup.find('table')
                
                if table:
                    rows = table.find_all('tr')[1:]
                    for row in rows:
                        columns = row.find_all('td')
                        if columns and len(columns) > 1:
                            ip = columns[1].text.strip()
                            if ip:
                                normalized = normalize_cidr(ip)
                                if normalized:
                                    cidrs.add(normalized)
            else:
                pass
                
        except Exception:
            pass
            
    print(f"    √ BadIP 总计去重后获取 {len(cidrs)} 个 IP 段")
    return cidrs

def clean_blacklist_against_whitelist(black_set, white_set):
    """
    清洗黑名单：如果黑名单中的 IP 段属于白名单（是子网或相等），则从黑名单中移除。
    注意：如果白名单是黑名单的子集（例如 Black=/16, White=/24），我们保留黑名单。
    理由：拆分 /16 为非 /24 的网段会导致规则数量爆炸，这种情况交由 WAF 优先检查白名单逻辑处理。
    """
    print(f"[-] 正在进行冲突检测 (Whitelist Priority Check)...")
    
    # 将字符串集合转换为网络对象列表
    white_nets = []
    for w in white_set:
        try:
            white_nets.append(ipaddress.ip_network(w, strict=False))
        except: pass
        
    black_nets = []
    for b in black_set:
        try:
            black_nets.append(ipaddress.ip_network(b, strict=False))
        except: pass
        
    cleaned_black = []
    removed_count = 0
    
    # 优化：对于大规模列表，O(N*M) 会很慢，但考虑到白名单通常较小（几百条），
    # 而脚本是一次性运行，这里采用直接遍历。
    
    for b_net in black_nets:
        is_conflict = False
        for w_net in white_nets:
            # 判断逻辑：如果 黑名单段 是 白名单段 的子网 (subnet_of)
            # 或者两者相等
            # 例如: w_net=1.2.3.0/24, b_net=1.2.3.4 (b belong to w) -> REMOVE b
            if b_net.subnet_of(w_net):
                is_conflict = True
                break
        
        if is_conflict:
            removed_count += 1
            # print(f"    > 移除冲突黑名单: {str(b_net)} (属于白名单)")
        else:
            cleaned_black.append(str(b_net))
            
    print(f"    √ 冲突清洗完成: 移除了 {removed_count} 个被误报为黑名单的白名单 IP")
    return set(cleaned_black)

def save_to_file(filename, cidr_set):
    """保存数据到文件，始终覆盖，排序"""
    try:
        # 按网络地址排序
        sorted_cidrs = sorted(list(cidr_set), 
                             key=lambda x: ipaddress.ip_network(x).network_address)
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted_cidrs))
            f.write("\n")
        
        print(f"[SUCCESS] 已写入 {filename} (共 {len(cidr_set)} 条)")
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

    print(f"\n[-] 白名单收集完成: 原始 {len(white_ips_all)} 个IP段")
    print(f"[-] 开始合并白名单CIDR段...")
    
    # 合并白名单
    merged_white = merge_cidrs(white_ips_all)
    print(f"    √ 白名单合并后: {len(merged_white)} 个IP段")
    
    # 保存白名单
    save_to_file(FILE_WHITE, merged_white)
    print("-" * 50)

    # --- 2. 处理黑名单 ---
    black_ips_all = set()
    
    # 2.1 文本 源 (威胁情报/长亭 API)
    for name, url in BLACK_TEXT_SOURCES.items():
        black_ips_all.update(fetch_text_cidrs(name, url))
    
    # 2.2 FireHOL 源
    for name, url in FIREHOL_SOURCES.items():
        black_ips_all.update(fetch_text_cidrs(name, url))
    
    # 2.3 BadIP 源
    black_ips_all.update(fetch_badip_recent_days(days=7))
    
    print(f"\n[-] 黑名单收集完成: 原始 {len(black_ips_all)} 个IP段")
    print(f"[-] 开始合并黑名单CIDR段...")
    
    # 合并黑名单
    merged_black = merge_cidrs(black_ips_all)
    print(f"    √ 黑名单合并后: {len(merged_black)} 个IP段")
    
    # --- 3. 核心升级：黑白名单冲突清洗 ---
    # 使用合并后的白名单来清洗黑名单
    final_black = clean_blacklist_against_whitelist(merged_black, merged_white)
    
    # 保存最终的黑名单
    save_to_file(FILE_BLACK, final_black)
    print("-" * 50)
    
    print("\n=== 更新完成 ===")
    print(f"白名单文件: {FILE_WHITE} (优先级高)")
    print(f"黑名单文件: {FILE_BLACK} (已剔除白名单IP)")

if __name__ == "__main__":
    main()
