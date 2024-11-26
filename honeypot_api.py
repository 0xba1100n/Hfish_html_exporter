import os
import requests
import json
from datetime import datetime
import urllib3
import html
import argparse
from pypinyin import lazy_pinyin

# 忽略 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def safe_filename(name):
    """将名称转为拼音，并去除非法字符"""
    return ''.join(lazy_pinyin(name))

# 恶意关键字列表
MALICIOUS_KEYWORDS = [
    "wget", "curl", "rm -rf", "chmod", "powershell", "phpinfo", "system(", "ping", "nslookup","tracert","traceroute",
    ".cgi", ".sh", "/etc/passwd","/etc/shadow","../../","entity","admin","<?","file://","ftp"#,"login", "logon"
]

"""
- wget、curl：常用于下载恶意文件或脚本。    
- rm -rf：用于删除文件或目录，可能导致破坏性操作。    
- chmod：用于修改权限，可能用于提升权限或执行恶意文件。    
- powershell：Windows系统中强大的脚本工具，常用于渗透测试或恶意脚本执行。    
- system(：PHP中执行系统命令的函数，常见于命令注入攻击。
- phpinfo：PHP内置函数，攻击者可能利用它获取服务器配置信息。    
- /etc/passwd、/etc/shadow：Linux系统的敏感文件路径，读取这些文件通常意味着目录遍历攻击或权限提升尝试。    
- ../../：路径遍历攻击的常见模式，尝试访问服务器的敏感文件。
- ping、nslookup、tracert、traceroute：用于网络侦察，可能是攻击者探测服务器的网络环境或路径。
- .cgi：CGI脚本文件，在一些老旧系统中容易被利用。    
- .sh：表示Shell脚本文件，可能用于执行恶意代码。    
- entity：与XML实体注入相关，可能导致XXE攻击。    
- admin、login、logon：针对管理面板或登录页面的暴力破解或未授权访问尝试。目前只使用了admin,开启另外两个可能有意想不到的收获
- "<?"：写入某种php木马的行为
等等
"""


# 请求大小阈值（字节数）
LARGE_REQUEST_THRESHOLD = 500

# 头图HTML代码
HEADER_IMAGE_HTML = '''
<img src="https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20241122202810.png" alt="ba1100n Banner" style="width:100%; margin-bottom: 20px;">
'''

# 全局样式
GLOBAL_STYLE = '''
<style>
    body {
        font-size: 14px;
        font-family: Arial, sans-serif;
        margin: 0;
        padding: 0;
        line-height: 1.6;
    }
    pre {
        font-family: monospace;
        background-color: #f4f4f4;
        padding: 10px;
        overflow-x: auto;
        border: 1px solid #ddd;
    }
    button {
        font-size: 14px;
        padding: 10px;
        margin: 5px 0;
        border: none;
        background-color: #007bff;
        color: white;
        cursor: pointer;
    }
    button:hover {
        background-color: #0056b3;
    }
    h1 {
        font-size: 20px;
        color: #333;
        margin-bottom: 20px;
    }
</style>
'''

# 解析命令行参数
parser = argparse.ArgumentParser(description="从API获取攻击详情并生成按蜜罐种类和日期分组的HTML文件，并记录可能的高价值exp")
parser.add_argument('--api_key', required=True, help='API密钥')
parser.add_argument('--hfish_domain', required=True, help='Hfish的域名或IP地址')
parser.add_argument('--output_dir', required=True, help='HTML文件保存路径')
args = parser.parse_args()

api_key = args.api_key
hfish_domain_or_ip = args.hfish_domain.strip()
output_dir = args.output_dir.strip()

# 请求 URL 和通用请求头
url = f"https://{hfish_domain_or_ip}:4433/api/v1/attack/detail?api_key={api_key}"
headers = {
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0'
}

# 验证路径是否存在
if not os.path.exists(output_dir):
    os.makedirs(output_dir)
    print(f"路径 {output_dir} 不存在，已创建。")
else:
    print(f"路径 {output_dir} 已存在，将保存HTML文件到该目录。")

# 存储每种蜜罐种类和日期的攻击详情
service_date_data = {}
# 存储“可能的高价值exp”相关请求的全局列表
high_value_exp_requests = []

try:
    for page_no in range(1, 21):  # 遍历 1 到 20 页
        payload = {
            "start_time": 0,
            "end_time": 0,
            "page_no": page_no,
            "page_size": 100,
            "client_id": [],
            "service_name": [],
            "info_confirm": "1"
        }
        response = requests.post(url, headers=headers, json=payload, verify=False, timeout=10)

        if response.status_code != 200:
            print(f"Page {page_no} 请求失败，状态码 {response.status_code}。")
            break
        response.encoding = 'utf-8'
        data = response.json()
        if data.get("response_code") != 0:
            print(f"API 在第 {page_no} 页返回错误: {data.get('verbose_msg')}")
            break

        detail_list = data["data"]["detail_list"]
        if not detail_list:
            print(f"第 {page_no} 页没有数据，结束循环。")
            break

        for detail in detail_list:
            service_name = detail["service_name"]
            create_date = datetime.fromtimestamp(detail["create_time"]).strftime("%Y-%m-%d")  # 提取日期

            if service_name not in service_date_data:
                service_date_data[service_name] = {}

            if create_date not in service_date_data[service_name]:
                service_date_data[service_name][create_date] = []

            service_date_data[service_name][create_date].append(detail)

            # 检测可能的高价值exp关键字和大数据包
            attack_info_raw = detail["attack_info"].strip()
            try:
                attack_info = json.loads(attack_info_raw)
            except json.JSONDecodeError:
                attack_info = {"raw_content": attack_info_raw}

            body = attack_info.get("body", "").lower()
            url_path = attack_info.get("url", "").lower()
            body_length = len(body)
            url_length = len(url_path)

            # 检查是否命中恶意关键字
            if (
                any(keyword in body for keyword in MALICIOUS_KEYWORDS) or 
                any(keyword in url_path for keyword in MALICIOUS_KEYWORDS)
            ) or (
                body_length > LARGE_REQUEST_THRESHOLD or url_length > LARGE_REQUEST_THRESHOLD
            ):
                high_value_exp_requests.append({
                    "service_name": service_name,
                    "attack_ip": detail["attack_ip"],
                    "ip_location": detail["ip_location"],
                    "create_time": datetime.fromtimestamp(detail["create_time"]).strftime("%Y-%m-%d %H:%M:%S"),
                    "method": attack_info.get("method", "").upper(),
                    "url": url_path,
                    "body": body,
                    "body_length": body_length,
                    "url_length": url_length
                })

    # 为每种蜜罐种类生成按日期分组的HTML页面
    for service_name, date_data in service_date_data.items():
        # 对蜜罐种类名进行拼音转换，生成安全路径
        encoded_service_name = safe_filename(service_name)
        service_dir = os.path.join(output_dir, encoded_service_name)
        if not os.path.exists(service_dir):
            os.makedirs(service_dir)

        # 生成该蜜罐种类的日期索引页面
        index_file_path = os.path.join(service_dir, "index.html")
        with open(index_file_path, "w", encoding="utf-8") as index_file:
            index_file.write(f"<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>{html.escape(service_name)} 索引</title>{GLOBAL_STYLE}</head><body>")
            index_file.write(HEADER_IMAGE_HTML)  # 插入头图
            index_file.write(f"<h1>{html.escape(service_name)} 蜜罐日期索引</h1>")
            # 按日期从新到旧排序
            for create_date in sorted(date_data.keys(), reverse=True):  # reverse=True 使日期降序排列
                index_file.write(f"<button onclick=\"window.location.href='{create_date}.html'\">{create_date}</button><br>")
            index_file.write("</body></html>")

    # 生成“可能的高价值exp”页面
    high_value_exp_file_path = os.path.join(output_dir, "high_value_exp.html")
    with open(high_value_exp_file_path, "w", encoding="utf-8") as high_value_exp_file:
        high_value_exp_file.write(f"<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>可能的高价值exp</title>{GLOBAL_STYLE}</head><body>")
        high_value_exp_file.write(HEADER_IMAGE_HTML)  # 插入头图
        high_value_exp_file.write("<h1>可能的高价值exp</h1>")
        for request in high_value_exp_requests:
            high_value_exp_file.write(f"<div style='border:1px solid black; margin:10px; padding:10px;'>")
            high_value_exp_file.write(f"<p><strong>蜜罐种类:</strong> {html.escape(request['service_name'])}</p>")
            high_value_exp_file.write(f"<p><strong>踩罐源IP:</strong> {html.escape(request['attack_ip'])}</p>")
            high_value_exp_file.write(f"<p><strong>IP归属地:</strong> {html.escape(request['ip_location'])}</p>")
            high_value_exp_file.write(f"<p><strong>时间:</strong> {html.escape(request['create_time'])}</p>")
            high_value_exp_file.write("<pre>")
            high_value_exp_file.write(html.escape(f"{request['method']} {request['url']}\n"))
            high_value_exp_file.write(html.escape(f"\n{request['body']}"))
            high_value_exp_file.write("</pre>")
            high_value_exp_file.write("</div>")
        high_value_exp_file.write("</body></html>")

    # 生成总索引页面
    index_file_path = os.path.join(output_dir, "index.html")
    with open(index_file_path, "w", encoding="utf-8") as index_file:
        index_file.write(f"<html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'><title>蜜罐种类索引</title>{GLOBAL_STYLE}</head><body>")
        index_file.write(HEADER_IMAGE_HTML)  # 插入头图
        index_file.write("<h1>蜜罐结果筛选</h1>")  # 添加筛选标题
        index_file.write(f"<button onclick=\"window.location.href='high_value_exp.html'\">可能的高价值exp</button><br><hr>")
        index_file.write("<h2>各型蜜罐结果（已按日期分类）</h2>")  # 插入新标题
        for service_name in service_date_data.keys():
            encoded_service_name = safe_filename(service_name)
            index_file.write(f"<button onclick=\"window.location.href='{encoded_service_name}/index.html'\">{html.escape(service_name)}</button><br>")
        index_file.write("</body></html>")

    print(f"HTML 文件按蜜罐种类和日期生成，并保存到目录 {output_dir}。索引页面已生成。“可能的高价值exp”页面已生成。")

except requests.exceptions.RequestException as e:
    print(f"请求失败: {e}")
except Exception as e:
    print(f"发生错误: {e}")
