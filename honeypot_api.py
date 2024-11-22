import os
import requests
import json
from datetime import datetime
import urllib3
import html
import argparse

# 忽略 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 解析命令行参数
parser = argparse.ArgumentParser(description="从API获取攻击详情并生成HTML文件")
parser.add_argument('--api_key', required=True, help='API密钥')
parser.add_argument('--hfish_domain', required=True, help='Hfish的域名或IP地址')
parser.add_argument('--output_dir', required=True, help='HTML文件保存路径')
args = parser.parse_args()

api_key = args.api_key
hfish_domain_or_ip = args.hfish_domain.strip()  # 获取 HFISH平台 域名或 IP 地址
output_dir = args.output_dir.strip()

# 请求 URL 和通用请求头
url = f"https://{hfish_domain_or_ip}:4433/api/v1/attack/detail?api_key={api_key}"

headers = {
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30'
}

# 验证路径是否存在，如果不存在则创建
if not os.path.exists(output_dir):
    os.makedirs(output_dir)
    print(f"路径 {output_dir} 不存在，已创建。")
else:
    print(f"路径 {output_dir} 已存在，将保存HTML文件到该目录。")

# 统计访问次数
ip_access_count = {}

# 遍历 page_no
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
        response.encoding = 'utf-8'  # 强制将编码设置为 UTF-8，避免乱码问题
        data = response.json()
        if data.get("response_code") != 0:
            print(f"API 在第 {page_no} 页返回错误: {data.get('verbose_msg')}")
            break

        # 获取攻击详情列表
        detail_list = data["data"]["detail_list"]
        if not detail_list:
            print(f"第 {page_no} 页没有数据，结束循环。")
            break

        # 生成单页 HTML，倒序输出
        page_file = os.path.join(output_dir, f"page_{page_no}.html")
        with open(page_file, "w", encoding="utf-8") as file:
            file.write(f"<html><head><meta charset='utf-8'><title>IOT蜜罐返回结果 - Page {page_no}</title></head><body>")
            file.write("<img src='https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20241122202810.png' alt='Banner' style='width:100%;'>")
            file.write(f"<h1>IOT蜜罐被访问记录（不记录扫描，仅记录访问）</h1>")

            for detail in reversed(detail_list):
                attack_info_raw = detail["attack_info"].strip()
                try:
                    attack_info = json.loads(attack_info_raw)
                except json.JSONDecodeError:
                    # 如果无法解析为 JSON，直接使用原始的 attack_info
                    print(f"Raw attack_info content: {attack_info_raw}")  # 调试信息
                    attack_info = {"raw_content": attack_info_raw}
                
                # 获取请求的关键信息
                attack_ip = html.escape(detail["attack_ip"])
                ip_location = html.escape(detail["ip_location"])
                create_time = datetime.fromtimestamp(detail["create_time"]).strftime("%Y-%m-%d %H:%M:%S")

                request_method = attack_info.get("method", "").upper()
                request_url = attack_info.get("url", "")
                body = attack_info.get("body", "")

                # 简化处理 "GET /" 且 "body is empty" 的情况
                if request_method == "GET" and request_url == "/" and not body:
                    # 统计访问次数
                    if attack_ip not in ip_access_count:
                        ip_access_count[attack_ip] = 0
                    ip_access_count[attack_ip] += 1
                    continue  # 跳过详细记录，直接统计访问次数

                # 如果 attack_info 中 body 为空，并且没有原始内容，则跳过此记录
                if not body:
                    attack_info["body"] = "body is empty"

                # 正常输出详细信息
                service_name = html.escape(detail["service_name"])
                try:
                    service_name = bytes(service_name, 'utf-8').decode('utf-8')
                except (UnicodeDecodeError, ValueError) as e:
                    print(f"解码失败: {e}, 保留原始值: {service_name}")

                # 写入单个请求的 HTML 部分
                file.write(f"<div style='border:1px solid black; margin:10px; padding:10px;'>")
                file.write(f"<p><strong>蜜罐种类:</strong> {service_name}</p>")
                file.write(f"<p><strong>踩罐源IP:</strong> {attack_ip}</p>")
                file.write(f"<p><strong>IP归属地:</strong> {ip_location}</p>")
                file.write(f"<p><strong>时间:</strong> {create_time}</p>")
                #file.write(f"<p><strong>返回状态码:</strong> {html.escape(str(attack_info.get('status_code', '')))}</p>")
                file.write("<pre>")
                file.write(html.escape(f"{request_method} {request_url}\n"))
                if body:
                    file.write(html.escape(f"\n{body}"))
                file.write("</pre>")
                file.write("</div>")

            # 添加上一页和下一页链接
            if page_no > 1:
                file.write(f"<a href='page_{page_no - 1}.html'>上一页</a> ")
            if page_no < 20:
                file.write(f"<a href='page_{page_no + 1}.html'>下一页</a>")

            file.write("</body></html>")

    # 生成总索引 HTML
    index_file_path = os.path.join(output_dir, "index.html")
    with open(index_file_path, "w", encoding="utf-8") as index_file:
        index_file.write("<html><head><meta charset='utf-8'><title>Index</title></head><body>")
        index_file.write("<h1>Attack Detail Pages</h1>")
        for i in range(1, page_no + 1):
            index_file.write(f"<button onclick=\"window.location.href='page_{i}.html'\">Page {i}</button><br>")
        index_file.write("</body></html>")

    # 输出访问统计信息
    stats_file_path = os.path.join(output_dir, "access_stats.txt")
    with open(stats_file_path, "w", encoding="utf-8") as stats_file:
        stats_file.write("访问统计:\n")
        for ip, count in ip_access_count.items():
            stats_file.write(f"{ip} : {count} 次访问\n")

    print(f"HTML 文件已生成并保存到目录 {output_dir}。访问统计已保存到 {stats_file_path}。")

except requests.exceptions.RequestException as e:
    print(f"请求失败: {e}")
except Exception as e:
    print(f"发生错误: {e}")
