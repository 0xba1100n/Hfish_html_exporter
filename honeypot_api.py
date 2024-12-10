import os
import requests
import json
import html
from datetime import datetime
import urllib3
import argparse
from pypinyin import lazy_pinyin
import openai
from urllib.parse import unquote

# 配置
openai.api_base = "https://api.bianxieai.com/v1"
MALICIOUS_KEYWORDS = [
    "wget", "curl", "rm -rf", "chmod", "shell", "phpinfo", "system", "eval",
    "\.cgi", "\.sh", "/etc/passwd", "\.\./\.\./", "entity", "admin", "\<\?", "file://", "ftp", "echo"
]
LARGE_REQUEST_THRESHOLD = 500
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def log(message):
    """日志输出"""
    print(f"[INFO] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}")

def safe_filename(name):
    """将名称转换为拼音并去除非法字符"""
    sanitized_name = ''.join(lazy_pinyin(name))
    log(f"文件名转换: 原名: {name}, 转换后: {sanitized_name}")
    return sanitized_name

def write_html_header(file, title):
    """生成HTML页头"""
    file.write("<!DOCTYPE html>\n<html lang='zh-CN'>\n<head>\n")
    file.write("<meta charset='UTF-8'>\n")
    file.write(f"<title>{title}</title>\n")
    file.write("<style>\nbody { font-family: Arial, sans-serif; line-height: 1.6; padding: 20px; }\n")
    file.write("h1, h2 { color: #333; }\n")
    file.write("ul { list-style-type: none; padding: 0; }\n")
    file.write("li { margin-bottom: 15px; padding: 10px; border-bottom: 1px solid #ddd; }\n")
    file.write("strong { color: #555; }\npre { background-color: #f4f4f4; padding: 10px; border: 1px solid #ccc; overflow-x: auto; }\n")
    file.write("table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }\n")
    file.write("table, th, td { border: 1px solid #ddd; padding: 8px; }\nth { background-color: #f4f4f4; text-align: left; }\n</style>\n")
    file.write("</head>\n<body>\n")

def write_html_footer(file):
    """生成HTML页脚"""
    file.write("</body>\n</html>\n")

def decode_attack_info(data):
    """递归解码所有字符串"""
    if isinstance(data, str):
        return unquote(data)
    elif isinstance(data, list):
        return [decode_attack_info(item) for item in data]
    elif isinstance(data, dict):
        return {key: decode_attack_info(value) for key, value in data.items()}
    return data

def render_attack_info_html(attack_info):
    """将攻击信息以更可读的方式渲染为HTML"""
    attack_info = decode_attack_info(attack_info)  # 在渲染HTML之前解码
    if isinstance(attack_info, str):
        try:
            attack_info = json.loads(attack_info)
        except json.JSONDecodeError:
            return f"<pre>{html.escape(attack_info)}</pre>"

    html_content = "<table>\n"
    for key, value in attack_info.items():
        if isinstance(value, dict):
            value = json.dumps(value, ensure_ascii=False, indent=2)
        elif isinstance(value, list):
            value = ', '.join(map(str, value))
        html_content += f"<tr><th>{html.escape(key)}</th><td>{html.escape(str(value))}</td></tr>\n"
    html_content += "</table>\n"
    return html_content

def analyze_with_openai(attack_info, openai_api_key):
    """使用OpenAI API分析攻击信息"""
    openai.api_key = openai_api_key
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "你是一个用词精确的IoT蜜罐结果解释器"},
                {"role": "user", "content": f"请简单描述这次攻击：{json.dumps(attack_info, ensure_ascii=False)}"}
            ]
        )
        return response['choices'][0]['message']['content']
    except Exception as e:
        log(f"调用OpenAI API失败: {e}")
        return "分析失败"

def process_attack_info(detail, openai_api_key):
    """处理每条攻击信息，解码URL并检查恶意内容"""
    attack_info_raw = detail["attack_info"].strip()
    try:
        attack_info = json.loads(attack_info_raw)
    except json.JSONDecodeError:
        attack_info = {"raw_content": attack_info_raw}

    # 解码每个字段
    attack_info = decode_attack_info(attack_info)
    body = attack_info.get("body", "").lower()
    url_path = attack_info.get("url", "").lower()

    if any(keyword in body for keyword in MALICIOUS_KEYWORDS) or any(keyword in url_path for keyword in MALICIOUS_KEYWORDS):
        if openai_api_key:
            attack_info["analysis"] = analyze_with_openai(attack_info, openai_api_key)
        return True, attack_info
    return False, None

# 命令行参数解析
parser = argparse.ArgumentParser(description="从API获取攻击详情并生成HTML文件")
parser.add_argument('--api_key', required=True, help='API密钥')
parser.add_argument('--hfish_domain', required=True, help='Hfish的域名或IP地址')
parser.add_argument('--output_dir', required=True, help='HTML文件保存路径')
parser.add_argument('--openai_api_key', help='OpenAI API密钥')
args = parser.parse_args()

# 配置请求参数
url = f"https://{args.hfish_domain.strip()}:4433/api/v1/attack/detail?api_key={args.api_key}"
headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
os.makedirs(args.output_dir, exist_ok=True)

# 高风险请求存储
high_risk_requests = []
log("程序开始运行...")

try:
    for page_no in range(1, 100000):  # 分页处理
        log(f"正在处理第 {page_no} 页数据...")
        payload = {"page_no": page_no, "page_size": 100, "info_confirm": "1"}
        response = requests.post(url, headers=headers, json=payload, verify=False, timeout=30)
        response.raise_for_status()

        data = response.json()
        if data.get("response_code") != 0:
            log(f"第 {page_no} 页数据请求失败，跳过...")
            continue

        details = data.get("data", {}).get("detail_list", [])
        if not details:
            log(f"第 {page_no} 页无数据，结束分页。")
            break

        for detail in details:
            service_name = detail["service_name"]
            create_date = datetime.fromtimestamp(detail["create_time"]).strftime("%Y-%m-%d %H:%M:%S")
            is_high_risk, attack_info = process_attack_info(detail, args.openai_api_key)
            if is_high_risk:
                log(f"发现高风险请求: 服务={service_name}, 攻击IP={detail['attack_ip']}")
                high_risk_requests.append({
                    "service_name": service_name,
                    "attack_ip": detail["attack_ip"],
                    "ip_location": detail["ip_location"],
                    "create_time": create_date,
                    "attack_info": attack_info
                })

    log("正在生成高风险请求报告...")
    high_risk_requests.sort(key=lambda x: x["create_time"], reverse=True)
    report_path = os.path.join(args.output_dir, "high_risk_requests.html")
    with open(report_path, "w", encoding="utf-8") as report_file:
        write_html_header(report_file, "高风险请求报告")
        report_file.write("<h1>高风险请求报告</h1><ul>")
        for req in high_risk_requests:
            report_file.write(f"<li><p><strong>服务:</strong> {html.escape(req['service_name'])}</p>")
            report_file.write(f"<p><strong>攻击IP:</strong> {html.escape(req['attack_ip'])}</p>")
            report_file.write(f"<p><strong>时间:</strong> {req['create_time']}</p>")
            report_file.write(render_attack_info_html(req['attack_info']))
            report_file.write("</li>")
        report_file.write("</ul>")
        write_html_footer(report_file)
    log(f"报告生成成功: {report_path}")

except Exception as e:
    log(f"脚本运行失败: {e}")
finally:
    log("程序运行结束。")
