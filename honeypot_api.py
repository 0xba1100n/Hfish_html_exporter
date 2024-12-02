import os 
import requests
import json
import html
from datetime import datetime
import urllib3
import argparse
from pypinyin import lazy_pinyin
import openai  # 导入OpenAI模块

openai.api_base = "https://api.bianxieai.com/v1"
ZH_CN = True
# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def safe_filename(name):
    """将名称转换为拼音并去除非法字符"""
    sanitized_name = ''.join(lazy_pinyin(name))
    print(f"[调试] 文件名转换: 原名: {name}, 转换后: {sanitized_name}")
    return sanitized_name

def write_html_header(file, title):
    """生成HTML页头"""
    file.write("<!DOCTYPE html>\n<html lang='zh-CN'>\n<head>\n")
    file.write("<meta charset='UTF-8'>\n")
    file.write(f"<title>{title}</title>\n")
    file.write("<style>\n")
    file.write("body { font-family: Arial, sans-serif; line-height: 1.6; padding: 20px; }\n")
    file.write("h1, h2 { color: #333; }\n")
    file.write("ul { list-style-type: none; padding: 0; }\n")
    file.write("li { margin-bottom: 15px; padding: 10px; border-bottom: 1px solid #ddd; }\n")
    file.write("strong { color: #555; }\n")
    file.write("pre { background-color: #f4f4f4; padding: 10px; border: 1px solid #ccc; overflow-x: auto; }\n")
    file.write("table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }\n")
    file.write("table, th, td { border: 1px solid #ddd; padding: 8px; }\n")
    file.write("th { background-color: #f4f4f4; text-align: left; }\n")
    file.write("</style>\n")
    file.write("</head>\n<body>\n")

def write_html_footer(file):
    """生成HTML页脚"""
    file.write("</body>\n</html>\n")

def render_attack_info_html(attack_info):
    """将攻击信息以更可读的方式渲染为HTML"""
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
    """使用OpenAI API分析攻击信息的细节"""
    openai.api_key = openai_api_key
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "你是一个用词精确的iot蜜罐结果解释器"},
                {"role": "user", "content": f"60个字以内，请简单描述一下这次攻击运用什么手法，攻击了哪个组件或者文件，如果有投递持久化用的东西比如投递木马或者sh文件，给出攻击者投递的外部文件下载路径，否则不需要给下载地址 {json.dumps(attack_info, ensure_ascii=False)}"}
            ]
        )
        analysis_result = response['choices'][0]['message']['content']
        return analysis_result
    except Exception as e:
        print(f"[错误] 调用OpenAI API时出错: {e}")
        return "分析失败: 无法调用OpenAI API"

# 恶意关键字列表
MALICIOUS_KEYWORDS = [
    "wget", "curl", "rm -rf", "chmod", "shell", "phpinfo", "system", "eval",
    "\.cgi", "\.sh", "/etc/passwd", "\.\./\.\./", "entity", "admin", "\<\?", "file://", "ftp"
]

# 请求大小阈值（字节数）
LARGE_REQUEST_THRESHOLD = 500

# 解析命令行参数
parser = argparse.ArgumentParser(description="从API获取攻击详情并生成按蜜罐种类和日期分组的HTML文件，并记录包含高风险字符的蜜罐抓取结果")
parser.add_argument('--api_key', required=True, help='API密钥')
parser.add_argument('--hfish_domain', required=True, help='Hfish的域名或IP地址')
parser.add_argument('--output_dir', required=True, help='HTML文件保存路径')
parser.add_argument('--openai_api_key', help='OpenAI API密钥')
args = parser.parse_args()

api_key = args.api_key
hfish_domain_or_ip = args.hfish_domain.strip()
output_dir = args.output_dir.strip()
openai_api_key = args.openai_api_key.strip() if args.openai_api_key else None

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
# 存储“包含高风险字符的蜜罐抓取结果”相关请求的全局列表
high_risk_requests = []

try:
    for page_no in range(1, 100000):  # 扩展分页范围，处理更多数据
        payload = {
            "start_time": 0,
            "end_time": 0,
            "page_no": page_no,
            "page_size": 100,
            "client_id": [],
            "service_name": [],
            "info_confirm": "1"
        }
        response = requests.post(url, headers=headers, json=payload, verify=False, timeout=30)
        response.raise_for_status()

        response.encoding = 'utf-8'
        data = response.json()

        if data.get("response_code") != 0:
            print(f"[警告] API 在第 {page_no} 页返回错误: {data.get('verbose_msg')}")
            continue

        detail_list = data.get("data", {}).get("detail_list", [])
        if not detail_list:
            print(f"[信息] 第 {page_no} 页没有数据，结束循环。")
            break

        print(f"[调试] 第 {page_no} 页包含 {len(detail_list)} 条数据。")

        for detail in detail_list:
            try:
                service_name = detail["service_name"]
                create_date = datetime.fromtimestamp(detail["create_time"]).strftime("%Y-%m-%d %H:%M:%S")

                if service_name not in service_date_data:
                    service_date_data[service_name] = {}

                if create_date[:10] not in service_date_data[service_name]:
                    service_date_data[service_name][create_date[:10]] = []

                service_date_data[service_name][create_date[:10]].append(detail)

                # 检测包含高风险字符的请求
                attack_info_raw = detail["attack_info"].strip()
                try:
                    attack_info = json.loads(attack_info_raw)
                except json.JSONDecodeError:
                    print(f"[警告] 攻击详情解析 JSON 失败，原始内容: {attack_info_raw}")
                    attack_info = {"raw_content": attack_info_raw}

                body = attack_info.get("body", "").lower()
                url_path = attack_info.get("url", "").lower()
                body_length = len(body)
                url_length = len(url_path)

                if (
                    any(keyword in body for keyword in MALICIOUS_KEYWORDS) or
                    any(keyword in url_path for keyword in MALICIOUS_KEYWORDS) or
                    body_length > LARGE_REQUEST_THRESHOLD or url_length > LARGE_REQUEST_THRESHOLD
                ):
                    # 使用OpenAI API分析攻击详情，前提是提供了openai_api_key
                    if openai_api_key:
                        analysis_result = analyze_with_openai(attack_info, openai_api_key)
                        attack_info["analysis"] = analysis_result
                    else:
                        print("未提供OpenAI API密钥，因此不进行分析。")

                    print(f"服务名: {service_name}, 攻击IP: {detail['attack_ip']}, IP位置: {detail['ip_location']}, 时间: {create_date}")
                    if (
                        any(keyword in body for keyword in MALICIOUS_KEYWORDS) or
                        any(keyword in url_path for keyword in MALICIOUS_KEYWORDS)
                    ):
                        print("是恶意攻击请求")
                        # 描述攻击流程
                        print("攻击流程: " + render_attack_info_html(attack_info))
                        # 提取恶意脚本下载路径（如果有）
                        malicious_script_url = attack_info.get("malicious_script_url")
                        if malicious_script_url:
                            print(f"evil url:{malicious_script_url}")
                        else:
                            print("evil url:未检测到恶意脚本的下载路径")
                    else:
                        print("不是恶意攻击请求")
                    
                    high_risk_requests.append({
                        "service_name": service_name,
                        "attack_ip": detail["attack_ip"],
                        "ip_location": detail["ip_location"],
                        "create_time": create_date,
                        "attack_info": attack_info
                    })
                    print(f"[包含高风险字符的蜜罐抓取结果] 服务名: {service_name}, 攻击IP: {detail['attack_ip']}，时间: {create_date}")

            except Exception as e:
                print(f"[错误] 写入数据时发生异常: {e}")
                continue

    # 输出 service_date_data 调试信息
    for service_name, date_data in service_date_data.items():
        print(f"[调试] 服务名: {service_name}")
        for date, details in date_data.items():
            print(f"[调试] 日期: {date} 包含 {len(details)} 条记录")

    # 对高风险请求按时间从最新到最旧进行排序
    high_risk_requests.sort(key=lambda x: x["create_time"], reverse=True)

    # 生成包含高风险字符的蜜罐抓取结果的 HTML 文件
    high_risk_path = os.path.join(output_dir, "high_risk_requests.html")
    print(f"[调试] 准备生成包含高风险字符的蜜罐抓取结果文件: {high_risk_path}")
    with open(high_risk_path, "w", encoding="utf-8") as high_risk_file:
        write_html_header(high_risk_file, "包含高风险字符的蜜罐抓取结果")
        high_risk_file.write("<h1>包含高风险字符的蜜罐抓取结果</h1>\n<ul>\n")
        for exp in high_risk_requests:
            high_risk_file.write("<li>\n")
            high_risk_file.write(f"<p><strong>服务名:</strong> {html.escape(exp['service_name'])}</p>\n")
            high_risk_file.write(f"<p><strong>攻击IP:</strong> {html.escape(exp['attack_ip'])}</p>\n")
            high_risk_file.write(f"<p><strong>IP位置:</strong> {html.escape(exp['ip_location'])}</p>\n")
            high_risk_file.write(f"<p><strong>时间:</strong> {exp['create_time']}</p>\n")
            high_risk_file.write(render_attack_info_html(exp['attack_info']))
            high_risk_file.write("</li>\n")
        high_risk_file.write("</ul>\n")
        write_html_footer(high_risk_file)
    print(f"[调试] 包含高风险字符的蜜罐抓取结果文件生成成功: {high_risk_path}")

except Exception as e:
    print(f"[严重错误] 脚本执行过程中发生异常: {e}")
finally:
    print("[完成] 数据处理结束。")
