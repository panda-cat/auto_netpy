import json
import os
import re
import requests


def fetch_json(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching {url}: {str(e)}")
        raise


def process_json_file(data, cdn_domain, asset_url):
    """
    处理目录数据并生成 aria2c 下载列表
    将 cdn_domain 和 asset_url 作为参数传入，避免重复请求网络接口
    """
    http_links = []
    for item in data.get('m_InternalIds', []):
        if isinstance(item, str) and item.startswith('http://file.sg-arts.com'):
            http_links.append(item)

    new_prefix = f"{cdn_domain}/{asset_url}"
    old_prefix = 'http://file.sg-arts.com/bundle/tkfm/development'

    processed_links = []
    for link in http_links:
        new_link = link.replace(old_prefix, new_prefix)
        relative_path = link[len(old_prefix):]

        output = {
            'url': new_link,
            'out': f'download{relative_path}'
        }
        processed_links.append(output)

    # 写入到 txbm.txt 文件
    with open('txbm.txt', 'w', encoding='utf-8') as out_file:
        for item in processed_links:
            out_file.write(f"{item['url']}\n  out={item['out']}\n")

    print(f"已处理并保存 {len(processed_links)} 个链接到 txbm.txt")
    
    # 使用 shlex.quote 或双引号包裹带中文字符的路径，防止系统终端解析错误
    os.system('aria2c -i txbm.txt -j 32 -s 16 -x 16 --check-certificate=false --dir="resdownload/天下布魔"')


def main():
    try:
        # 1. 获取基础 CDN 域名
        cdn_info = fetch_json("https://cdn-aussetzen-tkfm.pinkcore.net/")
        cdn_domain = cdn_info['cdn_domain']
        
        # 2. 获取最新构建版本号
        version_info = fetch_json(f"{cdn_domain}/version/tkfm-version-1101.json")
        latest_build_number = version_info['latest_build_number']
        
        # 3. 获取配置信息（包含资源路径和资源清单文件名）
        config_info = fetch_json(f"{cdn_domain}/config/tkfm-config-1101-{latest_build_number}.json")
        asset_url = config_info['asset_url']
        catalog_name = config_info['catalog_name']
        
        # 4. 获取完整的 Android 资源清单 JSON
        catalog_url = f"{cdn_domain}/{asset_url}/Android/{catalog_name}.json"
        catalog_data = fetch_json(catalog_url)
        
        # 5. 开始解析并下载（传入已获取的 cdn_domain 和 asset_url）
        process_json_file(catalog_data, cdn_domain, asset_url)

    except Exception as e:
        print(f"发生错误: {str(e)}")


if __name__ == "__main__":
    main()
