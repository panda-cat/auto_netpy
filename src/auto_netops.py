import re
import os
from typing import Dict, List, Tuple
import pandas as pd
from datetime import datetime

class NetworkConfigParser:
    """网络设备配置解析器"""
    
    def __init__(self):
        # 定义各厂商的识别模式
        self.vendor_patterns = {
            'Cisco': {
                'identifier': [r'cisco', r'IOS', r'Cisco IOS'],
                'version': r'Version\s+([^\s,]+)',
                'model': r'cisco\s+(\S+)\s+\(',
                'hostname': r'hostname\s+(\S+)'
            },
            'Huawei': {
                'identifier': [r'Huawei', r'VRP', r'Versatile Routing Platform'],
                'version': r'VRP.*Version\s+([^\s\)]+)',
                'model': r'Huawei\s+(\S+)\s+',
                'hostname': r'sysname\s+(\S+)'
            },
            'H3C': {
                'identifier': [r'H3C', r'Comware'],
                'version': r'Version\s+([^\s,]+)',
                'model': r'H3C\s+(\S+)',
                'hostname': r'sysname\s+(\S+)'
            },
            'Juniper': {
                'identifier': [r'Juniper', r'JUNOS'],
                'version': r'JUNOS.*\s+$$([^$$]+)\]',
                'model': r'Model:\s+(\S+)',
                'hostname': r'host-name\s+(\S+)'
            }
        }
        
        # 接口配置模式
        self.interface_patterns = {
            'Cisco': {
                'interface': r'interface\s+([\w/]+)',
                'access': r'switchport\s+mode\s+access',
                'trunk': r'switchport\s+mode\s+trunk',
                'access_vlan': r'switchport\s+access\s+vlan\s+(\d+)',
                'trunk_vlan': r'switchport\s+trunk\s+allowed\s+vlan\s+([\d,\-]+)'
            },
            'Huawei': {
                'interface': r'interface\s+([\w/]+)',
                'access': r'port\s+link-type\s+access',
                'trunk': r'port\s+link-type\s+trunk',
                'access_vlan': r'port\s+default\s+vlan\s+(\d+)',
                'trunk_vlan': r'port\s+trunk\s+allow-pass\s+vlan\s+([\d\s]+)'
            },
            'H3C': {
                'interface': r'interface\s+([\w/]+)',
                'access': r'port\s+link-type\s+access',
                'trunk': r'port\s+link-type\s+trunk',
                'access_vlan': r'port\s+access\s+vlan\s+(\d+)',
                'trunk_vlan': r'port\s+trunk\s+permit\s+vlan\s+([\d\s]+)'
            }
        }
    
    def detect_vendor(self, content: str) -> str:
        """检测设备厂商"""
        content_lower = content.lower()
        for vendor, patterns in self.vendor_patterns.items():
            for identifier in patterns['identifier']:
                if re.search(identifier.lower(), content_lower):
                    return vendor
        return 'Unknown'
    
    def extract_device_info(self, content: str, vendor: str) -> Dict:
        """提取设备基本信息"""
        info = {
            'vendor': vendor,
            'version': 'Unknown',
            'model': 'Unknown',
            'hostname': 'Unknown'
        }
        
        if vendor in self.vendor_patterns:
            patterns = self.vendor_patterns[vendor]
            
            # 提取版本
            version_match = re.search(patterns['version'], content, re.IGNORECASE)
            if version_match:
                info['version'] = version_match.group(1)
            
            # 提取型号
            model_match = re.search(patterns['model'], content, re.IGNORECASE)
            if model_match:
                info['model'] = model_match.group(1)
            
            # 提取主机名
            hostname_match = re.search(patterns['hostname'], content, re.IGNORECASE)
            if hostname_match:
                info['hostname'] = hostname_match.group(1)
        
        return info
    
    def parse_interfaces(self, content: str, vendor: str) -> List[Dict]:
        """解析接口配置"""
        interfaces = []
        
        if vendor not in self.interface_patterns:
            return interfaces
        
        patterns = self.interface_patterns[vendor]
        
        # 按接口分割配置
        interface_blocks = re.split(patterns['interface'], content)
        
        for i in range(1, len(interface_blocks), 2):
            interface_name = interface_blocks[i]
            interface_config = interface_blocks[i + 1] if i + 1 < len(interface_blocks) else ""
            
            # 判断接口类型
            port_mode = 'Unknown'
            vlan_info = ''
            
            if re.search(patterns['access'], interface_config):
                port_mode = 'Access'
                vlan_match = re.search(patterns['access_vlan'], interface_config)
                if vlan_match:
                    vlan_info = f"VLAN {vlan_match.group(1)}"
            elif re.search(patterns['trunk'], interface_config):
                port_mode = 'Trunk'
                vlan_match = re.search(patterns['trunk_vlan'], interface_config)
                if vlan_match:
                    vlan_info = f"VLANs: {vlan_match.group(1)}"
            
            # 判断接口状态
            shutdown = bool(re.search(r'shutdown', interface_config))
            status = 'Down' if shutdown else 'Up'
            
            interfaces.append({
                'interface': interface_name,
                'port_mode': port_mode,
                'vlan_info': vlan_info,
                'status': status
            })
        
        return interfaces
    
    def parse_config_file(self, file_path: str) -> Dict:
        """解析配置文件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(file_path, 'r', encoding='gbk') as f:
                content = f.read()
        
        # 检测厂商
        vendor = self.detect_vendor(content)
        
        # 提取设备信息
        device_info = self.extract_device_info(content, vendor)
        
        # 解析接口
        interfaces = self.parse_interfaces(content, vendor)
        
        # 统计信息
        total_ports = len(interfaces)
        access_ports = sum(1 for i in interfaces if i['port_mode'] == 'Access')
        trunk_ports = sum(1 for i in interfaces if i['port_mode'] == 'Trunk')
        
        return {
            'file_name': os.path.basename(file_path),
            'device_info': device_info,
            'statistics': {
                'total_ports': total_ports,
                'access_ports': access_ports,
                'trunk_ports': trunk_ports,
                'unknown_ports': total_ports - access_ports - trunk_ports
            },
            'interfaces': interfaces
        }
    
    def export_to_excel(self, results: List[Dict], output_file: str = 'network_config_analysis.xlsx'):
        """导出到Excel文件"""
        with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
            # 汇总表
            summary_data = []
            for result in results:
                summary_data.append({
                    '文件名': result['file_name'],
                    '设备厂商': result['device_info']['vendor'],
                    '设备型号': result['device_info']['model'],
                    '系统版本': result['device_info']['version'],
                    '主机名': result['device_info']['hostname'],
                    '总端口数': result['statistics']['total_ports'],
                    'Access端口数': result['statistics']['access_ports'],
                    'Trunk端口数': result['statistics']['trunk_ports'],
                    '未知类型端口数': result['statistics']['unknown_ports']
                })
            
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='设备汇总', index=False)
            
            # 为每个设备创建详细表
            for idx, result in enumerate(results):
                if result['interfaces']:
                    interface_df = pd.DataFrame(result['interfaces'])
                    sheet_name = f"{result['device_info']['hostname'][:20]}_{idx}"
                    interface_df.to_excel(writer, sheet_name=sheet_name, index=False)
        
        print(f"**分析完成！结果已保存到: {output_file}**")

def main():
    """主函数"""
    parser = NetworkConfigParser()
    
    # 配置文件目录
    config_dir = input("请输入配置文件目录路径 (默认为当前目录): ").strip()
    if not config_dir:
        config_dir = "."
    
    # 查找所有配置文件
    config_files = []
    for file in os.listdir(config_dir):
        if file.endswith(('.txt', '.log', '.conf')):
            config_files.append(os.path.join(config_dir, file))
    
    if not config_files:
        print("**未找到配置文件！**")
        return
    
    print(f"**找到 {len(config_files)} 个配置文件**")
    
    # 解析所有配置文件
    results = []
    for file_path in config_files:
        print(f"正在处理: {file_path}")
        try:
            result = parser.parse_config_file(file_path)
            results.append(result)
        except Exception as e:
            print(f"处理文件 {file_path} 时出错: {e}")
    
    # 导出结果
    if results:
        output_file = f"network_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        parser.export_to_excel(results, output_file)
    else:
        print("**没有成功解析的配置文件！**")

if __name__ == "__main__":
    main()
