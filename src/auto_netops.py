import re
import os
from typing import Dict, List, Tuple
import pandas as pd
from datetime import datetime

class NetworkConfigParser:
    """网络设备配置解析器 - 全面支持各种接口类型"""
    
    def __init__(self):
        # 定义所有可能的接口类型和速率
        self.interface_types = {
            # 接口全称: (常见缩写列表, 速率)
            'FastEthernet': (['Fa', 'Fast'], '100M'),
            'GigabitEthernet': (['Gi', 'Gig', 'GigE', 'GE'], '1G'),
            'TwoGigabitEthernet': (['Two', 'TwoGig', 'Tw'], '2.5G'),
            'FiveGigabitEthernet': (['Fi', 'FiveGig', 'Fiv'], '5G'),
            'TenGigabitEthernet': (['Te', 'Ten', 'TenGig', 'TenGigE', 'TGE', 'XGE'], '10G'),  # 添加XGE支持华为
            'TwentyFiveGigE': (['Twe', 'TwentyFiveGig', 'TF'], '25G'),
            'FortyGigabitEthernet': (['Fo', 'For', 'FortyGig', 'FortyGigE', 'FGE'], '40G'),
            'FiftyGigE': (['Fif', 'FiftyGig'], '50G'),
            'HundredGigE': (['Hu', 'Hun', 'HundredGig', 'HundredGigE', 'HGE'], '100G'),
            'TwoHundredGigE': (['TH', 'TwoHundredGig'], '200G'),
            'FourHundredGigE': (['FH', 'FourHundredGig'], '400G'),
            # 其他接口类型
            'Ethernet': (['Eth', 'Et'], 'Variable'),
            'Port-channel': (['Po', 'Port-Channel'], 'LAG'),
            'Eth-Trunk': (['Eth-Trunk'], 'LAG'),  # 华为链路聚合
            'Vlan': (['Vl', 'Vlan'], 'SVI'),
            'Vlanif': (['Vlanif'], 'SVI'),  # 华为VLAN接口
            'Loopback': (['Lo', 'Loop'], 'Virtual'),
            'LoopBack': (['LoopBack'], 'Virtual'),  # 华为Loopback
            'Tunnel': (['Tu', 'Tun'], 'Virtual'),
            'Serial': (['Se', 'Ser'], 'Serial'),
            'Management': (['Mgmt', 'Ma', 'MEth'], 'OOB'),  # MEth为华为管理接口
            'XGigabitEthernet': (['XGE', 'XGigE'], '10G'),  # 华为10G接口
            '10GE': (['10GE'], '10G'),  # 华为10G接口另一种格式
            '25GE': (['25GE'], '25G'),  # 华为25G接口
            '40GE': (['40GE'], '40G'),  # 华为40G接口
            '100GE': (['100GE'], '100G'),  # 华为100G接口
        }
        
        # 构建接口匹配正则表达式
        self._build_interface_regex()
        
        # 定义各厂商的识别模式
        self.vendor_patterns = {
            'Cisco': {
                'identifier': [r'cisco', r'IOS', r'Cisco IOS'],
                'version': r'Version\s+([^\s,]+)',
                'model': r'cisco\s+(\S+)\s+\(',
                'hostname': r'hostname\s+(\S+)',
                'is_9k': [r'C9[23456]\d{2}', r'Cat9K', r'Catalyst 9[0-9]{3}'],
                'is_nexus': [r'Nexus', r'NX-OS', r'N[579]K']
            },
            'Huawei': {
                'identifier': [r'Huawei', r'VRP', r'Versatile Routing Platform', r'sysname'],
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
            'Arista': {
                'identifier': [r'Arista', r'EOS'],
                'version': r'Software image version:\s+([^\s]+)',
                'model': r'Arista\s+(\S+)',
                'hostname': r'hostname\s+(\S+)'
            },
            'Juniper': {
                'identifier': [r'Juniper', r'JUNOS'],
                'version': r'JUNOS.*\s+$$([^$$]+)\]',
                'model': r'Model:\s+(\S+)',
                'hostname': r'host-name\s+(\S+)'
            }
        }
        
        # 更新接口配置模式
        self.interface_patterns = {
            'Cisco': {
                'interface': self.interface_regex,
                'access': r'switchport\s+mode\s+access',
                'trunk': r'switchport\s+mode\s+trunk',
                'routed': r'no\s+switchport',
                'access_vlan': r'switchport\s+access\s+vlan\s+(\d+)',
                'trunk_vlan': r'switchport\s+trunk\s+allowed\s+vlan\s+([\d,\-\s]+)',
                'shutdown': r'^\s*shutdown\s*$',
                'description': r'description\s+(.+)',
                'speed': r'speed\s+(\d+)',
                'duplex': r'duplex\s+(\w+)',
                'channel_group': r'channel-group\s+(\d+)',
                'vpc': r'vpc\s+(\d+)',
                'ip_address': r'ip\s+address\s+([\d\.]+)\s+([\d\.]+)'
            },
            'Huawei': {
                'interface': r'interface\s+([\w\-/\:\.]+)',  # 华为接口格式更灵活
                'access': r'port\s+link-type\s+access',
                'trunk': r'port\s+link-type\s+trunk',
                'hybrid': r'port\s+link-type\s+hybrid',
                'access_vlan': r'port\s+default\s+vlan\s+(\d+)',
                'trunk_vlan': r'port\s+trunk\s+allow-pass\s+vlan\s+([\d\s\-to]+)',  # 支持to关键字
                'hybrid_tagged': r'port\s+hybrid\s+tagged\s+vlan\s+([\d\s\-to]+)',
                'hybrid_untagged': r'port\s+hybrid\s+untagged\s+vlan\s+([\d\s\-to]+)',
                'shutdown': r'^\s*shutdown\s*$',
                'undo_shutdown': r'^\s*undo\s+shutdown\s*$',  # 华为使用undo shutdown启用端口
                'description': r'description\s+(.+)',
                'speed': r'negotiation\s+auto\s+speed\s+(\d+)',  # 华为速率配置
                'eth_trunk': r'eth-trunk\s+(\d+)',
                'ip_address': r'ip\s+address\s+([\d\.]+)\s+([\d\.]+)',
                'qinq': r'port\s+vlan-stacking',  # QinQ配置
                'pvid': r'port\s+trunk\s+pvid\s+vlan\s+(\d+)'  # Trunk PVID
            },
            'H3C': {
                'interface': r'interface\s+([\w\-/\:\.]+)',
                'access': r'port\s+link-type\s+access',
                'trunk': r'port\s+link-type\s+trunk',
                'hybrid': r'port\s+link-type\s+hybrid',
                'access_vlan': r'port\s+access\s+vlan\s+(\d+)',
                'trunk_vlan': r'port\s+trunk\s+permit\s+vlan\s+([\d\s\-to]+)',
                'shutdown': r'^\s*shutdown\s*$',
                'description': r'description\s+(.+)',
                'speed': r'speed\s+(\d+)',
                'bridge_aggregation': r'port\s+link-aggregation\s+group\s+(\d+)'
            },
            'Arista': {
                'interface': self.interface_regex,
                'access': r'switchport\s+mode\s+access',
                'trunk': r'switchport\s+mode\s+trunk',
                'routed': r'no\s+switchport',
                'access_vlan': r'switchport\s+access\s+vlan\s+(\d+)',
                'trunk_vlan': r'switchport\s+trunk\s+allowed\s+vlan\s+([\d,\-\s]+)',
                'shutdown': r'^\s*shutdown\s*$',
                'description': r'description\s+(.+)',
                'mlag': r'mlag\s+(\d+)'
            }
        }
    
    def _build_interface_regex(self):
        """构建匹配所有接口类型的正则表达式"""
        # 收集所有可能的接口名称（全称和缩写）
        interface_names = []
        for full_name, (abbreviations, _) in self.interface_types.items():
            interface_names.append(full_name)
            interface_names.extend(abbreviations)
        
        # 对华为设备特殊处理，支持无空格的接口名
        # 例如：GigabitEthernet0/0/1 或 GE0/0/1
        interface_pattern = r'interface\s+(' + '|'.join(interface_names) + r')[\s\-]*([\d/:\.]+)'
        self.interface_regex = interface_pattern
    
    def normalize_interface_name(self, interface: str) -> Tuple[str, str]:
        """
        标准化接口名称并识别速率
        返回: (标准化名称, 速率)
        """
        # 移除多余的空格
        interface = re.sub(r'\s+', '', interface)
        
        # 分离接口类型和编号
        match = re.match(r'([A-Za-z\-]+)([\d/:\.]+.*)', interface)
        if not match:
            return interface, 'Unknown'
        
        intf_type = match.group(1)
        intf_number = match.group(2)
        
        # 查找匹配的接口类型
        for full_name, (abbreviations, speed) in self.interface_types.items():
            # 检查是否匹配全称
            if intf_type.lower() == full_name.lower():
                return f"{full_name}{intf_number}", speed
            
            # 检查是否匹配缩写
            for abbr in abbreviations:
                if intf_type.lower() == abbr.lower():
                    return f"{full_name}{intf_number}", speed
        
        # 未找到匹配，返回原始名称
        return interface, 'Unknown'
    
    def parse_vlan_list_huawei(self, vlan_str: str) -> str:
        """解析华为的VLAN列表，将to转换为标准格式"""
        # 将 "1 to 10" 转换为 "1-10"
        vlan_str = re.sub(r'(\d+)\s+to\s+(\d+)', r'\1-\2', vlan_str)
        return vlan_str.strip()
    
    def parse_interfaces(self, content: str, vendor: str) -> List[Dict]:
        """解析接口配置 - 支持所有接口类型"""
        interfaces = []
        
        if vendor not in self.interface_patterns:
            return interfaces
        
        patterns = self.interface_patterns[vendor]
        
        # 使用更灵活的正则表达式来匹配接口
        interface_pattern = re.compile(patterns['interface'], re.MULTILINE | re.IGNORECASE)
        
        # 找到所有接口配置的起始位置
        interface_matches = list(interface_pattern.finditer(content))
        
        for i, match in enumerate(interface_matches):
            # 获取原始接口名称
            raw_interface = match.group(0).replace('interface', '').strip()
            
            # 标准化接口名称并获取速率
            interface_name, interface_speed = self.normalize_interface_name(raw_interface)
            
            # 获取该接口的配置内容
            start_pos = match.end()
            if i + 1 < len(interface_matches):
                end_pos = interface_matches[i + 1].start()
            else:
                # 最后一个接口，查找到下一个!或#或文件结尾
                next_section = re.search(r'\n[!#]', content[start_pos:])
                end_pos = start_pos + next_section.start() if next_section else len(content)
            
            interface_config = content[start_pos:end_pos]
            
            # 解析接口信息
            interface_info = self.parse_interface_number(interface_name)
            
            # 判断接口类型
            port_mode = 'Unknown'
            vlan_info = ''
            
            # 华为特殊处理
            if vendor == 'Huawei':
                # 检查是否是undo shutdown（端口启用）
                if re.search(patterns.get('undo_shutdown', ''), interface_config):
                    status = 'Up'
                elif re.search(patterns.get('shutdown', ''), interface_config):
                    status = 'Admin Down'
                else:
                    status = 'Up'  # 华为默认端口是启用的
                
                # 检查端口类型
                if re.search(patterns['access'], interface_config):
                    port_mode = 'Access'
                    vlan_match = re.search(patterns['access_vlan'], interface_config)
                    if vlan_match:
                        vlan_info = f"VLAN {vlan_match.group(1)}"
                elif re.search(patterns['trunk'], interface_config):
                    port_mode = 'Trunk'
                    vlan_match = re.search(patterns['trunk_vlan'], interface_config)
                    if vlan_match:
                        vlans = self.parse_vlan_list_huawei(vlan_match.group(1))
                        vlan_info = f"VLANs: {vlans}"
                    # 检查PVID
                    pvid_match = re.search(patterns.get('pvid', ''), interface_config)
                    if pvid_match:
                        vlan_info += f" (PVID: {pvid_match.group(1)})"
                elif re.search(patterns.get('hybrid', ''), interface_config):
                    port_mode = 'Hybrid'
                    tagged_vlans = []
                    untagged_vlans = []
                    
                    # 获取tagged VLANs
                    tagged_match = re.search(patterns.get('hybrid_tagged', ''), interface_config)
                    if tagged_match:
                        tagged_vlans = self.parse_vlan_list_huawei(tagged_match.group(1))
                    
                    # 获取untagged VLANs
                    untagged_match = re.search(patterns.get('hybrid_untagged', ''), interface_config)
                    if untagged_match:
                        untagged_vlans = self.parse_vlan_list_huawei(untagged_match.group(1))
                    
                    vlan_info = f"Tagged: {tagged_vlans}, Untagged: {untagged_vlans}"
                
                # 检查是否是三层接口
                ip_match = re.search(patterns.get('ip_address', ''), interface_config)
                if ip_match:
                    port_mode = 'Routed'
                    vlan_info = f"IP: {ip_match.group(1)}/{ip_match.group(2)}"
            else:
                # 其他厂商的处理逻辑
                # 检查是否是路由接口
                if 'routed' in patterns and re.search(patterns['routed'], interface_config):
                    port_mode = 'Routed'
                    # 查找IP地址
                    ip_match = re.search(patterns.get('ip_address', r'ip\s+address\s+([\d\.]+)\s+([\d\.]+)'), interface_config)
                    if ip_match:
                        vlan_info = f"IP: {ip_match.group(1)}/{ip_match.group(2)}"
                elif re.search(patterns['access'], interface_config):
                    port_mode = 'Access'
                    vlan_match = re.search(patterns['access_vlan'], interface_config)
                    if vlan_match:
                        vlan_info = f"VLAN {vlan_match.group(1)}"
                elif re.search(patterns['trunk'], interface_config):
                    port_mode = 'Trunk'
                    vlan_match = re.search(patterns['trunk_vlan'], interface_config)
                    if vlan_match:
                        vlans = vlan_match.group(1).strip()
                        vlan_info = f"VLANs: {vlans}"
                elif 'hybrid' in patterns and re.search(patterns['hybrid'], interface_config):
                    port_mode = 'Hybrid'
                    vlan_info = 'Hybrid mode'
                
                # 判断接口状态（非华为设备）
                shutdown = bool(re.search(patterns.get('shutdown', r'shutdown'), interface_config, re.MULTILINE))
                status = 'Admin Down' if shutdown else 'Up'
            
            # 提取描述
            description = ''
            desc_match = re.search(patterns.get('description', r'description\s+(.+)'), interface_config)
            if desc_match:
                description = desc_match.group(1).strip()
            
            # 提取速率设置
            configured_speed = ''
            speed_match = re.search(patterns.get('speed', r'speed\s+(\d+)'), interface_config)
            if speed_match:
                configured_speed = f"{speed_match.group(1)}M"
            
            # 提取双工设置
            duplex = ''
            duplex_match = re.search(patterns.get('duplex', r'duplex\s+(\w+)'), interface_config)
            if duplex_match:
                duplex = duplex_match.group(1)
            
            # 额外信息
            extra_info = {}
            
            # 端口聚合信息
            if vendor == 'Cisco':
                channel_match = re.search(patterns.get('channel_group', ''), interface_config)
                if channel_match:
                    extra_info['channel_group'] = f"Po{channel_match.group(1)}"
                
                vpc_match = re.search(patterns.get('vpc', ''), interface_config)
                if vpc_match:
                    extra_info['vpc'] = f"vPC {vpc_match.group(1)}"
            
            elif vendor == 'Huawei':
                eth_trunk_match = re.search(patterns.get('eth_trunk', ''), interface_config)
                if eth_trunk_match:
                    extra_info['eth_trunk'] = f"Eth-Trunk{eth_trunk_match.group(1)}"
                
                # QinQ检测
                if re.search(patterns.get('qinq', ''), interface_config):
                    extra_info['qinq'] = 'Enabled'
            
            elif vendor == 'H3C':
                bridge_agg_match = re.search(patterns.get('bridge_aggregation', ''), interface_config)
                if bridge_agg_match:
                    extra_info['bridge_aggregation'] = f"BAGG{bridge_agg_match.group(1)}"
            
            elif vendor == 'Arista':
                mlag_match = re.search(patterns.get('mlag', ''), interface_config)
                if mlag_match:
                    extra_info['mlag'] = f"MLAG {mlag_match.group(1)}"
            
            # 堆叠成员信息（针对9000系列）
            if interface_info.get('format') == '9k_stack':
                extra_info['stack_member'] = f"Switch-{interface_info['switch']}"
            
            interface_data = {
                'interface': interface_name,
                'interface_speed': interface_speed,
                'port_mode': port_mode,
                'vlan_info': vlan_info,
                'status': status,
                'description': description,
                'configured_speed': configured_speed,
                'duplex': duplex,
                'interface_format': interface_info.get('format', 'unknown')
            }
            
            # 添加额外信息
            interface_data.update(extra_info)
            
            interfaces.append(interface_data)
        
        return interfaces
    
    def parse_interface_number(self, interface: str) -> Dict:
        """解析接口编号，支持各种格式"""
        # 提取接口类型和编号
        match = re.match(r'([A-Za-z\-]+)([\d/:\.]+.*)', interface)
        if not match:
            return {'type': 'Unknown', 'numbers': [], 'format': 'unknown'}
        
        interface_type = match.group(1)
        numbers_str = match.group(2)
        
        # 解析不同的编号格式
        # 支持: 0/1, 1/0/1, 1/1/0/1, 1:1, 1.1等
        if '/' in numbers_str:
            numbers = numbers_str.strip('/').split('/')
            if len(numbers) == 4:
                # 9000系列堆叠格式: switch/module/slot/port
                return {
                    'type': interface_type,
                    'format': '9k_stack',
                    'switch': numbers[0],
                    'module': numbers[1],
                    'slot': numbers[2],
                    'port': numbers[3],
                    'numbers': numbers
                }
            elif len(numbers) == 3:
                # 传统3层格式: module/slot/port 或 华为格式: slot/subslot/port
                return {
                    'type': interface_type,
                    'format': 'traditional_3',
                    'module': numbers[0],
                    'slot': numbers[1],
                    'port': numbers[2],
                    'numbers': numbers
                }
            elif len(numbers) == 2:
                # 传统2层格式: slot/port
                return {
                    'type': interface_type,
                    'format': 'traditional_2',
                    'slot': numbers[0],
                    'port': numbers[1],
                    'numbers': numbers
                }
        elif ':' in numbers_str:
            # Nexus格式: Ethernet1:1
            numbers = numbers_str.split(':')
            return {
                'type': interface_type,
                'format': 'nexus',
                'slot': numbers[0],
                'port': numbers[1] if len(numbers) > 1 else '0',
                'numbers': numbers
            }
        elif '.' in numbers_str:
            # 子接口格式: GigabitEthernet0/1.100
            base_intf, sub_intf = numbers_str.split('.', 1)
            return {
                'type': interface_type,
                'format': 'subinterface',
                'base': base_intf,
                'subinterface': sub_intf,
                'numbers': [base_intf, sub_intf]
            }
        else:
            # 简单格式: Ethernet1
            return {
                'type': interface_type,
                'format': 'simple',
                'port': numbers_str,
                'numbers': [numbers_str]
            }
        
        return {'type': interface_type, 'format': 'unknown', 'numbers': [numbers_str]}
    
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
            'hostname': 'Unknown',
            'device_type': 'Unknown'
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
            hostname_match = re.search(patterns['hostname'], content, re.IGNORECASE | re.MULTILINE)
            if hostname_match:
                info['hostname'] = hostname_match.group(1)
            
            # 特定厂商的设备类型检测
            if vendor == 'Cisco':
                if any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns.get('is_9k', [])):
                    info['device_type'] = 'Catalyst 9000 Series'
                elif any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns.get('is_nexus', [])):
                    info['device_type'] = 'Nexus Series'
                else:
                    info['device_type'] = 'Traditional IOS'
            elif vendor == 'Huawei':
                if 'CE' in info['model']:
                    info['device_type'] = 'CloudEngine Series'
                elif 'S' in info['model']:
                    info['device_type'] = 'S Series Switch'
                elif 'AR' in info['model']:
                    info['device_type'] = 'AR Series Router'
        
        return info
    
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
        routed_ports = sum(1 for i in interfaces if i['port_mode'] == 'Routed')
        hybrid_ports = sum(1 for i in interfaces if i['port_mode'] == 'Hybrid')
        
        # 按速率统计
        speed_stats = {}
        for intf in interfaces:
            speed = intf.get('interface_speed', 'Unknown')
            speed_stats[speed] = speed_stats.get(speed, 0) + 1
        
        # 堆叠信息
        stack_info = {}
        if device_info.get('device_type') == 'Catalyst 9000 Series':
            stack_members = set()
            for intf in interfaces:
                if 'stack_member' in intf:
                    stack_members.add(intf['stack_member'])
            stack_info['stack_members'] = len(stack_members)
            stack_info['stack_member_list'] = list(stack_members)
        
        return {
            'file_name': os.path.basename(file_path),
            'device_info': device_info,
            'statistics': {
                'total_ports': total_ports,
                'access_ports': access_ports,
                'trunk_ports': trunk_ports,
                'routed_ports': routed_ports,
                'hybrid_ports': hybrid_ports,
                'unknown_ports': total_ports - access_ports - trunk_ports - routed_ports - hybrid_ports,
                'speed_stats': speed_stats
            },
            'stack_info': stack_info,
            'interfaces': interfaces
        }
    
    def export_to_excel(self, results: List[Dict], output_file: str = 'network_config_analysis.xlsx'):
        """导出到Excel文件"""
        with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
            # 汇总表
            summary_data = []
            for result in results:
                row = {
                    '文件名': result['file_name'],
                    '设备厂商': result['device_info']['vendor'],
                    '设备型号': result['device_info']['model'],
                    '设备类型': result['device_info'].get('device_type', 'Unknown'),
                    '系统版本': result['device_info']['version'],
                    '主机名': result['device_info']['hostname'],
                    '总端口数': result['statistics']['total_ports'],
                    'Access端口数': result['statistics']['access_ports'],
                    'Trunk端口数': result['statistics']['trunk_ports'],
                    'Routed端口数': result['statistics'].get('routed_ports', 0),
                    'Hybrid端口数': result['statistics'].get('hybrid_ports', 0),
                    '未知类型端口数': result['statistics']['unknown_ports']
                }
                
                # 添加速率统计
                for speed, count in result['statistics']['speed_stats'].items():
                    row[f'{speed}端口数'] = count
                
                # 添加堆叠信息
                if result.get('stack_info') and result['stack_info'].get('stack_members'):
                    row['堆叠成员数'] = result['stack_info']['stack_members']
                
                summary_data.append(row)
            
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='设备汇总', index=False)
            
            # 为每个设备创建详细表
            for idx, result in enumerate(results):
                if result['interfaces']:
                    # 准备接口数据
                    interface_data = []
                    for intf in result['interfaces']:
                        intf_row = {
                            '接口名称': intf['interface'],
                            '接口速率': intf['interface_speed'],
                            '端口模式': intf['port_mode'],
                            'VLAN信息': intf['vlan_info'],
                            '管理状态': intf['status'],
                            '描述': intf.get('description', ''),
                            '配置速率': intf.get('configured_speed', 'Auto'),
                            '双工模式': intf.get('duplex', 'Auto'),
                            '接口格式': intf.get('interface_format', '')
                        }
                        
                        # 添加额外信息
                        if 'stack_member' in intf:
                            intf_row['堆叠成员'] = intf['stack_member']
                        if 'channel_group' in intf:
                            intf_row['端口聚合'] = intf['channel_group']
                        if 'vpc' in intf:
                            intf_row['vPC'] = intf['vpc']
                        if 'eth_trunk' in intf:
                            intf_row['链路聚合'] = intf['eth_trunk']
                        if 'mlag' in intf:
                            intf_row['MLAG'] = intf['mlag']
                        if 'qinq' in intf:
                            intf_row['QinQ'] = intf['qinq']
                        
                        interface_data.append(intf_row)
                    
                    interface_df = pd.DataFrame(interface_data)
                    sheet_name = f"{result['device_info']['hostname'][:20]}_{idx}"
                    interface_df.to_excel(writer, sheet_name=sheet_name, index=False)
            
            # 自动调整列宽
            for sheet_name in writer.sheets:
                worksheet = writer.sheets[sheet_name]
                for column in worksheet.columns:
                    max_length = 0
                    column_letter = column[0].column_letter
                    for cell in column:
                        try:
                            if len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except:
                            pass
                    adjusted_width = min(max_length + 2, 50)
                    worksheet.column_dimensions[column_letter].width = adjusted_width
        
        print(f"**分析完成！结果已保存到: {output_file}**")

# 创建示例配置，展示各种接口类型（包括华为）
def create_huawei_sample_config():
    """创建华为设备示例配置"""
    sample_config = """#
# Huawei Versatile Routing Platform Software
# VRP (R) software, Version 8.180 (CE6850 V200R005C00)
#
sysname SW-HUAWEI-CORE-01
#
interface GigabitEthernet0/0/1
 description To-Access-Switch-01
 port link-type access
 port default vlan 10
#
interface GigabitEthernet0/0/2
 port link-type trunk
 port trunk allow-pass vlan 10 20 30 to 40 100
 port trunk pvid vlan 1
#
interface XGigabitEthernet0/0/10
 description 10G-Uplink-to-Core
 port link-type trunk
 port trunk allow-pass vlan all
#
interface 40GE0/0/1
 description 40G-Link-to-Datacenter
 port link-type trunk
 port trunk allow-pass vlan 100 200 to 300
 eth-trunk 1
#
interface 100GE0/0/1
 description 100G-Backbone
 undo shutdown
 ip address 10.0.0.1 255.255.255.252
#
interface Eth-Trunk1
 description LAG-to-Datacenter
 port link-type trunk
 port trunk allow-pass vlan all
#
interface Vlanif100
 description Management-VLAN
 ip address 192.168.100.1 255.255.255.0
#
interface GigabitEthernet0/0/3
 port link-type hybrid
 port hybrid tagged vlan 100 200
 port hybrid untagged vlan 10
#
interface MEth0/0/1
 description Management-Port
 ip address 192.168.1.1 255.255.255.0
#
"""
    
    with open('sample_huawei_config.txt', 'w', encoding='utf-8') as f:
        f.write(sample_config)
    
    print("**华为设备示例配置文件已创建: sample_huawei_config.txt**")

def main():
    """主函数"""
    parser = NetworkConfigParser()
    
    # 可选：创建示例配置
    # create_huawei_sample_config()
    
    # 配置文件目录
    config_dir = input("请输入配置文件目录路径 (默认为当前目录): ").strip()
    if not config_dir:
        config_dir = "."
    
    # 查找所有配置文件
    config_files = []
    for file in os.listdir(config_dir):
        if file.endswith(('.txt', '.log', '.conf', '.cfg')):
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
            print(f"  - 厂商: {result['device_info']['vendor']}")
            print(f"  - 主机名: {result['device_info']['hostname']}")
            print(f"  - 接口数: {result['statistics']['total_ports']}")
        except Exception as e:
            print(f"处理文件 {file_path} 时出错: {e}")
            import traceback
            traceback.print_exc()
    
    # 导出结果
    if results:
        output_file = f"network_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        parser.export_to_excel(results, output_file)
    else:
        print("**没有成功解析的配置文件！**")

if __name__ == "__main__":
    main()
