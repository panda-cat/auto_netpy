import re
import os
from typing import Dict, List, Tuple, Set
import pandas as pd
from datetime import datetime

class NetworkConfigParser:
    """网络设备配置解析器 - 增强Ruckus ICX支持"""
    
    def __init__(self):
        # 定义所有可能的接口类型和速率
        self.interface_types = {
            # 接口全称: (常见缩写列表, 速率)
            'FastEthernet': (['Fa', 'Fast'], '100M'),
            'GigabitEthernet': (['Gi', 'Gig', 'GigE', 'GE'], '1G'),
            'TwoGigabitEthernet': (['Two', 'TwoGig', 'Tw'], '2.5G'),
            'FiveGigabitEthernet': (['Fi', 'FiveGig', 'Fiv'], '5G'),
            'TenGigabitEthernet': (['Te', 'Ten', 'TenGig', 'TenGigE', 'TGE', 'XGE'], '10G'),
            'TwentyFiveGigE': (['Twe', 'TwentyFiveGig', 'TF'], '25G'),
            'FortyGigabitEthernet': (['Fo', 'For', 'FortyGig', 'FortyGigE', 'FGE'], '40G'),
            'FiftyGigE': (['Fif', 'FiftyGig'], '50G'),
            'HundredGigE': (['Hu', 'Hun', 'HundredGig', 'HundredGigE', 'HGE'], '100G'),
            # Ruckus特殊格式
            'ethernet': (['ethernet', 'e'], 'Variable'),  # Ruckus使用小写ethernet
            'lag': (['lag'], 'LAG'),  # Ruckus LAG
            've': (['ve'], 'Virtual'),  # Ruckus虚拟接口
            'management': (['management'], 'OOB'),
            # 其他接口类型
            'Ethernet': (['Eth', 'Et'], 'Variable'),
            'Port-channel': (['Po', 'Port-Channel'], 'LAG'),
            'Eth-Trunk': (['Eth-Trunk'], 'LAG'),
            'Vlan': (['Vl', 'Vlan'], 'SVI'),
            'Vlanif': (['Vlanif'], 'SVI'),
            'Loopback': (['Lo', 'Loop'], 'Virtual'),
            'LoopBack': (['LoopBack'], 'Virtual'),
            'Tunnel': (['Tu', 'Tun'], 'Virtual'),
            'Serial': (['Se', 'Ser'], 'Serial'),
            'Management': (['Mgmt', 'Ma', 'MEth'], 'OOB'),
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
            'Ruckus': {
                'identifier': [r'Ruckus', r'FastIron', r'ICX', r'Current configuration:', r'ver \d+\.\d+\.\d+'],
                'version': r'SW:\s+Version\s+([^\s]+)',
                'model': r'ICX(\d+[A-Z]*)',
                'hostname': r'hostname\s+["\']?([^"\']+)["\']?',
                'stack_info': r'stack\s+unit\s+(\d+)'
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
            'Ruckus': {
                'interface': r'interface\s+(ethernet\s+[\d/]+|lag\s+\d+|ve\s+\d+|management\s+\d+)',
                'shutdown': r'^\s*disable\s*$',
                'enable': r'^\s*enable\s*$',
                'description': r'port-name\s+["\']?([^"\']+)["\']?',
                'speed': r'speed-duplex\s+(\d+)-',
                'duplex': r'speed-duplex\s+\d+-(\w+)',
                'lag_member': r'lag\s+(\w+)\s+id\s+(\d+)',
                'ip_address': r'ip\s+address\s+([\d\.]+)(?:/(\d+)|\s+([\d\.]+))'
            },
            'Huawei': {
                'interface': r'interface\s+([\w\-/\:\.]+)',
                'access': r'port\s+link-type\s+access',
                'trunk': r'port\s+link-type\s+trunk',
                'hybrid': r'port\s+link-type\s+hybrid',
                'access_vlan': r'port\s+default\s+vlan\s+(\d+)',
                'trunk_vlan': r'port\s+trunk\s+allow-pass\s+vlan\s+([\d\s\-to]+)',
                'hybrid_tagged': r'port\s+hybrid\s+tagged\s+vlan\s+([\d\s\-to]+)',
                'hybrid_untagged': r'port\s+hybrid\s+untagged\s+vlan\s+([\d\s\-to]+)',
                'shutdown': r'^\s*shutdown\s*$',
                'undo_shutdown': r'^\s*undo\s+shutdown\s*$',
                'description': r'description\s+(.+)',
                'speed': r'negotiation\s+auto\s+speed\s+(\d+)',
                'eth_trunk': r'eth-trunk\s+(\d+)',
                'ip_address': r'ip\s+address\s+([\d\.]+)\s+([\d\.]+)',
                'qinq': r'port\s+vlan-stacking',
                'pvid': r'port\s+trunk\s+pvid\s+vlan\s+(\d+)'
            }
        }
        
        # Ruckus VLAN配置缓存
        self.ruckus_vlan_cache = {}
    
    def _build_interface_regex(self):
        """构建匹配所有接口类型的正则表达式"""
        # 收集所有可能的接口名称（全称和缩写）
        interface_names = []
        for full_name, (abbreviations, _) in self.interface_types.items():
            interface_names.append(full_name)
            interface_names.extend(abbreviations)
        
        # 构建正则表达式
        interface_pattern = r'interface\s+(' + '|'.join(interface_names) + r')[\s\-]*([\d/:\.]+)'
        self.interface_regex = interface_pattern
    
    def parse_ruckus_vlan_config(self, content: str) -> Dict[int, Dict[str, List[str]]]:
        """解析Ruckus的VLAN配置块"""
        vlan_configs = {}
        current_vlan = None
        in_vlan_block = False
        
        # Ruckus VLAN配置模式
        vlan_pattern = r'vlan\s+(\d+)(?:\s+name\s+["\']?([^"\']+)["\']?)?'
        tagged_pattern = r'^\s*tagged\s+(.+)'
        untagged_pattern = r'^\s*untagged\s+(.+)'
        router_interface_pattern = r'^\s*router-interface\s+ve\s+(\d+)'
        spanning_tree_pattern = r'^\s*spanning-tree'
        
        lines = content.split('\n')
        
        for line in lines:
            line = line.rstrip()
            
            # 检测VLAN配置块开始
            if match := re.match(vlan_pattern, line):
                current_vlan = int(match.group(1))
                vlan_name = match.group(2) if match.group(2) else ''
                vlan_configs[current_vlan] = {
                    'name': vlan_name,
                    'tagged': [],
                    'untagged': [],
                    've': None
                }
                in_vlan_block = True
                continue
            
            # 检测是否退出VLAN配置块
            if in_vlan_block and line and not line.startswith((' ', '\t')) and not line.startswith('!'):
                if not re.match(r'^\s*(tagged|untagged|router-interface|spanning-tree)', line):
                    in_vlan_block = False
                    current_vlan = None
            
            # 在VLAN配置块内解析
            if current_vlan and in_vlan_block:
                # 解析tagged端口
                if match := re.match(tagged_pattern, line):
                    ports = self._parse_ruckus_port_list(match.group(1))
                    vlan_configs[current_vlan]['tagged'].extend(ports)
                
                # 解析untagged端口
                elif match := re.match(untagged_pattern, line):
                    ports = self._parse_ruckus_port_list(match.group(1))
                    vlan_configs[current_vlan]['untagged'].extend(ports)
                
                # 解析路由接口
                elif match := re.match(router_interface_pattern, line):
                    vlan_configs[current_vlan]['ve'] = f"ve {match.group(1)}"
        
        return vlan_configs
    
    def _parse_ruckus_port_list(self, port_str: str) -> List[str]:
        """解析Ruckus端口列表"""
        ports = []
        
        # 处理ethernet端口范围
        # 格式: ethernet 1/1/1 to 1/1/24 ethernet 2/1/1
        port_str = port_str.strip()
        
        # 先处理简单的逗号分隔
        if ',' in port_str and 'to' not in port_str:
            for port in port_str.split(','):
                port = port.strip()
                if port.startswith('ethernet'):
                    ports.append(port)
                elif port.startswith('lag'):
                    ports.append(port)
            return ports
        
        # 处理包含to的范围
        parts = re.split(r'\s+', port_str)
        i = 0
        
        while i < len(parts):
            if parts[i] == 'ethernet' and i + 1 < len(parts):
                # 检查是否有范围
                if i + 3 < len(parts) and parts[i + 2] == 'to':
                    # ethernet 1/1/1 to 1/1/24 格式
                    start_port = f"ethernet {parts[i + 1]}"
                    end_port_num = parts[i + 3]
                    
                    # 解析端口范围
                    start_parts = parts[i + 1].split('/')
                    end_parts = end_port_num.split('/')
                    
                    if len(start_parts) == 3 and len(end_parts) == 3:
                        # 标准格式 stack/module/port
                        for port_num in range(int(start_parts[2]), int(end_parts[2]) + 1):
                            port = f"ethernet {start_parts[0]}/{start_parts[1]}/{port_num}"
                            ports.append(port)
                    elif len(end_parts) == 1:
                        # 简化格式，只有端口号 ethernet 1/1/1 to 24
                        for port_num in range(int(start_parts[2]), int(end_parts[0]) + 1):
                            port = f"ethernet {start_parts[0]}/{start_parts[1]}/{port_num}"
                            ports.append(port)
                    
                    # 查找下一个ethernet或结束
                    i += 4
                    while i < len(parts) and parts[i] != 'ethernet' and parts[i] != 'lag':
                        i += 1
                else:
                    # 单个端口
                    ports.append(f"ethernet {parts[i + 1]}")
                    i += 2
            elif parts[i] == 'lag' and i + 1 < len(parts):
                ports.append(f"lag {parts[i + 1]}")
                i += 2
            else:
                i += 1
        
        return ports
    
    def parse_interfaces(self, content: str, vendor: str) -> List[Dict]:
        """解析接口配置 - 支持所有接口类型"""
        interfaces = []
        
        if vendor not in self.interface_patterns:
            return interfaces
        
        patterns = self.interface_patterns[vendor]
        
        # 对于Ruckus，先解析VLAN配置
        if vendor == 'Ruckus':
            self.ruckus_vlan_cache = self.parse_ruckus_vlan_config(content)
        
        # 使用更灵活的正则表达式来匹配接口
        interface_pattern = re.compile(patterns['interface'], re.MULTILINE | re.IGNORECASE)
        
        # 找到所有接口配置的起始位置
        interface_matches = list(interface_pattern.finditer(content))
        
        for i, match in enumerate(interface_matches):
            # 获取原始接口名称
            raw_interface = match.group(0).replace('interface', '').strip()
            
            # 标准化接口名称并获取速率
            interface_name, interface_speed = self.normalize_interface_name(raw_interface, vendor)
            
            # 获取该接口的配置内容
            start_pos = match.end()
            if i + 1 < len(interface_matches):
                end_pos = interface_matches[i + 1].start()
            else:
                # 最后一个接口
                next_section = re.search(r'\n(?:!|vlan\s+\d+|interface)', content[start_pos:])
                end_pos = start_pos + next_section.start() if next_section else len(content)
            
            interface_config = content[start_pos:end_pos]
            
            # 解析接口信息
            interface_info = self.parse_interface_number(interface_name)
            
            if vendor == 'Ruckus':
                # Ruckus特殊处理
                interface_data = self._parse_ruckus_interface(
                    interface_name, interface_speed, interface_config, interface_info
                )
            else:
                # 其他厂商的处理逻辑
                interface_data = self._parse_standard_interface(
                    interface_name, interface_speed, interface_config, 
                    interface_info, patterns, vendor
                )
            
            interfaces.append(interface_data)
        
        return interfaces
    
    def _parse_ruckus_interface(self, interface_name: str, interface_speed: str, 
                              interface_config: str, interface_info: Dict) -> Dict:
        """解析Ruckus接口配置"""
        patterns = self.interface_patterns['Ruckus']
        
        # 判断接口状态
        if re.search(patterns.get('disable', r'disable'), interface_config):
            status = 'Admin Down'
        else:
            status = 'Up'
        
        # 提取描述（port-name）
        description = ''
        desc_match = re.search(patterns.get('description'), interface_config)
        if desc_match:
            description = desc_match.group(1).strip()
        
        # 判断接口类型和VLAN信息
        port_mode = 'Unknown'
        vlan_info = ''
        
        # 查找该接口属于哪些VLAN
        interface_vlans = {'tagged': [], 'untagged': []}
        
        for vlan_id, vlan_config in self.ruckus_vlan_cache.items():
            if interface_name in vlan_config['tagged']:
                interface_vlans['tagged'].append(vlan_id)
            if interface_name in vlan_config['untagged']:
                interface_vlans['untagged'].append(vlan_id)
        
        # 判断端口模式
        if interface_name.startswith('ve'):
            port_mode = 'Routed'
            # 查找IP地址
            ip_match = re.search(patterns.get('ip_address'), interface_config)
            if ip_match:
                ip = ip_match.group(1)
                if ip_match.group(2):  # CIDR格式
                    mask_bits = ip_match.group(2)
                    vlan_info = f"IP: {ip}/{mask_bits}"
                elif ip_match.group(3):  # 传统格式
                    mask = ip_match.group(3)
                    vlan_info = f"IP: {ip} {mask}"
        elif interface_vlans['untagged'] and not interface_vlans['tagged']:
            # 只有untagged VLAN - Access端口
            port_mode = 'Access'
            vlan_info = f"VLAN {interface_vlans['untagged'][0]}"
        elif interface_vlans['tagged']:
            # 有tagged VLAN - Trunk端口
            port_mode = 'Trunk'
            vlans_str = ','.join(map(str, sorted(interface_vlans['tagged'])))
            if interface_vlans['untagged']:
                vlans_str += f" (Native: {interface_vlans['untagged'][0]})"
            vlan_info = f"VLANs: {vlans_str}"
        elif interface_name.startswith('lag'):
            # LAG接口
            port_mode = 'LAG'
            if interface_vlans['tagged'] or interface_vlans['untagged']:
                vlans_str = ','.join(map(str, sorted(interface_vlans['tagged'])))
                if interface_vlans['untagged']:
                    vlans_str += f" (Native: {interface_vlans['untagged'][0]})"
                vlan_info = f"VLANs: {vlans_str}"
        
        # 提取速率和双工设置
        configured_speed = ''
        duplex = ''
        speed_duplex_match = re.search(r'speed-duplex\s+(\d+)-(\w+)', interface_config)
        if speed_duplex_match:
            configured_speed = f"{speed_duplex_match.group(1)}M"
            duplex = speed_duplex_match.group(2)
        
        # 额外信息
        extra_info = {}
        
        # LAG成员信息
        lag_match = re.search(patterns.get('lag_member'), interface_config)
        if lag_match:
            lag_type = lag_match.group(1)  # dynamic或static
            lag_id = lag_match.group(2)
            extra_info['lag_member'] = f"LAG {lag_id} ({lag_type})"
        
        # 堆叠成员信息（从接口名提取）
        if interface_info.get('format') == 'ruckus_stack':
            extra_info['stack_member'] = f"Unit-{interface_info['stack_unit']}"
        
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
        
        return interface_data
    
    def _parse_standard_interface(self, interface_name: str, interface_speed: str,
                                interface_config: str, interface_info: Dict,
                                patterns: Dict, vendor: str) -> Dict:
        """解析标准接口配置（非Ruckus）"""
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
        else:
            # 判断接口状态（非华为设备）
            shutdown = bool(re.search(patterns.get('shutdown', r'shutdown'), interface_config, re.MULTILINE))
            status = 'Admin Down' if shutdown else 'Up'
        
        # 检查是否是路由接口
        if 'routed' in patterns and re.search(patterns['routed'], interface_config):
            port_mode = 'Routed'
            ip_match = re.search(patterns.get('ip_address'), interface_config)
            if ip_match:
                vlan_info = f"IP: {ip_match.group(1)}/{ip_match.group(2)}"
        elif re.search(patterns.get('access', ''), interface_config):
            port_mode = 'Access'
            vlan_match = re.search(patterns.get('access_vlan', ''), interface_config)
            if vlan_match:
                vlan_info = f"VLAN {vlan_match.group(1)}"
        elif re.search(patterns.get('trunk', ''), interface_config):
            port_mode = 'Trunk'
            vlan_match = re.search(patterns.get('trunk_vlan', ''), interface_config)
            if vlan_match:
                vlans = vlan_match.group(1).strip()
                if vendor == 'Huawei':
                    vlans = self.parse_vlan_list_huawei(vlans)
                vlan_info = f"VLANs: {vlans}"
        elif 'hybrid' in patterns and re.search(patterns['hybrid'], interface_config):
            port_mode = 'Hybrid'
            vlan_info = 'Hybrid mode'
        
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
        elif vendor == 'Huawei':
            eth_trunk_match = re.search(patterns.get('eth_trunk', ''), interface_config)
            if eth_trunk_match:
                extra_info['eth_trunk'] = f"Eth-Trunk{eth_trunk_match.group(1)}"
        
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
        
        return interface_data
    
    def normalize_interface_name(self, interface: str, vendor: str = None) -> Tuple[str, str]:
        """
        标准化接口名称并识别速率
        返回: (标准化名称, 速率)
        """
        # Ruckus特殊处理
        if vendor == 'Ruckus' and interface.lower().startswith('ethernet'):
            # Ruckus使用小写ethernet，保持原样
            parts = interface.split()
            if len(parts) >= 2:
                # 根据端口号判断速率
                port_info = parts[1].split('/')
                if len(port_info) >= 3:
                    port_num = int(port_info[2])
                    # 通常1-48是1G，49-56是10G（根据型号可能不同）
                    if port_num <= 48:
                        return interface, '1G'
                    else:
                        return interface, '10G'
            return interface, 'Variable'
        
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
    
    def parse_interface_number(self, interface: str) -> Dict:
        """解析接口编号，支持各种格式"""
        # 提取接口类型和编号
        match = re.match(r'([A-Za-z\-\s]+?)\s*([\d/:\.]+.*)', interface)
        if not match:
            return {'type': 'Unknown', 'numbers': [], 'format': 'unknown'}
        
        interface_type = match.group(1).strip()
        numbers_str = match.group(2)
        
        # 解析不同的编号格式
        if '/' in numbers_str:
            numbers = numbers_str.strip('/').split('/')
            
            # Ruckus格式检测
            if interface_type.lower() == 'ethernet' and len(numbers) == 3:
                # Ruckus格式: stack/module/port
                return {
                    'type': interface_type,
                    'format': 'ruckus_stack',
                    'stack_unit': numbers[0],
                    'module': numbers[1],
                    'port': numbers[2],
                    'numbers': numbers
                }
            elif len(numbers) == 4:
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
            # 简单格式: Ethernet1, ve1, lag 1
            return {
                'type': interface_type,
                'format': 'simple',
                'port': numbers_str,
                'numbers': [numbers_str]
            }
    
    def parse_vlan_list_huawei(self, vlan_str: str) -> str:
        """解析华为的VLAN列表，将to转换为标准格式"""
        vlan_str = re.sub(r'(\d+)\s+to\s+(\d+)', r'\1-\2', vlan_str)
        return vlan_str.strip()
    
    def detect_vendor(self, content: str) -> str:
        """检测设备厂商"""
        content_lower = content.lower()
        
        # 按优先级检测
        vendor_priority = ['Ruckus', 'Huawei', 'H3C', 'Cisco', 'Arista', 'Juniper']
        
        for vendor in vendor_priority:
            patterns = self.vendor_patterns[vendor]
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
            if vendor == 'Ruckus':
                if 'ICX' in info['model']:
                    info['device_type'] = f"ICX {info['model']} Series"
                
                # 检测堆叠信息
                stack_matches = re.findall(patterns.get('stack_info', ''), content)
                if stack_matches:
                    info['stack_units'] = list(set(stack_matches))
                    info['device_type'] += f" (Stack: {len(info['stack_units'])} units)"
        
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
        lag_ports = sum(1 for i in interfaces if i['port_mode'] == 'LAG')
        
        # 按速率统计
        speed_stats = {}
        for intf in interfaces:
            speed = intf.get('interface_speed', 'Unknown')
            speed_stats[speed] = speed_stats.get(speed, 0) + 1
        
        # 堆叠信息
        stack_info = {}
        if vendor == 'Ruckus' and 'stack_units' in device_info:
            stack_info['stack_members'] = len(device_info['stack_units'])
            stack_info['stack_member_list'] = device_info['stack_units']
        elif device_info.get('device_type') == 'Catalyst 9000 Series':
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
                'lag_ports': lag_ports,
                'unknown_ports': total_ports - access_ports - trunk_ports - routed_ports - lag_ports,
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
                    'LAG端口数': result['statistics'].get('lag_ports', 0),
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
                        if 'lag_member' in intf:
                            intf_row['LAG成员'] = intf['lag_member']
                        if 'channel_group' in intf:
                            intf_row['端口聚合'] = intf['channel_group']
                        if 'eth_trunk' in intf:
                            intf_row['链路聚合'] = intf['eth_trunk']
                        
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

# 创建Ruckus ICX示例配置
def create_ruckus_sample_config():
    """创建Ruckus ICX设备示例配置"""
    sample_config = """Current configuration:
!
ver 08.0.95gT211
!
stack unit 1
  module 1 icx7150-48p-poe-port-management-module
  module 2 icx7150-2-copper-port-2g-module
  module 3 icx7150-4-sfp-plus-port-40g-module
  stack-port 1/3/1
  stack-port 1/3/3
!
stack unit 2
  module 1 icx7150-48p-poe-port-management-module
  module 2 icx7150-2-copper-port-2g-module
  module 3 icx7150-4-sfp-plus-port-40g-module
  stack-port 2/3/2
  stack-port 2/3/4
!
!
hostname "ICX7150-Stack"
!
vlan 1 name DEFAULT-VLAN by port
!
vlan 10 name USERS by port
 tagged ethernet 1/1/49 to 1/1/52 ethernet 2/1/49 to 2/1/52
 untagged ethernet 1/1/1 to 1/1/24
 spanning-tree 802-1w
!
vlan 20 name SERVERS by port
 tagged ethernet 1/1/49 to 1/1/52 ethernet 2/1/49 to 2/1/52
 untagged ethernet 1/1/25 to 1/1/48 ethernet 2/1/1 to 2/1/24
 router-interface ve 20
 spanning-tree 802-1w
!
vlan 100 name MANAGEMENT by port
 tagged ethernet 1/1/49 to 1/1/52 ethernet 2/1/49 to 2/1/52 lag 1
 router-interface ve 100
 spanning-tree 802-1w
!
!
lag "LAG-TO-CORE" dynamic id 1
 ports ethernet 1/2/1 ethernet 1/2/2
 primary-port 1/2/1
 deploy
!
!
interface ethernet 1/1/1
 port-name "User-Port-01"
 enable
!
interface ethernet 1/1/25
 port-name "Server-Port-01"
 speed-duplex 1000-full
 enable
!
interface ethernet 1/1/49
 port-name "Uplink-to-Core-1"
 speed-duplex 10g-full
 enable
!
interface ethernet 2/1/1
 port-name "Server-Port-25"
 enable
!
interface ethernet 1/2/1
 port-name "LAG-Member-1"
 lag dynamic id 1
 enable
!
interface ethernet 1/2/2
 port-name "LAG-Member-2"
 lag dynamic id 1
 enable
!
interface lag 1
 port-name "LAG-TO-CORE"
 enable
!
interface ve 20
 port-name "Server-VLAN-Interface"
 ip address 192.168.20.1/24
!
interface ve 100
 port-name "Management-Interface"
 ip address 192.168.100.1/24
!
!
end
"""
    
    with open('sample_ruckus_config.txt', 'w', encoding='utf-8') as f:
        f.write(sample_config)
    
    print("**Ruckus ICX设备示例配置文件已创建: sample_ruckus_config.txt**")

def main():
    """主函数"""
    parser = NetworkConfigParser()
    
    # 可选：创建示例配置
    # create_ruckus_sample_config()
    
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
