from nornir import InitNornir
from nornir.core.task import Task, Result
from nornir_utils.plugins.functions import print_result
from nornir_netmiko import netmiko_send_command
from datetime import datetime
import os
import sys
import argparse
import yaml
from typing import Dict, List, Optional

# --------------------------
# 配置管理模块
# --------------------------
def load_command_map() -> Dict:
    """加载多平台命令映射"""
    with open("command_maps.yaml", encoding='utf-8') as f:
        return yaml.safe_load(f)

COMMAND_MAP = load_command_map()

# --------------------------
# 工具函数
# --------------------------
def sanitize_filename(name: str) -> str:
    """生成安全文件名"""
    invalid_chars = r'<>:"/\|?*'
    return ''.join(c for c in name if c not in invalid_chars).strip()[:50]

def get_platform_commands(host, command_type: str) -> List[str]:
    """获取平台适配的命令列表"""
    # 优先级: 设备级 > 组级 > 全局默认
    platform = host.platform or 'default'
    custom_cmds = host.get('custom_commands', {}).get(command_type)
    
    if custom_cmds:
        return custom_cmds if isinstance(custom_cmds, list) else [custom_cmds]
    
    group_cmds = []
    for group in host.groups:
        if group.get('custom_commands', {}).get(command_type):
            group_cmds.extend(group['custom_commands'][command_type])
    if group_cmds:
        return group_cmds
    
    return COMMAND_MAP.get(platform, {}).get(command_type, [])

# --------------------------
# 核心任务
# --------------------------
def execute_commands(task: Task, output_dir: str) -> Result:
    """执行设备命令任务"""
    host = task.host
    try:
        # 获取平台适配的命令
        commands = get_platform_commands(host, 'get_config')
        if not commands:
            raise ValueError("未找到该平台的命令配置")
        
        # 执行命令
        results = []
        for cmd in commands:
            result = task.run(
                task=netmiko_send_command,
                command_string=cmd,
                enable=True if host.platform == 'cisco_ios' else False
            )
            results.append(result.result)
        
        # 保存结果
        save_results(task, results, output_dir)
        return Result(host=host, result=results, changed=False)
    
    except Exception as e:
        log_error(host, str(e))
        return Result(host=host, result=str(e), failed=True)

def save_results(task: Task, results: List[str], output_dir: str):
    """保存执行结果"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    ip = task.host.hostname
    platform = task.host.platform
    
    filename = f"{sanitize_filename(ip)}_{platform}_{timestamp}.txt"
    content = f"=== 设备 {ip} ({platform}) 执行结果 ===\n\n"
    
    for i, (cmd, output) in enumerate(zip(
        get_platform_commands(task.host, 'get_config'), 
        results
    )):
        content += f"[命令 {i+1}]\n{cmd}\n\n[输出]\n{output}\n{'='*40}\n"
    
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, filename), 'w') as f:
        f.write(content)

def log_error(host, error: str):
    """记录错误日志"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] {host.hostname} ({host.platform}) - {error}\n"
    
    with open("operation_errors.log", 'a') as f:
        f.write(log_entry)

# --------------------------
# 主程序
# --------------------------
def main(output_dir: Optional[str], workers: int):
    # 初始化Nornir
    nr = InitNornir(
        runner={
            "plugin": "threaded",
            "options": {
                "num_workers": workers,
            }
        },
        inventory={
            "plugin": "SimpleInventory",
            "options": {
                "host_file": "inventory/hosts.yaml",
                "group_file": "inventory/groups.yaml",
                "defaults_file": "inventory/defaults.yaml",
            }
        }
    )
    
    # 设置输出目录
    final_output = output_dir or f"results_{datetime.now().strftime('%Y%m%d')}"
    
    # 执行任务
    result = nr.run(
        task=execute_commands,
        output_dir=final_output
    )
    
    # 输出统计
    success = len(result) - len(result.failed_hosts)
    print(f"\n执行统计:")
    print(f"  成功: {success} 台")
    print(f"  失败: {len(result.failed_hosts)} 台")
    print(f"结果目录: {os.path.abspath(final_output)}")
    print(f"错误日志: operation_errors.log")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="网络设备批量运维工具")
    parser.add_argument("-o", "--output", 
                       help="指定输出目录路径", 
                       metavar="DIR")
    parser.add_argument("-t", "--threads", 
                       type=int, 
                       default=4, 
                       help="并发线程数 (默认: 4)")
    args = parser.parse_args()
    
    main(output_dir=args.output, workers=args.threads)
