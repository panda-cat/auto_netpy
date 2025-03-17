from nornir import InitNornir
from nornir_netmiko import netmiko_send_command
from nornir_utils.plugins.functions import print_result
from datetime import datetime
import os
import openpyxl

def excel_to_nornir(excel_file: str) -> None:
    """将Excel数据转换为Nornir清单"""
    wb = openpyxl.load_workbook(excel_file)
    sheet = wb.active
    
    # 生成hosts.yaml内容
    hosts = {}
    groups = {}
    
    for row in sheet.iter_rows(min_row=2, values_only=True):
        host_data = {
            "hostname": row[0],
            "platform": row[3],
            "groups": [f"{row[3]}_group"],
            "data": {
                "commands": row[6].split(";"),
                "secret": row[4],
                "readtime": row[5]
            }
        }
        hosts[row[0]] = host_data
        
        # 创建设备组
        group_name = f"{row[3]}_group"
        groups.setdefault(group_name, {
            "username": row[1],
            "password": row[2],
            "connection_options": {
                "netmiko": {
                    "extras": {
                        "secret": row[4],
                        "read_timeout_override": int(row[5])
                    }
                }
            }
        })
    
    # 生成YAML文件
    with open("inventories/hosts.yaml", "w") as f:
        f.write("---\n")
        for host, data in hosts.items():
            f.write(f"{host}:\n")
            for k, v in data.items():
                f.write(f"  {k}: {v}\n")

def save_results(result, host) -> None:
    """保存执行结果"""
    date_str = datetime.now().strftime("%Y%m%d")
    output_dir = f"results/result_{date_str}"
    os.makedirs(output_dir, exist_ok=True)
    
    filename = f"{host.hostname}_{host.name}.txt"
    with open(os.path.join(output_dir, filename), "w") as f:
        for cmd_result in result:
            f.write(f"=== Command: {cmd_result.command} ===\n")
            f.write(cmd_result.result + "\n\n")

def main():
    # 初始化Nornir
    nr = InitNornir(config_file="config.yaml")
    
    # 执行任务
    results = nr.run(
        task=netmiko_send_command,
        command_string=nr.config.inventory.hosts[
            nr.current_host.name].data["commands"]
    )
    
    # 处理结果
    for host, result in results.items():
        if result.failed:
            with open("error_log.txt", "a") as f:
                f.write(f"{datetime.now()} | {host} | {result.exception}\n")
        else:
            save_results(result, host)
    
    print_result(results)

if __name__ == "__main__":
    # 转换Excel数据
    excel_to_nornir("devices.xlsx")
    
    # 执行主程序
    main()
