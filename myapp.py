import os
from nornir import InitNornir
from nornir.plugins.tasks.networking import netmiko_send_command
from nornir.plugins.functions.text import print_result
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def execute_device_commands(task):
    """
    针对每台设备执行其特定的多条命令，并处理错误。
    """
    commands = task.host.get("commands", [])
    results = []

    for command in commands:
        result = task.run(task=netmiko_send_command, command_string=command, use_enable=True) #增加enable模式
        if result.failed:
            logging.error(f"Device {task.host.name}, command '{command}' failed: {result.result}")
            results.append({"command": command, "status": "failed", "output": result.result})
        else:
            logging.info(f"Device {task.host.name}, command '{command}' success")
            results.append({"command": command, "status": "success", "output": result.result})

    task.host["output"] = results

def save_results(nr, output_folder):
    """
    保存每台设备的结果到指定的文件夹，并处理错误。
    """
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
        logging.info(f"创建文件夹: {output_folder}")

    for host in nr.inventory.hosts.values():
        file_path = os.path.join(output_folder, f"{host.name}.txt")
        try:
            with open(file_path, "w", encoding="utf-8") as file:
                file.write(f"Device: {host.name}\n")
                file.write("Execution Results:\n")
                for result in host["output"]:
                    file.write(f"Command: {result['command']}\n")
                    file.write(f"Status: {result['status']}\n")
                    file.write(f"Output: {result['output']}\n\n")
            logging.info(f"结果已保存至: {file_path}")
        except Exception as e:
            logging.error(f"保存结果到 {file_path} 失败: {e}")

def main(config_file, output_folder, group_name=None):#增加group_name参数
    nr = InitNornir(config_file=config_file)
    if group_name:
        filtered_nr = nr.filter(group=group_name)
    else:
        filtered_nr = nr

    results = filtered_nr.run(task=execute_device_commands)
    print_result(results)
    save_results(filtered_nr, output_folder)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="使用 Nornir 执行设备特定命令并保存结果")
    parser.add_argument("--config", required=True, help="Nornir 配置文件路径")
    parser.add_argument("--output", required=True, help="保存结果的文件夹路径")
    parser.add_argument("--group", required=False, help="需要运行的组名")#增加group参数
    args = parser.parse_args()
    main(args.config, args.output, args.group)
