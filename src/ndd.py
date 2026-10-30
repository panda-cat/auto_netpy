import argparse
import os
from pathlib import Path


def process_files(input_dir, output_dir):
    # 使用 pathlib 自动转换并处理跨平台路径
    src_path = Path(input_dir)
    out_path = Path(output_dir)

    # 如果输出文件夹不存在，则自动创建（parents=True 确保多级目录也能创建）
    out_path.mkdir(parents=True, exist_ok=True)

    success_count = 0

    # 遍历源文件夹
    for file_path in src_path.glob("*.txt"):
        # 兼容一些系统下可能出现的同名大小写或隐藏文件问题
        if file_path.is_dir():
            continue

        out_file_path = out_path / file_path.name

        try:
            extracted_lines = []
            is_recording = False

            # 使用 utf-8 编码，并忽略无法识别的字节（跨平台传输文件常有编码乱码问题）
            with open(
                file_path, "r", encoding="utf-8", errors="ignore"
            ) as f:
                for line in f:
                    if "Command: dis cur" in line:
                        is_recording = True
                        continue

                    if is_recording:
                        extracted_lines.append(line)
                        if "return" in line:
                            break

            if extracted_lines:
                with open(out_file_path, "w", encoding="utf-8") as f:
                    f.writelines(extracted_lines)
                success_count += 1
                print(f"成功提取: {file_path.name}")
            else:
                print(f"未找到匹配区间跳过: {file_path.name}")

        except Exception as e:
            print(f"处理失败 {file_path.name}: {e}")

    print(f"\n批量提取完成！共成功处理 {success_count} 个文件。")


if __name__ == "__main__":
    # 配置命令行参数解析
    parser = argparse.ArgumentParser(
        description="批量提取 TXT 文件中特定区间的文本内容（跨平台版）"
    )
    parser.add_argument(
        "-i",
        "--input",
        required=True,
        help="输入文件夹路径 (存放原始 TXT 文件)",
    )
    parser.add_argument(
        "-o", "--output", required=True, help="输出文件夹路径"
    )

    args = parser.parse_args()

    # 执行核心处理逻辑
    process_files(args.input, args.output)
