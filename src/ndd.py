import os
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# Unity 资源包的标准文件头魔术字 (UnityFS)
UNITY_MAGIC = b"UnityFS"
# 查找文件头的最大扫描范围（防止非 Unity 资源导致死循环）
MAX_SCAN_BYTES = 1024


def process_bundle(src_path, dst_path):
    """处理单个 bundle 文件：寻找 UnityFS 并切除前方多余字节"""
    try:
        if not os.path.exists(src_path):
            return f"ERROR: 文件不存在: {src_path}"

        with open(src_path, "rb") as f:
            # 读取前 1024 字节寻找 UnityFS 标志
            header_chunk = f.read(MAX_SCAN_BYTES)
            pos = header_chunk.find(UNITY_MAGIC)

            if pos == -1:
                return f"SKIP: 未找到 UnityFS 魔术头, 已跳过: {os.path.basename(src_path)}"

            # 定位到 UnityFS 起始位置，流式写入新文件
            f.seek(pos)

            # 确保目标文件夹存在
            os.makedirs(os.path.dirname(dst_path), exist_ok=True)

            with open(dst_path, "wb") as out_f:
                # 每次读取 4MB，流式写入，防止大文件爆内存
                while True:
                    chunk = f.read(4 * 1024 * 1024)
                    if not chunk:
                        break
                    out_f.write(chunk)

        return f"SUCCESS: 成功修复 (切除 {pos} 字节): {os.path.basename(src_path)}"

    except Exception as e:
        return f"ERROR: 处理 {os.path.basename(src_path)} 时出错: {str(e)}"


def main():
    # 配置命令行参数解析
    parser = argparse.ArgumentParser(
        description="Unity .bundle 文件混淆前缀切除工具 (纯净原生版)"
    )
    parser.add_argument(
        "-i", "--input", required=True, help="包含原始 bundle 文件的文件夹路径"
    )
    parser.add_argument(
        "-o", "--output", required=True, help="修复后 bundle 文件的输出文件夹路径"
    )
    args = parser.parse_args()

    input_folder = args.input
    output_folder = args.output

    if not os.path.exists(input_folder):
        print(f"错误: 输入文件夹不存在 '{input_folder}'")
        return

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # 扫描任务
    tasks = []
    for root, _, files in os.walk(input_folder):
        for file in files:
            if file.lower().endswith(".bundle"):
                src_file_path = os.path.join(root, file)
                relative_path = os.path.relpath(src_file_path, input_folder)
                dst_file_path = os.path.join(output_folder, relative_path)
                tasks.append((src_file_path, dst_file_path))

    total_tasks = len(tasks)
    if total_tasks == 0:
        print("未在输入文件夹中找到任何 .bundle 文件。")
        return

    print(f"开始处理，共找到 {total_tasks} 个 .bundle 文件...")

    success_count = 0
    skip_count = 0
    fail_count = 0
    errors = []

    # 使用多线程加速
    with ThreadPoolExecutor() as executor:
        future_to_file = {
            executor.submit(process_bundle, src, dst): src for src, dst in tasks
        }

        completed_count = 0
        for future in as_completed(future_to_file):
            completed_count += 1
            try:
                res = future.result()
                if res.startswith("SUCCESS"):
                    success_count += 1
                elif res.startswith("SKIP"):
                    skip_count += 1
                else:
                    fail_count += 1
                    errors.append(res)
            except Exception as e:
                fail_count += 1
                errors.append(f"ERROR: 线程未知异常: {str(e)}")

            # 原生终端单行刷新进度条效果 (\r)
            percent = (completed_count / total_tasks) * 100
            sys.stdout.write(
                f"\r进度: [{completed_count}/{total_tasks}] {percent:.1f}% | 成功: {success_count} | 跳过: {skip_count} | 失败: {fail_count}"
            )
            sys.stdout.flush()

    # 打印最终结果
    print("\n\n工作完成！")
    print(f"  - 成功修复: {success_count} 个")
    print(f"  - 无需处理: {skip_count} 个")
    print(f"  - 修复失败: {fail_count} 个")

    if errors:
        print("\n失败详情:")
        for err in errors:
            print(f"  {err}")


if __name__ == "__main__":
    main()
