import cv2
import os
import sys
import numpy as np
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import (
    Progress,
    SpinnerColumn,
    TimeElapsedColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)
from rich.console import Console

# 蒙版文件后缀，不区分大小写
MASK_SUFFIXES = ["_alpha", "_mask", "[alpha]"]
NUM_THREADS = multiprocessing.cpu_count()


def normalize_filename(filename):
    """标准化文件名以便于匹配"""
    return filename.lower().replace("[", "_").replace("]", "_")


def analyze_image(img):
    """分析图片特征"""
    if img is None or len(img.shape) < 2:
        return None

    channels = img.shape[2] if len(img.shape) > 2 else 1
    info = {
        "shape": img.shape,
        "channels": channels,
    }

    channel_names = (
        ["B", "G", "R", "A"]
        if channels == 4
        else (["B", "G", "R"] if channels == 3 else ["Gray"])
    )

    for i in range(channels):
        channel = img[:, :, i] if channels > 1 else img
        name = channel_names[i]
        info[f"{name}_stats"] = {
            "min": int(np.min(channel)),
            "max": int(np.max(channel)),
            "mean": float(np.mean(channel)),
            "unique_values": len(np.unique(channel)),
        }

    return info


def determine_alpha_type(alpha_img):
    """
    判断alpha图片的类型
    返回: 'arknights', 'gfl', 'rgb_mask' 或 None
    """
    if alpha_img is None:
        return None

    info = analyze_image(alpha_img)
    if info is None:
        return None

    # 如果是 4 通道图像
    if info["channels"] == 4:
        # 少女前线类型特征：RGB通道全255，A通道有变化
        if (
            info["B_stats"]["min"] == 255
            and info["B_stats"]["max"] == 255
            and info["G_stats"]["min"] == 255
            and info["G_stats"]["max"] == 255
            and info["R_stats"]["min"] == 255
            and info["R_stats"]["max"] == 255
            and info["A_stats"]["unique_values"] > 1
        ):
            return "gfl"

        # 明日方舟类型特征：RGB通道有变化，A通道接近全不透明
        elif (
            info["B_stats"]["unique_values"] > 1
            and info["G_stats"]["unique_values"] > 1
            and info["R_stats"]["unique_values"] > 1
            and info["A_stats"]["min"] >= 254
        ):
            return "arknights"

    # 白鲸回廊类型特征：3 通道图像
    elif info["channels"] == 3:
        return "rgb_mask"

    return None


def get_alpha_channel(alpha_img):
    """提取alpha通道"""
    if alpha_img is None:
        return None, "没有 Alpha 图片"

    alpha_type = determine_alpha_type(alpha_img)
    debug_info = {"type": alpha_type, "shape": alpha_img.shape}

    try:
        if alpha_type == "gfl":
            # 直接使用A通道
            alpha = alpha_img[:, :, 3]
            debug_info["method"] = "direct_alpha"
            return alpha, debug_info

        elif alpha_type == "arknights":
            # 直接使用RGB通道（转灰度）
            alpha = cv2.cvtColor(alpha_img[:, :, :3], cv2.COLOR_BGR2GRAY)
            debug_info["method"] = "rgb_to_gray"
            return alpha, debug_info

        elif alpha_type == "rgb_mask":
            # 通道蒙版，直接转灰度
            if len(alpha_img.shape) == 3:
                alpha = cv2.cvtColor(alpha_img, cv2.COLOR_BGR2GRAY)
            else:
                alpha = alpha_img
            debug_info["method"] = "3ch_to_gray"
            return alpha, debug_info

        return None, f"Unknown alpha image type. Stats: {analyze_image(alpha_img)}"

    except Exception as e:
        return None, f"Error processing alpha: {str(e)}, Debug info: {debug_info}"


def find_alpha_file(base_name, all_files_dict):
    """在所有文件中查找对应的alpha文件"""
    for suffix in MASK_SUFFIXES:
        potential_mask = f"{base_name}{suffix}.png"
        potential_mask_normalized = normalize_filename(potential_mask)
        if potential_mask_normalized in all_files_dict:
            return all_files_dict[potential_mask_normalized]
    return None


def merge_images(file_info, all_files_dict):
    """合并RGB图像和alpha通道图像"""
    full_path, file = file_info

    if not file.lower().endswith(".png"):
        return None

    base_name = file[:-4]
    mask_file_path = find_alpha_file(base_name, all_files_dict)
    if not mask_file_path:
        return f"对于文件 '{file}' 未找到匹配的蒙版文件"

    src = cv2.imread(full_path, cv2.IMREAD_UNCHANGED)
    alpha_img = cv2.imread(mask_file_path, cv2.IMREAD_UNCHANGED)

    if src is None:
        return f"无法读取源图像: {file}"
    if alpha_img is None:
        return f"无法读取蒙版图像: {os.path.basename(mask_file_path)}"

    alpha_channel, debug_info = get_alpha_channel(alpha_img)
    if alpha_channel is None:
        return f"无法从文件 '{os.path.basename(mask_file_path)}' 提取alpha通道: {debug_info}"

    h, w = src.shape[:2]
    alpha_resized = cv2.resize(alpha_channel, (w, h), interpolation=cv2.INTER_CUBIC)

    if len(src.shape) == 2:
        dst = cv2.merge([src, alpha_resized])
    else:
        dst = cv2.merge(
            [
                src[:, :, 0],  # B
                src[:, :, 1],  # G
                src[:, :, 2],  # R
                alpha_resized,  # A
            ]
        )

    # 尝试写入，写入成功后再移除蒙版文件，防止异常丢失数据
    if cv2.imwrite(full_path, dst):
        try:
            os.remove(mask_file_path)
        except OSError as e:
            return f"成功合并但移除蒙版失败: {full_path} (原因: {str(e)})"
        return f"成功合并: {full_path}"
    else:
        return f"无法保存合并后的图像: {full_path}"


def main():
    console = Console()

    # 修复：防止没有传参时引发 sys.argv[1] IndexError 崩溃
    if len(sys.argv) < 2:
        console.print("[red]错误: 请设置输入文件夹路径！[/red]")
        console.print("[yellow]用法: python merge_masks.py <文件夹路径>[/yellow]")
        return

    input_folder = sys.argv[1]

    if not os.path.exists(input_folder):
        console.print(f"[red]错误: 路径不存在 '{input_folder}'[/red]")
        return

    target_images = []  # 存放待处理的原图
    all_files_dict = {}  # 存放所有文件以供蒙版匹配

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
    ) as progress:
        scan_task = progress.add_task("[cyan]扫描文件...", total=None)

        for root, _, files in os.walk(input_folder):
            for file in files:
                full_path = os.path.join(root, file)
                file_lower = file.lower()
                
                # 记录所有文件以便查找
                all_files_dict[normalize_filename(file)] = full_path

                # 优化：如果在扫描时发现是蒙版文件，则不加入待处理队列
                if any(suffix.lower() in file_lower for suffix in MASK_SUFFIXES):
                    continue

                if file_lower.endswith(".png"):
                    target_images.append((full_path, file))

        progress.update(
            scan_task,
            completed=True,
            description=f"[green]扫描完成，找到 {len(target_images)} 个待合并目标[/green]",
        )

        if not target_images:
            console.print("[yellow]未找到需要合并的 PNG 原图文件。[/yellow]")
            return

        merge_task = progress.add_task("[cyan]处理文件...", total=len(target_images))
        results = []

        with ThreadPoolExecutor(max_workers=NUM_THREADS) as executor:
            future_to_file = {
                executor.submit(merge_images, file_info, all_files_dict): file_info[1]
                for file_info in target_images
            }

            for future in as_completed(future_to_file):
                filename = future_to_file[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    results.append(f"[red]处理 {filename} 时发生严重错误: {str(e)}[/red]")
                progress.update(merge_task, advance=1)

    console.print("\n[bold]处理完成[/bold]")

    success_count = sum(1 for r in results if r and r.startswith("成功合并"))
    error_count = sum(1 for r in results if r and not r.startswith("成功合并"))

    console.print(f"[green]成功处理: {success_count} 个文件[/green]")
    if error_count > 0:
        console.print(f"[yellow]忽略或失败: {error_count} 个项目[/yellow]")
        console.print("\n[yellow]详情日志:[/yellow]")
        for result in results:
            if result and not result.startswith("成功合并"):
                console.print(result)


if __name__ == "__main__":
    main()
