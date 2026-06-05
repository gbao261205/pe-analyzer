import os
import sys
import traceback
from datetime import datetime
import logging
import logging.handlers
import multiprocessing
import dataclasses
import pefile
from rich import box
from typing import List, Dict, Any, Optional

from rich.panel import Panel as _Panel
from rich.table import Table as _Table

def Panel(*args, **kwargs):
    kwargs.setdefault('box', box.SQUARE)
    return _Panel(*args, **kwargs)

def Table(*args, **kwargs):
    kwargs.setdefault('box', box.SQUARE)
    return _Table(*args, **kwargs)

from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
    MofNCompleteColumn,
)

from ui.renderer import (
    console,
    render_hashes,
    render_signature,
    render_yara,
    render_risk_score,
    render_sections,
    render_imports,
    render_strings_iocs,
    render_batch_summary,
)
from core.sections import analyze_sections
from core.imports_exports import analyze_imports_exports
from core.strings_analyzer import analyze_strings
from core.hashes import calculate_hashes
from core.yara_scanner import scan_with_yara, compile_yara_rules
from core.signature import check_signature
from core.scoring import calculate_risk_score
from core.constants import PE_EXTENSIONS, DEFAULT_ENTROPY_THRESHOLD, SCORE_LIMIT_SAFE
from utils.exporter import export_to_json
from utils.logger import setup_global_logging, get_app_logger, get_log_file_path, get_standard_formatter
from rich.panel import Panel

# ═══════════════════════════════════════════════════════════
#  PE STATIC FEATURE EXTRACTOR — Entry Point
#  Maintainer: Nguyễn Gia Bảo
# ═══════════════════════════════════════════════════════════

_BANNER = r"""
[bold cyan]
  ██████╗ ███████╗     █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗
  ██╔══██╗██╔════╝    ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
  ██████╔╝█████╗      ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
  ██╔═══╝ ██╔══╝      ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
  ██║     ███████╗     ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║
  ╚═╝     ╚══════╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
[/]
[bold white]  ──────────────────────────────────────────────────────────────────────────────────[/]
[bold green]   ⚡ PE Static Feature Extractor — Malware Analysis CLI Tool[/]
[dim]   Author: Nguyễn Gia Bảo  |  Type: Defensive Cybersecurity  |  Mode: Static Analysis[/]
[bold white]  ──────────────────────────────────────────────────────────────────────────────────[/]
"""

_MODE_MENU_TEXT = """[bold yellow][1][/]  📄 Phân tích một file PE (Single Scan)
[bold yellow][2][/]  📁 Quét thư mục hàng loạt (Batch Scan)

[bold red][0][/]  🚪 Thoát chương trình"""

_ANALYSIS_MENU_TEXT = """[bold yellow][1][/]  ⚙  Phân tích YARA, Score, Hashes & Sections
[bold yellow][2][/]  📦 Phân tích Imports / Exports (Suspicious APIs)
[bold yellow][3][/]  🔍 Phân tích Strings & IoCs (IP, Domains, Cmds)
[bold yellow][4][/]  📄 Xuất báo cáo JSON

[bold red][0][/]  🔙 Quay lại chọn chế độ"""

def clear_screen() -> None:
    """Xóa màn hình terminal, tự nhận diện hệ điều hành."""
    os.system("cls" if os.name == "nt" else "clear")


def print_banner() -> None:
    """In banner ASCII Art của công cụ."""
    console.print(_BANNER)


def get_file_path() -> str:
    """
    Vòng lặp yêu cầu người dùng nhập đường dẫn file PE hợp lệ.

    Returns:
        str: Đường dẫn file PE đã xác nhận tồn tại.
    """
    while True:
        file_path = console.input(
            "\n[bold cyan]  📂 Nhập đường dẫn file PE cần phân tích: [/]"
        ).strip().strip('"').strip("'")

        if not file_path:
            console.print("  [bold red]✘ Đường dẫn không được để trống.[/]")
            continue

        if not os.path.exists(file_path):
            console.print(f"  [bold red]✘ File không tồn tại: {file_path}[/]")
            continue

        if not os.path.isfile(file_path):
            console.print(f"  [bold red]✘ Đường dẫn không phải là file: {file_path}[/]")
            continue

        return file_path


def get_directory_path() -> str:
    """
    Vòng lặp yêu cầu người dùng nhập đường dẫn thư mục hợp lệ.

    Returns:
        str: Đường dẫn thư mục đã xác nhận tồn tại.
    """
    while True:
        dir_path = console.input(
            "\n[bold cyan]  📁 Nhập đường dẫn thư mục cần quét: [/]"
        ).strip().strip('"').strip("'")

        if not dir_path:
            console.print("  [bold red]✘ Đường dẫn không được để trống.[/]")
            continue

        if not os.path.exists(dir_path):
            console.print(f"  [bold red]✘ Thư mục không tồn tại: {dir_path}[/]")
            continue

        if not os.path.isdir(dir_path):
            console.print(f"  [bold red]✘ Đường dẫn không phải là thư mục: {dir_path}[/]")
            continue

        return dir_path


def load_pe(file_path: str) -> pefile.PE:
    """
    Nạp file PE bằng thư viện pefile. Cho phép nhập lại nếu file không hợp lệ.

    Args:
        file_path (str): Đường dẫn file PE.

    Returns:
        pefile.PE: Đối tượng PE đã nạp thành công.
    """
    while True:
        try:
            console.print(f"\n  [dim]⏳ Đang nạp file: {file_path}...[/]")
            pe = pefile.PE(file_path)
            console.print("  [bold green]✔ Nạp file PE thành công![/]")
            return pe
        except pefile.PEFormatError:
            console.print(
                f"  [bold red]✘ File không phải định dạng PE hợp lệ: {file_path}[/]"
            )
            console.print("  [bold yellow]Vui lòng chọn file khác.[/]")
            file_path = get_file_path()
        except Exception as e:
            console.print(
                f"  [bold red]✘ Lỗi không xác định khi nạp file: {e}[/]"
            )
            console.print("  [bold yellow]Vui lòng chọn file khác.[/]")
            file_path = get_file_path()


def collect_pe_files(directory: str) -> List[str]:
    """
    Đệ quy thu thập tất cả file PE trong thư mục theo đuôi mở rộng.

    Args:
        directory (str): Đường dẫn thư mục gốc.

    Returns:
        List[str]: Danh sách đường dẫn tuyệt đối của các file PE tìm được.
    """
    pe_files: List[str] = []
    for root, _dirs, files in os.walk(directory):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in PE_EXTENSIONS:
                pe_files.append(os.path.join(root, f))
    return pe_files


def setup_batch_logging() -> tuple[Optional[multiprocessing.Queue], Optional[logging.handlers.QueueListener]]:
    """Thiết lập logging an toàn cho đa tiến trình sử dụng QueueListener."""
    log_path = get_log_file_path()
    
    log_queue = multiprocessing.Queue(-1)
    file_handler = logging.handlers.RotatingFileHandler(log_path, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(get_standard_formatter())
    
    listener = logging.handlers.QueueListener(log_queue, file_handler)
    listener.start()
    return log_queue, listener


def configure_worker_logger(log_queue: multiprocessing.Queue) -> logging.Logger:
    """Cấu hình logger cho mỗi process/worker trỏ về Queue."""
    logger = logging.getLogger("BatchWorker")
    logger.setLevel(logging.ERROR)
    logger.propagate = False
    
    # Xóa các handler cũ nếu có
    if logger.hasHandlers():
        logger.handlers.clear()
        
    queue_handler = logging.handlers.QueueHandler(log_queue)
    logger.addHandler(queue_handler)
    return logger


def run_batch_scan(directory: str, compiled_rules: Optional["yara.Rules"]) -> List[Dict[str, Any]]:
    """
    Quét hàng loạt tất cả file PE trong thư mục, hiển thị thanh tiến trình,
    và trả về danh sách kết quả tóm tắt.

    Args:
        directory (str): Đường dẫn thư mục cần quét.
        compiled_rules (Optional["yara.Rules"]): Đối tượng luật YARA đã được biên dịch.

    Returns:
        List[Dict[str, Any]]: Danh sách kết quả phân tích từng file.
    """
    # Thu thập danh sách file
    console.print(f"\n  [dim]⏳ Đang quét thư mục: {directory}...[/]")
    pe_files = collect_pe_files(directory)

    if not pe_files:
        console.print("  [bold yellow]⚠ Không tìm thấy file PE nào trong thư mục.[/]")
        return []

    # --- Setup Logging an toàn cho Thread/Process ---
    log_queue, log_listener = setup_batch_logging()
    batch_logger = None
    if log_queue:
        batch_logger = configure_worker_logger(log_queue)

    console.print(f"  [bold cyan]📋 Tìm thấy {len(pe_files)} file PE. Bắt đầu phân tích...[/]\n")

    scan_results: List[Dict[str, Any]] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}[/]"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning PE files", total=len(pe_files))

        for file_path in pe_files:
            file_name = os.path.basename(file_path)

            try:
                file_size = os.path.getsize(file_path)
            except OSError:
                file_size = 0

            pe = None
            try:
                pe = pefile.PE(file_path)

                # --- Chạy 6 module Core ---
                yara_data = scan_with_yara(file_path, compiled_rules)
                hash_data = calculate_hashes(file_path, pe)
                section_data = analyze_sections(pe)
                import_data = analyze_imports_exports(pe)
                strings_data = analyze_strings(pe)
                signature_data = check_signature(pe)

                # --- 7. Tính điểm rủi ro ---
                scoring_data = calculate_risk_score(section_data, import_data, strings_data, yara_data, signature_data)
                risk_score = scoring_data.risk_score
                risk_level = scoring_data.risk_level
                is_suspicious = risk_score > SCORE_LIMIT_SAFE

                # --- Đánh giá nhanh (Dành cho Summary Table) ---
                section_flags: List[str] = []

                # Kiểm tra sections
                for sec in section_data.sections:
                    if sec.is_rwx:
                        section_flags.append("RWX")
                    if sec.entropy > DEFAULT_ENTROPY_THRESHOLD:
                        section_flags.append("HIGH_ENTROPY")
                    if sec.has_size_anomaly:
                        section_flags.append("SIZE_ANOMALY")

                # Loại trùng lặp flags
                section_flags = list(dict.fromkeys(section_flags))

                suspicious_apis = import_data.suspicious_imports
                suspicious_api_count = len(suspicious_apis)

                # Kiểm tra IoCs
                iocs_dict = dataclasses.asdict(strings_data.iocs)
                iocs_count = sum(len(v) for v in iocs_dict.values() if isinstance(v, list))

                scan_results.append({
                    "file_name": file_name,
                    "file_path": file_path,
                    "file_size": file_size,
                    "status_type": "success",
                    "is_suspicious": is_suspicious,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "suspicious_api_count": suspicious_api_count,
                    "section_flags": section_flags,
                    "iocs_count": iocs_count,
                    "is_signed": signature_data.is_signed,
                })

            except pefile.PEFormatError:
                # File không phải định dạng PE hợp lệ hoặc header bị hỏng
                scan_results.append({
                    "file_name": file_name,
                    "file_path": file_path,
                    "file_size": file_size,
                    "status_type": "corrupted",
                    "is_suspicious": False,
                    "risk_score": 0,
                    "risk_level": "SAFE",
                    "suspicious_api_count": 0,
                    "section_flags": [],
                    "iocs_count": 0,
                    "is_signed": False,
                })

            except Exception as e:
                # Lỗi hệ thống hoặc lỗi logic code — ghi log chi tiết ra Queue an toàn
                if batch_logger:
                    batch_logger.error(f"Lỗi khi xử lý file {file_path} - {type(e).__name__}: {e}", exc_info=True)
                    
                scan_results.append({
                    "file_name": file_name,
                    "file_path": file_path,
                    "file_size": file_size,
                    "status_type": "system_error",
                    "is_suspicious": False,
                    "risk_score": 0,
                    "risk_level": "SAFE",
                    "suspicious_api_count": 0,
                    "section_flags": [],
                    "iocs_count": 0,
                    "is_signed": False,
                })

            finally:
                # Giải phóng bộ nhớ cho mỗi file
                if pe is not None:
                    try:
                        pe.close()
                    except Exception:
                        pass

                progress.advance(task)

    # Dọn dẹp Listener khi kết thúc vòng lặp Batch Scan
    if log_listener:
        log_listener.stop()

    return scan_results


def pause() -> None:
    """Chờ người dùng nhấn Enter trước khi quay lại Menu."""
    console.input("\n  [dim][ Nhấn Enter để quay lại Menu... ][/]")


def run_single_scan(compiled_rules: Optional["yara.Rules"]) -> None:
    """Chế độ phân tích chi tiết một file PE duy nhất."""
    pe = None
    logger = get_app_logger()

    try:
        file_path = get_file_path()
        logger.info(f"Bắt đầu phân tích Single Scan cho file: {file_path}")
        pe = load_pe(file_path)

        # Chạy phân tích
        console.print("\n  [dim]⏳ Đang phân tích file...[/]")
        
        yara_data = scan_with_yara(file_path, compiled_rules)
        logger.info("Hoàn tất quét YARA.")
        
        hash_data = calculate_hashes(file_path, pe)
        logger.info("Hoàn tất tính toán mã băm.")
        
        section_data = analyze_sections(pe)
        logger.info("Hoàn tất phân tích phân vùng (Sections).")
        
        import_data = analyze_imports_exports(pe)
        logger.info("Hoàn tất phân tích Imports/Exports.")
        
        strings_data = analyze_strings(pe)
        logger.info("Hoàn tất phân tích chuỗi và trích xuất IoCs.")
        
        signature_data = check_signature(pe)
        logger.info("Hoàn tất kiểm tra chữ ký số Authenticode.")
        
        scoring_data = calculate_risk_score(section_data, import_data, strings_data, yara_data, signature_data)
        
        console.print("  [bold green]✔ Phân tích hoàn tất![/]")
        logger.info("Single Scan hoàn tất.")
        console.input("\n  [dim][ Nhấn Enter để vào Menu phân tích... ][/]")

        # Vòng lặp Analysis Menu
        while True:
            clear_screen()
            print_banner()
            console.print(
                f"  [bold white]📄 File đang phân tích:[/] [bold yellow]{file_path}[/]"
            )
            console.print(Panel(
                _ANALYSIS_MENU_TEXT,
                title="[bold cyan]📋  ANALYSIS MENU[/]",
                border_style="cyan",
                padding=(1, 4),
                width=70
            ))

            try:
                choice = console.input("  [bold cyan]👉 Chọn chức năng (0-4): [/]").strip()
            except EOFError:
                choice = "0"

            if choice == "1":
                clear_screen()
                render_risk_score(scoring_data)
                render_yara(yara_data)
                render_hashes(hash_data)
                render_signature(signature_data)
                render_sections(section_data)
                pause()
            elif choice == "2":
                clear_screen()
                render_imports(import_data)
                pause()
            elif choice == "3":
                clear_screen()
                render_strings_iocs(strings_data)
                pause()
            elif choice == "4":
                clear_screen()
                console.print("\n")
                
                report_path = export_to_json(file_path, hash_data, yara_data, signature_data, section_data, import_data, strings_data, scoring_data)
                
                if report_path:
                    console.print(Panel(
                        f"[bold green]✔ Xuất báo cáo thành công![/]\n\n[dim]Đã lưu tại:[/] [bold cyan]{report_path}[/]",
                        title="[bold]Export JSON[/]",
                        border_style="green"
                    ))
                else:
                    console.print(Panel(
                        f"[bold red]✘ Xuất báo cáo thất bại![/]\n\n[dim]Đã có lỗi xảy ra trong quá trình ghi file.[/]",
                        title="[bold]Export Error[/]",
                        border_style="red"
                    ))
                
                pause()
            elif choice == "0":
                break
            else:
                console.print(
                    "  [bold red]✘ Lựa chọn không hợp lệ. Vui lòng chọn từ 0 đến 4.[/]"
                )
                pause()

    except pefile.PEFormatError as e:
        logger.error(f"Lỗi định dạng PE: {e}")
        console.print(f"  [bold red]✘ Lỗi định dạng PE:[/] {e}")
        pause()
    except Exception as e:
        logger.error(f"Lỗi hệ thống không mong muốn: {e}", exc_info=True)
        console.print(f"  [bold red]✘ Lỗi hệ thống:[/] {e}")
        pause()
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass


def main() -> None:
    """Hàm chạy chính."""
    setup_global_logging()
    logger = get_app_logger()
    logger.info("PE Analyzer bắt đầu khởi chạy.")
    
    try:
        clear_screen()
        print_banner()
        
        # Compile YARA rules once at startup
        compiled_rules = compile_yara_rules()
        if compiled_rules:
            console.print("  [dim cyan][INFO] Đã nạp thành công các luật YARA từ thư mục /rules.[/]\n")
        else:
            console.print("  [bold yellow][WARN] Không tìm thấy luật YARA nào hoặc thư viện chưa được cài đặt. Tính năng quét YARA sẽ bị bỏ qua.[/]\n")
            
        while True:
            console.print(Panel(
            _MODE_MENU_TEXT,
            title="[bold cyan]🚀  SCAN MODE[/]",
            border_style="cyan",
            padding=(1, 4),
            width=60
        ))

            try:
                mode = console.input("  [bold cyan]👉 Chọn chế độ (0-2): [/]").strip()
            except EOFError:
                mode = "0"

            if mode == "1":
                # --- Single Scan ---
                clear_screen()
                print_banner()
                run_single_scan(compiled_rules)

            elif mode == "2":
                # --- Batch Scan ---
                clear_screen()
                print_banner()
                dir_path = get_directory_path()
                results = run_batch_scan(dir_path, compiled_rules)

                if results:
                    clear_screen()
                    print_banner()
                    render_batch_summary(results)
                    pause()

            elif mode == "0":
                break

            else:
                console.print(
                    "  [bold red]✘ Lựa chọn không hợp lệ. Vui lòng chọn 0, 1 hoặc 2.[/]"
                )
                pause()

    except KeyboardInterrupt:
        console.print("\n\n  [bold yellow]⚠ Đã nhận tín hiệu ngắt (Ctrl+C).[/]")

    finally:
        console.print("\n  [bold cyan]👋 Cảm ơn bạn đã sử dụng PE Analyzer. Tạm biệt![/]\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
