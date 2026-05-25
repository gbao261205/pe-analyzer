import os
import sys
import pefile
from typing import List, Dict, Any

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
from core.yara_scanner import scan_with_yara
from core.signature import check_signature
from core.scoring import calculate_risk_score
from utils.exporter import export_to_json
from rich.panel import Panel

# ═══════════════════════════════════════════════════════════
#  PE STATIC FEATURE EXTRACTOR — Entry Point
#  Maintainer: Nguyễn Gia Bảo
# ═══════════════════════════════════════════════════════════

# Các đuôi file thực thi phổ biến cần quét
_PE_EXTENSIONS = {".exe", ".dll", ".sys", ".bin"}

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

_MODE_MENU = """
[bold cyan]  ╔══════════════════════════════════════════════════════════╗
  ║                  🚀  SCAN MODE                         ║
  ╠══════════════════════════════════════════════════════════╣
  ║                                                        ║
  ║   [bold yellow][1][/bold yellow]  📄 Phân tích một file PE (Single Scan)            ║
  ║   [bold yellow][2][/bold yellow]  📁 Quét thư mục hàng loạt (Batch Scan)            ║
  ║                                                        ║
  ║   [bold red][0][/bold red]  🚪 Thoát chương trình                             ║
  ║                                                        ║
  ╚══════════════════════════════════════════════════════════╝[/]
"""

_ANALYSIS_MENU = """
[bold cyan]  ╔══════════════════════════════════════════════════════════╗
  ║                    📋  ANALYSIS MENU                   ║
  ╠══════════════════════════════════════════════════════════╣
  ║                                                        ║
  ║   [bold yellow][1][/bold yellow]  ⚙  Phân tích YARA, Score, Hashes & Sections      ║
  ║   [bold yellow][2][/bold yellow]  📦 Phân tích Imports / Exports (Suspicious APIs)  ║
  ║   [bold yellow][3][/bold yellow]  🔍 Phân tích Strings & IoCs (IP, Domains, Cmds)   ║
  ║   [bold yellow][4][/bold yellow]  📄 Xuất báo cáo JSON                              ║
  ║                                                        ║
  ║   [bold red][0][/bold red]  🔙 Quay lại chọn chế độ                            ║
  ║                                                        ║
  ╚══════════════════════════════════════════════════════════╝[/]
"""


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
            if ext in _PE_EXTENSIONS:
                pe_files.append(os.path.join(root, f))
    return pe_files


def run_batch_scan(directory: str) -> List[Dict[str, Any]]:
    """
    Quét hàng loạt tất cả file PE trong thư mục, hiển thị thanh tiến trình,
    và trả về danh sách kết quả tóm tắt.

    Args:
        directory (str): Đường dẫn thư mục cần quét.

    Returns:
        List[Dict[str, Any]]: Danh sách kết quả phân tích từng file.
    """
    # Thu thập danh sách file
    console.print(f"\n  [dim]⏳ Đang quét thư mục: {directory}...[/]")
    pe_files = collect_pe_files(directory)

    if not pe_files:
        console.print("  [bold yellow]⚠ Không tìm thấy file PE nào trong thư mục.[/]")
        return []

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
                yara_data = scan_with_yara(file_path)
                hash_data = calculate_hashes(file_path, pe)
                section_data = analyze_sections(pe)
                import_data = analyze_imports_exports(pe)
                strings_data = analyze_strings(pe)
                signature_data = check_signature(pe)

                # --- 7. Tính điểm rủi ro ---
                scoring_data = calculate_risk_score(section_data, import_data, strings_data, yara_data, signature_data)
                risk_score = scoring_data.get("risk_score", 0)
                risk_level = scoring_data.get("risk_level", "SAFE")
                is_suspicious = risk_score >= 16

                # --- Đánh giá nhanh (Dành cho Summary Table) ---
                section_flags: List[str] = []

                # Kiểm tra sections
                for sec in section_data.get("sections", []):
                    if sec.get("is_rwx", False):
                        section_flags.append("RWX")
                    if sec.get("entropy", 0) > 7.2:
                        section_flags.append("HIGH_ENTROPY")
                    if sec.get("has_size_anomaly", False):
                        section_flags.append("SIZE_ANOMALY")

                # Loại trùng lặp flags
                section_flags = list(dict.fromkeys(section_flags))

                suspicious_apis = import_data.get("suspicious_imports", [])
                suspicious_api_count = len(suspicious_apis)

                # Kiểm tra IoCs
                iocs = strings_data.get("iocs", {})
                iocs_count = sum(len(v) for v in iocs.values() if isinstance(v, list))

                scan_results.append({
                    "file_name": file_name,
                    "file_path": file_path,
                    "file_size": file_size,
                    "is_suspicious": is_suspicious,
                    "risk_score": risk_score,
                    "risk_level": risk_level,
                    "suspicious_api_count": suspicious_api_count,
                    "section_flags": section_flags,
                    "iocs_count": iocs_count,
                    "is_signed": signature_data.get("is_signed", False),
                })

            except (pefile.PEFormatError, Exception):
                # File rác hoặc PE bị hỏng — bỏ qua, không in lỗi để giữ progress bar
                scan_results.append({
                    "file_name": file_name,
                    "file_path": file_path,
                    "file_size": file_size,
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

    return scan_results


def pause() -> None:
    """Chờ người dùng nhấn Enter trước khi quay lại Menu."""
    console.input("\n  [dim][ Nhấn Enter để quay lại Menu... ][/]")


def run_single_scan() -> None:
    """Chế độ phân tích chi tiết một file PE duy nhất."""
    pe = None

    try:
        file_path = get_file_path()
        pe = load_pe(file_path)

        # Chạy phân tích
        console.print("\n  [dim]⏳ Đang phân tích file...[/]")
        yara_data = scan_with_yara(file_path)
        hash_data = calculate_hashes(file_path, pe)
        section_data = analyze_sections(pe)
        import_data = analyze_imports_exports(pe)
        strings_data = analyze_strings(pe)
        signature_data = check_signature(pe)
        scoring_data = calculate_risk_score(section_data, import_data, strings_data, yara_data, signature_data)
        console.print("  [bold green]✔ Phân tích hoàn tất![/]")
        console.input("\n  [dim][ Nhấn Enter để vào Menu phân tích... ][/]")

        # Vòng lặp Analysis Menu
        while True:
            clear_screen()
            print_banner()
            console.print(
                f"  [bold white]📄 File đang phân tích:[/] [bold yellow]{file_path}[/]"
            )
            console.print(_ANALYSIS_MENU)

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

    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass


def main() -> None:
    """Hàm chính — Entry Point của chương trình."""
    try:
        while True:
            clear_screen()
            print_banner()
            console.print(_MODE_MENU)

            try:
                mode = console.input("  [bold cyan]👉 Chọn chế độ (0-2): [/]").strip()
            except EOFError:
                mode = "0"

            if mode == "1":
                # --- Single Scan ---
                clear_screen()
                print_banner()
                run_single_scan()

            elif mode == "2":
                # --- Batch Scan ---
                clear_screen()
                print_banner()
                dir_path = get_directory_path()
                results = run_batch_scan(dir_path)

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
