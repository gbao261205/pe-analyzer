from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from typing import Dict, Any, List
from core.constants import MAX_BATCH_SUMMARY_DISPLAY

# Đối tượng Console toàn cục cho module UI
console = Console()

# --- Quy chuẩn màu sắc SOC/Cybersecurity ---
_CLR_SAFE = "bold green"
_CLR_WARN = "bold yellow"
_CLR_DANGER = "bold red"
_CLR_INFO = "bold cyan"
_CLR_DIM = "dim"


def render_hashes(hash_data: Dict[str, Any]) -> None:
    """
    Hiển thị thông tin mã băm (Hashes) ra terminal.
    
    Args:
        hash_data (Dict[str, Any]): Dictionary trả về từ core/hashes.py.
    """
    console.print()
    console.print(f"[{_CLR_INFO}]{'═' * 60}[/]")
    console.print(f"[{_CLR_INFO}]  #  FILE IDENTIFICATION (HASHES)[/]")
    console.print(f"[{_CLR_INFO}]{'═' * 60}[/]")

    status = hash_data.get("status", "error")
    if status == "error":
        error_msg = hash_data.get("error_message", "Lỗi không xác định.")
        console.print(Panel(
            f"[{_CLR_DANGER}]✘ {error_msg}[/]",
            title="[bold]Hash Analysis Error[/]",
            border_style="red"
        ))
        return

    md5 = hash_data.get("md5", "N/A")
    sha256 = hash_data.get("sha256", "N/A")
    imphash = hash_data.get("imphash", "N/A")
    tlsh_hash = hash_data.get("tlsh", "N/A")

    hash_text = Text()
    hash_text.append("MD5:     ", style="bold white")
    hash_text.append(f"{md5}\n", style=_CLR_INFO)
    
    hash_text.append("SHA-256: ", style="bold white")
    hash_text.append(f"{sha256}\n", style=_CLR_INFO)
    
    hash_text.append("Imphash: ", style="bold white")
    hash_text.append(f"{imphash}\n", style=_CLR_WARN)
    
    hash_text.append("TLSH:    ", style="bold white")
    hash_text.append(f"{tlsh_hash}", style=_CLR_SAFE)

    console.print(Panel(
        hash_text,
        title="[bold]Cryptographic & Fuzzy Hashes[/]",
        border_style="cyan",
        padding=(1, 2)
    ))


def render_signature(signature_data: Dict[str, Any]) -> None:
    """
    Hiển thị trạng thái Chữ ký số Authenticode ra terminal.

    Args:
        signature_data (Dict[str, Any]): Dictionary trả về từ core/signature.py.
    """
    is_signed = signature_data.get("is_signed", False)
    status = signature_data.get("status", "error")

    if status == "error":
        error_msg = signature_data.get("error_message", "Lỗi không xác định.")
        console.print(f"  [{_CLR_WARN}]⚠ Authenticode: {error_msg}[/]")
    elif is_signed:
        console.print(f"  [{_CLR_SAFE}]✔ Authenticode: Signed (Presence Only - Validity Unverified)[/]")
    else:
        console.print(f"  [{_CLR_WARN}]⚠ Authenticode: Unsigned (Không có chữ ký số)[/]")

    console.print()

def render_yara(yara_data: Dict[str, Any]) -> None:
    """
    Hiển thị kết quả quét YARA ra terminal.
    
    Args:
        yara_data (Dict[str, Any]): Dictionary trả về từ core/yara_scanner.py.
    """
    console.print()
    console.print(f"[{_CLR_INFO}]{'═' * 60}[/]")
    console.print(f"[{_CLR_INFO}]  ☢  YARA SCAN RESULTS[/]")
    console.print(f"[{_CLR_INFO}]{'═' * 60}[/]")

    status = yara_data.get("status", "error")
    error_msg = yara_data.get("error_message", "")
    
    if status == "error":
        console.print(Panel(
            f"[{_CLR_DANGER}]✘ Lỗi quét YARA:[/] {error_msg}",
            border_style="red"
        ))
        return
        
    if status == "no_rules":
        console.print(Panel(
            f"[{_CLR_WARN}]⚠ Cảnh báo:[/] {error_msg}",
            border_style="yellow"
        ))
        return

    matches = yara_data.get("yara_matches", [])
    
    if not matches:
        console.print(Panel(
            f"[{_CLR_SAFE}]✔ Không phát hiện bất kỳ dấu hiệu mã độc nào dựa trên tập luật YARA.[/]",
            border_style="green"
        ))
    else:
        table = Table(
            show_header=True,
            header_style="bold magenta",
            border_style="red",
            title=f"[bold]🚨 {len(matches)} YARA Rules Triggered![/]",
            title_style="bold white",
            expand=True,
        )
        table.add_column("#", style="dim", width=4, justify="center")
        table.add_column("Rule Name", style=_CLR_DANGER, overflow="fold", no_wrap=False)

        for idx, rule in enumerate(matches, start=1):
            table.add_row(str(idx), rule)

        console.print(table)




def render_risk_score(scoring_data: Dict[str, Any]) -> None:
    """
    Hiển thị thông tin tổng hợp điểm rủi ro và các lý do.
    
    Args:
        scoring_data (Dict[str, Any]): Dữ liệu điểm rủi ro trả về từ module scoring.
    """
    console.print()
    
    score = scoring_data.get("risk_score", 0)
    level = scoring_data.get("risk_level", "SAFE")
    reasons = scoring_data.get("reasons", [])

    if level == "CRITICAL":
        color = "red"
        text_color = _CLR_DANGER
        icon = "⛔"
    elif level == "HIGH":
        color = "red"
        text_color = _CLR_DANGER
        icon = "🚨"
    elif level == "MEDIUM":
        color = "yellow"
        text_color = _CLR_WARN
        icon = "⚠"
    elif level == "LOW":
        color = "yellow"
        text_color = _CLR_WARN
        icon = "⚠"
    else:
        color = "green"
        text_color = _CLR_SAFE
        icon = "✔"

    text = Text()
    text.append(f"Risk Score: ", style="bold white")
    text.append(f"{score}/100\n", style=text_color)
    text.append(f"Risk Level: ", style="bold white")
    text.append(f"{icon} {level}\n", style=text_color)
    
    if reasons:
        text.append("\n[ Reasons for Score ]\n", style="bold white")
        for r in reasons:
            text.append(f"  • {r}\n", style="dim white")
    else:
        text.append("\nFile an toàn, không có dấu hiệu mã độc.", style="dim white")

    console.print(Panel(
        text,
        title="[bold]Threat Risk Assessment[/]",
        border_style=color,
        padding=(1, 2)
    ))


def render_sections(section_data: Dict[str, Any]) -> None:
    """
    Hiển thị bảng phân tích Sections (Entropy, Permissions, Size Anomaly) ra terminal.

    Args:
        section_data (Dict[str, Any]): Dictionary trả về từ core/sections.py.
    """
    console.print()
    console.print(f"[{_CLR_INFO}]{'═' * 60}[/]")
    console.print(f"[{_CLR_INFO}]  ⚙  SECTION ANALYSIS[/]")
    console.print(f"[{_CLR_INFO}]{'═' * 60}[/]")

    # Kiểm tra lỗi
    status = section_data.get("status", "error")
    if status == "error":
        error_msg = section_data.get("error_message", "Lỗi không xác định.")
        console.print(Panel(
            f"[{_CLR_DANGER}]✘ {error_msg}[/]",
            title="[bold]Section Analysis Error[/]",
            border_style="red"
        ))
        return

    total = section_data.get("total_sections", 0)
    sections = section_data.get("sections", [])

    if total == 0:
        console.print(f"  [{_CLR_DIM}]Không tìm thấy section nào.[/]")
        return

    console.print(f"  Tổng số sections: [{_CLR_INFO}]{total}[/]")
    console.print()

    # Xây dựng bảng
    table = Table(
        show_header=True,
        header_style="bold magenta",
        border_style="bright_blue",
        title=f"[bold]PE Sections Overview[/]",
        title_style="bold white",
        expand=True,
    )
    table.add_column("#", style="dim", width=3, justify="center")
    table.add_column("Name", min_width=10)
    table.add_column("Virtual Addr", min_width=10, justify="center")
    table.add_column("Virtual Size", min_width=10, justify="right")
    table.add_column("Raw Size", min_width=10, justify="right")
    table.add_column("Entropy", min_width=8, justify="center")
    table.add_column("Perms", min_width=6, justify="center")
    table.add_column("Flags", min_width=14, justify="center")
    table.add_column("Status", min_width=10, justify="center")

    for idx, sec in enumerate(sections, start=1):
        name = sec.get("name", "N/A")
        vaddr = sec.get("virtual_address", "N/A")
        vsize = sec.get("virtual_size", 0)
        rsize = sec.get("raw_size", 0)
        entropy = sec.get("entropy", 0.0)
        perms = sec.get("perms", {})
        is_rwx = sec.get("is_rwx", False)
        has_size_anomaly = sec.get("has_size_anomaly", False)
        is_suspicious = sec.get("is_suspicious", False)

        # Chuỗi quyền rút gọn: R/W/X
        perm_str = ""
        perm_str += "R" if perms.get("read", False) else "-"
        perm_str += "W" if perms.get("write", False) else "-"
        perm_str += "X" if perms.get("execute", False) else "-"

        # Cờ cảnh báo chi tiết
        flags: List[str] = []
        if is_rwx:
            flags.append("RWX")
        if entropy > 7.2:
            flags.append("HIGH_ENTROPY")
        if has_size_anomaly:
            flags.append("SIZE_ANOMALY")

        flags_str = ", ".join(flags) if flags else "—"

        # Quyết định màu sắc và trạng thái
        if is_suspicious:
            row_style = _CLR_DANGER
            status_label = "⛔ DANGER"
        else:
            row_style = _CLR_SAFE
            status_label = "✔ CLEAN"

        table.add_row(
            str(idx),
            Text(name, style=row_style),
            Text(vaddr, style=row_style),
            Text(f"{vsize:,}", style=row_style),
            Text(f"{rsize:,}", style=row_style),
            Text(str(entropy), style=_CLR_DANGER if entropy > 7.2 else _CLR_SAFE),
            Text(perm_str, style=_CLR_DANGER if is_rwx else _CLR_SAFE),
            Text(flags_str, style=_CLR_DANGER if flags else _CLR_DIM),
            Text(status_label, style=row_style),
        )

    console.print(table)


def render_imports(import_data: Dict[str, Any]) -> None:
    """
    Hiển thị bảng Imports/Exports và danh sách Suspicious APIs ra terminal.

    Args:
        import_data (Dict[str, Any]): Dictionary trả về từ core/imports_exports.py.
    """
    console.print()
    console.print(f"[{_CLR_INFO}]{'═' * 60}[/]")
    console.print(f"[{_CLR_INFO}]  📦  IMPORTS / EXPORTS ANALYSIS[/]")
    console.print(f"[{_CLR_INFO}]{'═' * 60}[/]")

    # Nhận diện .NET Framework
    is_dot_net = import_data.get("is_dot_net", False)
    if is_dot_net:
        console.print(Panel(
            "[bold cyan]🔷 Architecture: C# .NET Framework[/]\n"
            "[dim]File này sử dụng mscoree.dll — mã trung gian (IL/MSIL). "
            "Entropy cao ở .rsrc là bình thường.[/]",
            border_style="cyan",
            padding=(0, 2),
        ))

    # Kiểm tra lỗi
    status = import_data.get("status", "error")
    error_msg = import_data.get("error_message")
    if status == "error":
        console.print(Panel(
            f"[{_CLR_DANGER}]✘ {error_msg or 'Lỗi không xác định.'}[/]",
            title="[bold]Import/Export Error[/]",
            border_style="red"
        ))
        return

    if status == "partial_error" and error_msg:
        console.print(Panel(
            f"[{_CLR_WARN}]⚠ {error_msg}[/]",
            title="[bold]Partial Error[/]",
            border_style="yellow"
        ))

    imports = import_data.get("imports", {})
    exports = import_data.get("exports", [])
    suspicious = import_data.get("suspicious_imports", [])

    # --- Panel cảnh báo Suspicious APIs ---
    if suspicious:
        suspicious_text = Text()
        for i, api in enumerate(suspicious):
            if i > 0:
                suspicious_text.append("  •  ", style=_CLR_DIM)
            suspicious_text.append(api, style=_CLR_DANGER)

        console.print(Panel(
            suspicious_text,
            title=f"[{_CLR_DANGER}]🚨 Suspicious APIs Detected: {len(suspicious)}[/]",
            border_style="red",
            padding=(1, 2),
        ))
    else:
        console.print(f"  [{_CLR_SAFE}]✔ Không phát hiện API khả nghi.[/]")

    console.print()

    # --- Bảng Imports ---
    if imports:
        table = Table(
            show_header=True,
            header_style="bold magenta",
            border_style="bright_blue",
            title="[bold]Import Address Table (IAT)[/]",
            title_style="bold white",
            expand=True,
        )
        table.add_column("DLL", style=_CLR_WARN, min_width=20)
        table.add_column("Functions", min_width=40)

        suspicious_set = set(suspicious)

        for dll_name, functions in imports.items():
            # Xây dựng chuỗi hàm với highlight cho suspicious
            func_text = Text()
            for i, func in enumerate(functions):
                if i > 0:
                    func_text.append(", ", style=_CLR_DIM)
                if func in suspicious_set:
                    func_text.append(func, style=_CLR_DANGER)
                else:
                    func_text.append(func)

            table.add_row(dll_name, func_text)

        console.print(table)
    else:
        console.print(f"  [{_CLR_DIM}]Không có dữ liệu Import.[/]")

    # --- Exports ---
    console.print()
    if exports:
        export_text = Text()
        for i, exp in enumerate(exports):
            if i > 0:
                export_text.append("  •  ", style=_CLR_DIM)
            export_text.append(exp, style=_CLR_WARN)

        console.print(Panel(
            export_text,
            title=f"[{_CLR_INFO}]📤 Exported Functions: {len(exports)}[/]",
            border_style="cyan",
            padding=(1, 2),
        ))
    else:
        console.print(f"  [{_CLR_DIM}]Không có hàm Export.[/]")


def render_strings_iocs(strings_data: Dict[str, Any]) -> None:
    """
    Hiển thị kết quả trích xuất chuỗi và phân loại IoCs ra terminal.

    Args:
        strings_data (Dict[str, Any]): Dictionary trả về từ core/strings_analyzer.py.
    """
    console.print()
    console.print(f"[{_CLR_INFO}]{'═' * 60}[/]")
    console.print(f"[{_CLR_INFO}]  🔍  SMART STRINGS & IoCs ANALYSIS[/]")
    console.print(f"[{_CLR_INFO}]{'═' * 60}[/]")

    # Kiểm tra lỗi
    status = strings_data.get("status", "error")
    if status == "error":
        error_msg = strings_data.get("error_message", "Lỗi không xác định.")
        console.print(Panel(
            f"[{_CLR_DANGER}]✘ {error_msg}[/]",
            title="[bold]Strings Analysis Error[/]",
            border_style="red"
        ))
        return

    total_strings = strings_data.get("total_strings_count", 0)
    whitelisted_count = strings_data.get("whitelisted_count", 0)
    iocs = strings_data.get("iocs", {})

    console.print(f"  Tổng số chuỗi trích xuất: [{_CLR_INFO}]{total_strings}[/]")
    if whitelisted_count > 0:
        console.print(
            f"  Đã lọc bỏ (Whitelist):   [{_CLR_DIM}]{whitelisted_count} IoCs an toàn[/]"
        )
    console.print()

    # Cấu hình hiển thị cho từng loại IoC: (key, icon, label, color)
    ioc_display_config = [
        ("ipv4", "🌐", "IPv4 Addresses", _CLR_DANGER),
        ("ipv6", "🌐", "IPv6 Addresses", _CLR_WARN),
        ("mac_address", "🔌", "MAC Addresses", _CLR_WARN),
        ("urls", "🔗", "URLs", _CLR_DANGER),
        ("domains", "🌍", "Standalone Domains", _CLR_DANGER),
        ("emails", "📧", "Email Addresses (Ransomware IoC)", _CLR_DANGER),
        ("bitcoin", "₿", "Bitcoin Wallets (Ransomware IoC)", _CLR_DANGER),
        ("registry", "🗝", "Registry Keys", _CLR_WARN),
        ("commands", "💻", "Suspicious Commands", _CLR_DANGER),
    ]

    has_any_ioc = False

    for key, icon, label, color in ioc_display_config:
        items = iocs.get(key, [])
        if not items:
            continue

        has_any_ioc = True

        table = Table(
            show_header=True,
            header_style="bold magenta",
            border_style="bright_blue",
            title=f"[bold]{icon} {label} ({len(items)})[/]",
            title_style="bold white",
            expand=True,
        )
        table.add_column("#", style="dim", width=4, justify="center")
        table.add_column("Value", style=color, overflow="fold", no_wrap=False)

        for i, item in enumerate(items, start=1):
            table.add_row(str(i), item)

        console.print(table)
        console.print()

    if not has_any_ioc:
        console.print(Panel(
            f"[{_CLR_SAFE}]✔ Không phát hiện IoC đáng ngờ nào trong chuỗi.[/]",
            border_style="green",
        ))


def render_batch_summary(results: List[Dict[str, Any]]) -> None:
    """
    Hiển thị bảng tóm tắt kết quả Batch Scan.
    Chỉ hiển thị tối đa 20 file khả nghi nhất, sắp xếp theo mức độ nguy hiểm.

    Args:
        results (List[Dict[str, Any]]): Danh sách kết quả phân tích từ run_batch_scan().
    """
    console.print()
    console.print(f"[{_CLR_INFO}]{'═' * 60}[/]")
    console.print(f"[{_CLR_INFO}]  📊  BATCH SCAN SUMMARY[/]")
    console.print(f"[{_CLR_INFO}]{'═' * 60}[/]")

    total_scanned = len(results)
    suspicious_results = [r for r in results if r.get("is_suspicious", False)]
    corrupted_count = sum(1 for r in results if r.get("status_type") == "corrupted")
    error_count = sum(1 for r in results if r.get("status_type") == "system_error")
    clean_count = total_scanned - len(suspicious_results) - corrupted_count - error_count

    # Thống kê tổng quan
    console.print(f"\n  Tổng số file đã quét:       [{_CLR_INFO}]{total_scanned}[/]")
    console.print(f"  File sạch (Clean):          [{_CLR_SAFE}]{clean_count}[/]")
    console.print(f"  File khả nghi (Suspicious): [{_CLR_DANGER}]{len(suspicious_results)}[/]")

    if corrupted_count > 0:
        console.print(f"  File lỗi định dạng (Corrupted): [dim yellow]{corrupted_count}[/]")

    if error_count > 0:
        console.print(
            f"  Lỗi hệ thống (System Errors):  [bold red]{error_count}[/]"
            f"  [dim]— Chi tiết xem tại reports/error.log[/]"
        )

    console.print()

    if not suspicious_results:
        console.print(Panel(
            f"[{_CLR_SAFE}]✔ Không phát hiện file nào khả nghi trong thư mục.[/]",
            border_style="green",
        ))
        return

    # Sắp xếp theo mức độ nguy hiểm (risk_score) giảm dần
    suspicious_results.sort(key=lambda r: r.get("risk_score", 0), reverse=True)

    # Giới hạn hiển thị tối đa
    display_results = suspicious_results[:MAX_BATCH_SUMMARY_DISPLAY]

    if len(suspicious_results) > MAX_BATCH_SUMMARY_DISPLAY:
        console.print(
            f"  [{_CLR_WARN}]⚠ Hiển thị top {MAX_BATCH_SUMMARY_DISPLAY}/{len(suspicious_results)} "
            f"file khả nghi nhất.[/]"
        )
        console.print()

    table = Table(
        show_header=True,
        header_style="bold magenta",
        border_style="bright_blue",
        title="[bold]🚨 Suspicious Files Detected[/]",
        title_style="bold white",
        expand=True,
    )
    table.add_column("#", style="dim", width=3, justify="center")
    table.add_column("File Name", min_width=25, overflow="fold", no_wrap=False)
    table.add_column("Size", min_width=10, justify="right")
    table.add_column("Susp. APIs", min_width=10, justify="center")
    table.add_column("Section Flags", min_width=16, overflow="fold", no_wrap=False)
    table.add_column("IoCs", min_width=6, justify="center")
    table.add_column("Risk", min_width=6, justify="center")
    table.add_column("Status", min_width=10, justify="center")

    for idx, item in enumerate(display_results, start=1):
        file_name = item.get("file_name", "N/A")
        file_size = item.get("file_size", 0)
        suspicious_apis = item.get("suspicious_api_count", 0)
        section_flags = item.get("section_flags", [])
        iocs_count = item.get("iocs_count", 0)
        risk_score = item.get("risk_score", 0)

        # Format kích thước file dễ đọc
        if file_size >= 1_048_576:
            size_str = f"{file_size / 1_048_576:.1f} MB"
        elif file_size >= 1024:
            size_str = f"{file_size / 1024:.1f} KB"
        else:
            size_str = f"{file_size} B"

        flags_str = ", ".join(section_flags) if section_flags else "—"

        # Màu theo risk score mới (0-100)
        risk_level = item.get("risk_level", "SAFE")
        if risk_level == "CRITICAL":
            row_style = _CLR_DANGER
            status_label = "⛔ CRITICAL"
        elif risk_level == "HIGH":
            row_style = _CLR_DANGER
            status_label = "🚨 HIGH"
        elif risk_level == "MEDIUM":
            row_style = _CLR_WARN
            status_label = "⚠ MEDIUM"
        elif risk_level == "LOW":
            row_style = _CLR_WARN
            status_label = "⚠ LOW"
        else:
            row_style = _CLR_SAFE
            status_label = "✔ SAFE"

        is_signed = item.get("is_signed", False)
        prefix_icon = "[bold green]✔[/] " if is_signed else "[bold yellow]⚠[/] "
        
        file_name_display = Text.from_markup(f"{prefix_icon}")
        file_name_display.append(file_name, style=row_style)

        table.add_row(
            str(idx),
            file_name_display,
            Text(size_str, style=_CLR_DIM),
            Text(str(suspicious_apis), style=_CLR_DANGER if suspicious_apis > 0 else _CLR_DIM),
            Text(flags_str, style=_CLR_DANGER if section_flags else _CLR_DIM),
            Text(str(iocs_count), style=_CLR_DANGER if iocs_count > 0 else _CLR_DIM),
            Text(str(risk_score), style=row_style),
            Text(status_label, style=row_style),
        )

    console.print(table)
    console.print("  [dim]Ghi chú: ([bold green]✔[/dim]) File có chữ ký số | ([bold yellow]⚠[/dim]) File không có chữ ký số (Unsigned)[/]")
