import pefile
from typing import Dict, Any, List, Set

# Danh sách các API khả nghi thường được mã độc sử dụng.
# Được phân loại theo hành vi để dễ bảo trì và mở rộng.
SUSPICIOUS_APIS: Set[str] = {
    # Process Injection & Memory Manipulation
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtWriteVirtualMemory",
    "RtlMoveMemory",
    # Process & Thread Control
    "CreateProcessA",
    "CreateProcessW",
    "OpenProcess",
    "ShellExecuteA",
    "ShellExecuteW",
    "WinExec",
    # DLL Loading & Function Resolution (Dynamic API Resolution)
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "LdrLoadDll",
    # Hooking & Keylogging
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "GetAsyncKeyState",
    # Anti-Debugging & Evasion
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    # Networking & Download
    "InternetOpenA",
    "InternetOpenW",
    "InternetOpenUrlA",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    # Registry Manipulation (Persistence)
    "RegSetValueExA",
    "RegSetValueExW",
    "RegCreateKeyExA",
    # Cryptography (Ransomware indicators)
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptAcquireContextA",
}


def analyze_imports_exports(pe: pefile.PE) -> Dict[str, Any]:
    """
    Trích xuất bảng Imports (IAT) và bảng Exports từ file PE.
    Đồng thời đối chiếu các hàm import với danh sách API khả nghi.

    Args:
        pe (pefile.PE): Đối tượng file PE đã được nạp bằng thư viện pefile.

    Returns:
        Dict[str, Any]: Dictionary chứa imports, exports, suspicious_imports và trạng thái.
    """
    result: Dict[str, Any] = {
        "status": "success",
        "error_message": None,
        "imports": {},
        "exports": [],
        "suspicious_imports": []
    }

    suspicious_found: List[str] = []

    # --- Xử lý Imports (riêng biệt để lỗi không ảnh hưởng Exports) ---
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') and pe.DIRECTORY_ENTRY_IMPORT:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                # Decode tên DLL an toàn
                try:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                except Exception:
                    dll_name = "UNKNOWN_DLL"

                func_names: List[str] = []

                for imp in entry.imports:
                    if imp.name:
                        # Import bằng tên hàm
                        try:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                        except Exception:
                            func_name = f"ord_{imp.ordinal}" if imp.ordinal else "UNKNOWN"
                    elif imp.ordinal:
                        # Import bằng số thứ tự (ordinal)
                        func_name = f"ord_{imp.ordinal}"
                    else:
                        continue  # Bỏ qua entry rỗng, tránh đưa None vào mảng

                    func_names.append(func_name)

                    # Đối chiếu với danh sách Suspicious APIs
                    if func_name in SUSPICIOUS_APIS:
                        suspicious_found.append(func_name)

                if func_names:
                    result["imports"][dll_name] = func_names

    except pefile.PEFormatError as e:
        result["status"] = "partial_error"
        result["error_message"] = f"Lỗi định dạng PE khi đọc Imports: {str(e)}"
    except Exception as e:
        result["status"] = "partial_error"
        result["error_message"] = f"Lỗi không xác định khi đọc Imports: {str(e)}"

    # --- Xử lý Exports (riêng biệt để lỗi không ảnh hưởng Imports) ---
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    try:
                        export_name = exp.name.decode('utf-8', errors='ignore')
                    except Exception:
                        export_name = f"ord_{exp.ordinal}" if exp.ordinal else "UNKNOWN"
                elif exp.ordinal:
                    export_name = f"ord_{exp.ordinal}"
                else:
                    continue  # Bỏ qua entry rỗng

                result["exports"].append(export_name)

    except pefile.PEFormatError as e:
        error_msg = f"Lỗi định dạng PE khi đọc Exports: {str(e)}"
        if result["error_message"]:
            result["error_message"] += f" | {error_msg}"
        else:
            result["status"] = "partial_error"
            result["error_message"] = error_msg
    except Exception as e:
        error_msg = f"Lỗi không xác định khi đọc Exports: {str(e)}"
        if result["error_message"]:
            result["error_message"] += f" | {error_msg}"
        else:
            result["status"] = "partial_error"
            result["error_message"] = error_msg

    # Loại bỏ trùng lặp nhưng giữ nguyên thứ tự (Python 3.7+)
    result["suspicious_imports"] = list(dict.fromkeys(suspicious_found))

    # Nếu cả hai khối đều lỗi thì status là "error" thay vì "partial_error"
    if not result["imports"] and not result["exports"] and result["error_message"]:
        result["status"] = "error"

    return result
