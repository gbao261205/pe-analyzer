import re
import pefile
from typing import Dict, Any, Set, List

# --- Regex Patterns biên dịch sẵn để tăng tốc so khớp ---
# Dùng re.IGNORECASE cho các pattern cần khớp cả chữ hoa/thường.

COMPILED_PATTERNS: Dict[str, re.Pattern] = {
    # IPv4: 4 octet (0-255), phân tách bằng dấu chấm
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
    ),

    # URLs: http, https, ftp, smb
    "urls": re.compile(
        r'(?:https?|ftp|smb)://[^\s<>\"\'\x00]+',
        re.IGNORECASE
    ),

    # Registry Keys: HKLM, HKCU, HKCR, HKU, HKCC hoặc dạng đầy đủ
    "registry": re.compile(
        r'(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|'
        r'HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)'
        r'(?:\\[^\s<>\"\x00]+)+',
        re.IGNORECASE
    ),

    # Commands: các tiến trình/lệnh thường bị mã độc lạm dụng
    "commands": re.compile(
        r'(?:cmd\.exe|powershell(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|'
        r'mshta(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|'
        r'vssadmin(?:\.exe)?|schtasks(?:\.exe)?|regsvr32(?:\.exe)?|'
        r'rundll32(?:\.exe)?|msiexec(?:\.exe)?)'
        r'(?:\s[^\x00]*)?',
        re.IGNORECASE
    ),

    # Emails: Chỉ báo Ransomware - mã độc tống tiền thường để lại email liên hệ
    "emails": re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b'
    ),

    # Bitcoin Wallets: Địa chỉ ví BTC (Legacy P2PKH/P2SH và Bech32)
    "bitcoin": re.compile(
        r'\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b'
    ),

    # Standalone Domains: Tên miền không có giao thức, hardcode trong binary
    "domains": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
        r'(?:com|net|org|xyz|top|info|io|ru|cn|tk|ml|ga|cf|gq|cc|pw|biz|ws|su|onion)\b',
        re.IGNORECASE
    ),

    # IPv6: Địa chỉ IPv6 đầy đủ hoặc rút gọn
    "ipv6": re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
    ),

    # MAC Address: Địa chỉ vật lý thiết bị mạng (AA:BB:CC:DD:EE:FF hoặc AA-BB-CC-DD-EE-FF)
    "mac_address": re.compile(
        r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'
    ),
}

# Regex trích xuất chuỗi thô từ mảng byte
_ASCII_PATTERN: re.Pattern = re.compile(rb'[ -~]{4,}')
_UNICODE_PATTERN: re.Pattern = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')


def extract_raw_strings(data: bytes) -> Set[str]:
    """
    Trích xuất toàn bộ chuỗi ASCII và Unicode (UTF-16 LE) từ mảng byte thô.
    Chỉ giữ lại các chuỗi có độ dài >= 4 ký tự.

    Args:
        data (bytes): Mảng byte thô của toàn bộ file PE.

    Returns:
        Set[str]: Tập hợp các chuỗi duy nhất đã decode.
    """
    strings: Set[str] = set()

    if not data:
        return strings

    # Trích xuất chuỗi ASCII
    try:
        for match in _ASCII_PATTERN.finditer(data):
            try:
                decoded = match.group().decode('ascii', errors='ignore')
                if decoded:
                    strings.add(decoded)
            except Exception:
                continue
    except Exception:
        pass  # Bỏ qua nếu quá trình quét ASCII gặp lỗi

    # Trích xuất chuỗi Unicode (UTF-16 LE)
    try:
        for match in _UNICODE_PATTERN.finditer(data):
            try:
                decoded = match.group().decode('utf-16-le', errors='ignore')
                if decoded and len(decoded) >= 4:
                    strings.add(decoded)
            except Exception:
                continue
    except Exception:
        pass  # Bỏ qua nếu quá trình quét Unicode gặp lỗi

    return strings


def analyze_strings(pe: pefile.PE) -> Dict[str, Any]:
    """
    Trích xuất chuỗi từ toàn bộ file PE nhị phân và phân loại các IoCs
    (Indicators of Compromise) bằng Regex.

    Args:
        pe (pefile.PE): Đối tượng file PE đã được nạp bằng thư viện pefile.

    Returns:
        Dict[str, Any]: Dictionary chứa tổng số chuỗi, các IoCs phân loại, và trạng thái.
    """
    result: Dict[str, Any] = {
        "status": "success",
        "error_message": None,
        "total_strings_count": 0,
        "iocs": {
            "ipv4": [],
            "ipv6": [],
            "mac_address": [],
            "urls": [],
            "domains": [],
            "emails": [],
            "bitcoin": [],
            "registry": [],
            "commands": [],
        }
    }

    try:
        # Đọc toàn bộ mảng byte thô của file PE (bao gồm cả Overlay)
        raw_data: bytes = pe.__data__

        # Trích xuất chuỗi thô
        all_strings: Set[str] = extract_raw_strings(raw_data)
        result["total_strings_count"] = len(all_strings)

        # Dùng set tạm để loại trùng lặp cho từng danh mục IoC
        ioc_sets: Dict[str, Set[str]] = {
            "ipv4": set(),
            "ipv6": set(),
            "mac_address": set(),
            "urls": set(),
            "domains": set(),
            "emails": set(),
            "bitcoin": set(),
            "registry": set(),
            "commands": set(),
        }

        # Duyệt từng chuỗi và so khớp với các pattern
        for string in all_strings:
            for category, pattern in COMPILED_PATTERNS.items():
                try:
                    matches = pattern.findall(string)
                    for match in matches:
                        cleaned = match.strip()
                        if cleaned:
                            ioc_sets[category].add(cleaned)
                except Exception:
                    continue

        # Chuyển set sang list cho output JSON
        for category in ioc_sets:
            result["iocs"][category] = sorted(ioc_sets[category])

    except pefile.PEFormatError as e:
        result["status"] = "error"
        result["error_message"] = f"Lỗi định dạng PE khi trích xuất chuỗi: {str(e)}"
    except Exception as e:
        result["status"] = "error"
        result["error_message"] = f"Lỗi không xác định khi trích xuất chuỗi: {str(e)}"

    return result
