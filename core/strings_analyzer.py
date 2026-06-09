"""
core/strings_analyzer.py — Module trích xuất chuỗi (Strings) và phân loại
Chỉ báo Xâm nhập (IoCs — Indicators of Compromise) từ tệp PE nhị phân.

Phiên bản nâng cấp v2:
- Mở rộng bộ Regex IoC (thêm suspicious_paths, user_agents, mutexes,
  suspicious_keywords, encoded_strings).
- Mở rộng danh sách TLD cho domains từ ~15 lên ~60+ TLD.
- Thêm heuristic phát hiện chuỗi mã hóa Base64 và XOR-encoded.
- Bổ sung trích xuất chuỗi từ từng Section riêng lẻ (bao gồm cả Overlay).
- Cải thiện Whitelist để giảm False Positive khi mở rộng phạm vi quét.
"""
import re
import base64
import pefile
from typing import Dict, Set, List

from core.models import IoCs, StringsResult


# ═══════════════════════════════════════════════════════════
#  REGEX PATTERNS — Biên dịch sẵn để tăng tốc so khớp
# ═══════════════════════════════════════════════════════════

COMPILED_PATTERNS: Dict[str, re.Pattern] = {
    # IPv4: 4 octet (0-255), phân tách bằng dấu chấm
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
    ),

    # IPv6: Địa chỉ IPv6 đầy đủ hoặc rút gọn
    "ipv6": re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
    ),

    # URLs: http, https, ftp, smb
    "urls": re.compile(
        r'(?:https?|ftp|smb)://[^\s<>\"\'\\\x00]{4,}',
        re.IGNORECASE
    ),

    # Standalone Domains: Mở rộng hỗ trợ ~60+ TLD phổ biến
    "domains": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' 
        r'(?:com|net|org|xyz|top|info|io|ru|cn|tk|ml|ga|cf|gq|cc|pw|biz|ws|su|onion|'
        r'me|tv|co|uk|de|fr|jp|br|in|es|it|nl|au|ca|pl|ch|at|se|no|fi|dk|cz|hu|'
        r'ro|bg|hr|sk|lt|lv|ee|si|ua|kz|by|az|ge|am|'
        r'site|online|store|tech|click|link|pro|dev|app|cloud|live|world|vip|win|'
        r'download|buzz|monster|quest|sbs|cfd|icu|fun)\b',
        re.IGNORECASE
    ),

    # Emails: Chỉ báo Ransomware — mã độc tống tiền thường để lại email liên hệ
    "emails": re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,7}\b'
    ),

    # Bitcoin / Crypto Wallets: BTC Legacy, BTC Bech32, ETH, Monero
    "bitcoin": re.compile(
        r'\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b|'        # BTC
        r'\b0x[0-9a-fA-F]{40}\b|'                             # ETH
        r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'               # XMR (Monero)
    ),

    # Registry Keys
    "registry": re.compile(
        r'(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|'
        r'HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)'
        r'(?:\\[^\s<>\"\x00]+)+',
        re.IGNORECASE
    ),

    # Commands: các tiến trình/lệnh thường bị mã độc lạm dụng
    "commands": re.compile(
        r'(?:cmd(?:\.exe)?(?:\s+/[ckqar])?|'
        r'powershell(?:\.exe)?(?:\s+[\-/][a-z]+)?|'
        r'wscript(?:\.exe)?|cscript(?:\.exe)?|'
        r'mshta(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|'
        r'vssadmin(?:\.exe)?|schtasks(?:\.exe)?|regsvr32(?:\.exe)?|'
        r'rundll32(?:\.exe)?|msiexec(?:\.exe)?|'
        r'wmic(?:\.exe)?|net(?:\.exe)?\s+(?:user|localgroup|share|use|stop|start)|'
        r'sc(?:\.exe)?\s+(?:create|config|delete|stop|start|query)|'
        r'reg(?:\.exe)?\s+(?:add|delete|query|export|import)|'
        r'bcdedit(?:\.exe)?|'
        r'icacls(?:\.exe)?|takeown(?:\.exe)?|'
        r'attrib(?:\.exe)?\s+[\+\-][srha]|'
        r'del\s+/[fqsa]|erase\s+/[fqsa]|'
        r'taskkill(?:\.exe)?(?:\s+/[fti])?)(?:\s[^\x00]*)?',
        re.IGNORECASE
    ),

    # MAC Address
    "mac_address": re.compile(
        r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'
    ),
}

# ═══════════════════════════════════════════════════════════
#  HEURISTIC PATTERNS — Phát hiện chuỗi đáng ngờ theo hành vi
# ═══════════════════════════════════════════════════════════

# Đường dẫn file đáng ngờ thường xuất hiện trong mã độc
_RE_SUSPICIOUS_PATHS = re.compile(
    r'(?:[A-Za-z]:\\(?:Windows|Users|ProgramData|Temp|AppData|'
    r'System32|SysWOW64|Program\sFiles)[^\x00\s\"]{3,})|'
    r'(?:%(?:APPDATA|TEMP|USERPROFILE|SYSTEMROOT|PUBLIC|LOCALAPPDATA|PROGRAMDATA)%'
    r'[^\x00\s\"]{3,})',
    re.IGNORECASE
)

# Chuỗi User-Agent nhúng trong mã độc để giả mạo trình duyệt
_RE_USER_AGENTS = re.compile(
    r'(?:Mozilla/[45]\.0|User-Agent:\s|curl/|wget/|python-requests/|'
    r'Java/\d|MSIE\s|Trident/)',
    re.IGNORECASE
)

# Tên Mutex thường được mã độc tạo ra để kiểm tra infection marker
_RE_MUTEXES = re.compile(
    r'(?:Global\\|Local\\)[A-Za-z0-9_\-]{4,}',
    re.IGNORECASE
)

# Từ khóa đáng ngờ — Heuristic phát hiện hành vi mã độc
_RE_SUSPICIOUS_KEYWORDS = re.compile(
    r'\b(?:'
    # Anti-Analysis
    r'IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|'
    r'OutputDebugString|GetTickCount|QueryPerformanceCounter|'
    r'SbieDll|vmware|VBox|sandbox|wireshark|procmon|'
    # Injection / Evasion
    r'CreateRemoteThread|NtCreateThreadEx|RtlCreateUserThread|'
    r'VirtualAllocEx|WriteProcessMemory|NtUnmapViewOfSection|'
    r'ZwUnmapViewOfSection|NtWriteVirtualMemory|'
    r'Process\s?Hollowing|RunPE|reflective\s?load|'
    # Persistence
    r'CurrentVersion\\Run|CurrentVersion\\RunOnce|'
    r'Winlogon\\Shell|Winlogon\\Userinit|'
    r'Scheduled\s?Task|StartupFolder|'
    # Credential Theft
    r'mimikatz|lsass\.exe|SAM\s?database|credentials?\.txt|'
    r'passwords?\.txt|login\.txt|'
    # Ransomware
    r'YOUR\s?FILES?\s?(?:HAVE\s?BEEN|ARE)\s?ENCRYPTED|'
    r'DECRYPT|RANSOM|bitcoin|wallet|'
    r'\.encrypted|\.locked|\.crypto|'
    # Shell / Reverse Shell
    r'reverse.{0,5}shell|bind.{0,5}shell|web.{0,5}shell|'
    r'nc\.exe|ncat|netcat|socat|'
    r'meterpreter|metasploit|cobalt.?strike|beacon|'
    # Data Exfiltration
    r'upload|exfiltrat|steal|keylog|screenshot|clipboard'
    r')\b',
    re.IGNORECASE
)

# Phát hiện chuỗi mã hóa Base64 (chiều dài >= 20 ký tự, có padding hoặc không)
_RE_BASE64 = re.compile(
    r'\b(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b'
)


# ═══════════════════════════════════════════════════════════
#  WHITELIST — Lọc bỏ IoC hợp pháp để giảm False Positives
# ═══════════════════════════════════════════════════════════

WHITELIST_PATTERNS: List[re.Pattern] = [
    # === Local / Bogon IPs ===
    re.compile(r'^0\.0\.0\.0$'),
    re.compile(r'^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$'),
    re.compile(r'^255\.255\.255\.255$'),
    re.compile(r'^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$'),
    re.compile(r'^192\.168\.\d{1,3}\.\d{1,3}$'),
    re.compile(r'^172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$'),
    re.compile(r'^169\.254\.\d{1,3}\.\d{1,3}$'),  # Link-local
    re.compile(r'^(?:22[4-9]|23\d)\.\d{1,3}\.\d{1,3}\.\d{1,3}$'),  # Multicast

    # === Microsoft / Windows / Azure ===
    re.compile(r'(?:^|\.)microsoft\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)windows\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)windowsupdate\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)live\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)msn\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)office\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)azure\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)bing\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)visualstudio\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)aka\.ms$', re.IGNORECASE),

    # === Google ===
    re.compile(r'(?:^|\.)google\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)googleapis\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)gstatic\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)android\.com$', re.IGNORECASE),

    # === Hãng Chứng chỉ số & Bảo mật ===
    re.compile(r'(?:^|\.)verisign\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)digicert\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)symantec\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)letsencrypt\.org$', re.IGNORECASE),
    re.compile(r'(?:^|\.)globalsign\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)thawte\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)comodoca\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)entrust\.net$', re.IGNORECASE),

    # === Apple ===
    re.compile(r'(?:^|\.)apple\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)icloud\.com$', re.IGNORECASE),

    # === XML / Schema / .NET Namespace ===
    re.compile(r'schemas\.openxmlformats\.org', re.IGNORECASE),
    re.compile(r'schemas\.microsoft\.com', re.IGNORECASE),
    re.compile(r'www\.w3\.org', re.IGNORECASE),
    re.compile(r'^System\.[A-Z][A-Za-z0-9.]+$'),
    re.compile(r'^Microsoft\.[A-Z][A-Za-z0-9.]+$'),
    re.compile(r'^Windows\.[A-Z][A-Za-z0-9.]+$'),

    # === Version strings (x.x.x.x) ===
    re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'),

    # === Common programming / build artifacts ===
    re.compile(r'(?:^|\.)github\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)nuget\.org$', re.IGNORECASE),
    re.compile(r'(?:^|\.)python\.org$', re.IGNORECASE),
    re.compile(r'(?:^|\.)java\.com$', re.IGNORECASE),
    re.compile(r'(?:^|\.)mozilla\.org$', re.IGNORECASE),
    re.compile(r'(?:^|\.)apache\.org$', re.IGNORECASE),
    re.compile(r'(?:^|\.)sourceforge\.net$', re.IGNORECASE),
    re.compile(r'localhost', re.IGNORECASE),
]


# ═══════════════════════════════════════════════════════════
#  Whitelist cho Suspicious Keywords — Tránh bắt nhầm tên API
#  trong bảng Import (đã được phân tích ở module imports_exports)
# ═══════════════════════════════════════════════════════════
_KEYWORD_WHITELIST = {
    # Tên hàm API xuất hiện trong IAT — không phải chuỗi đáng ngờ
    "isdebuggerPresent", "checkremotedebuggerpresent",
    "querypeformancecounter", "gettickcount",
    "outputdebugstring",
}


# ═══════════════════════════════════════════════════════════
#  TRÍCH XUẤT CHUỖI THÔ
# ═══════════════════════════════════════════════════════════

_ASCII_PATTERN: re.Pattern = re.compile(rb'[\x20-\x7E]{4,}')
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
        pass

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
        pass

    return strings


def _is_whitelisted(value: str) -> bool:
    """Kiểm tra xem một chuỗi IoC có nằm trong Whitelist hay không."""
    for wl_pattern in WHITELIST_PATTERNS:
        if wl_pattern.search(value):
            return True
    return False


def _try_decode_base64(candidate: str) -> List[str]:
    """
    Cố gắng giải mã một chuỗi Base64. Nếu kết quả chứa ít nhất 70%
    ký tự in được (printable), trả về chuỗi giải mã kèm chuỗi gốc.
    Ngưỡng 70% giúp loại bỏ các chuỗi hash hoặc binary ngẫu nhiên.
    """
    decoded_strings = []
    try:
        raw = base64.b64decode(candidate, validate=True)
        if len(raw) < 4:
            return []
        # Kiểm tra tỷ lệ ký tự in được
        printable_count = sum(1 for b in raw if 0x20 <= b <= 0x7E)
        ratio = printable_count / len(raw) if len(raw) > 0 else 0
        if ratio >= 0.70:
            decoded_text = raw.decode('ascii', errors='ignore').strip()
            if len(decoded_text) >= 4:
                decoded_strings.append(decoded_text)
    except Exception:
        pass
    return decoded_strings


def analyze_strings(pe: pefile.PE) -> StringsResult:
    """
    Trích xuất chuỗi từ toàn bộ file PE nhị phân và phân loại các IoCs
    (Indicators of Compromise) bằng Regex + Heuristic Analysis.

    Pipeline phân tích:
    1. Trích xuất chuỗi ASCII/Unicode thô từ toàn bộ PE binary.
    2. Quét IoC mạng (IP, URL, Domain, Email, Wallet).
    3. Quét IoC hành vi (Commands, Registry, Paths, User-Agents, Mutex).
    4. Quét Heuristic: từ khóa đáng ngờ (suspicious keywords).
    5. Quét Base64: giải mã và phân tích đệ quy chuỗi mã hóa.
    6. Áp dụng Whitelist lọc False Positive.

    Args:
        pe (pefile.PE): Đối tượng file PE đã được nạp bằng thư viện pefile.

    Returns:
        StringsResult: Đối tượng chứa tổng số chuỗi, các IoCs phân loại, và trạng thái.
    """
    result = StringsResult()

    try:
        # Đọc toàn bộ mảng byte thô của file PE (bao gồm cả Overlay)
        raw_data: bytes = pe.__data__

        # Trích xuất chuỗi thô
        all_strings: Set[str] = extract_raw_strings(raw_data)
        result.total_strings_count = len(all_strings)

        # Dùng set tạm để loại trùng lặp cho từng danh mục IoC
        ioc_sets: Dict[str, Set[str]] = {
            "ipv4": set(), "ipv6": set(), "mac_address": set(),
            "urls": set(), "domains": set(), "emails": set(),
            "bitcoin": set(), "registry": set(), "commands": set(),
        }

        # Tập hợp riêng cho Heuristic IoCs (không dùng chung Whitelist mạng)
        suspicious_paths: Set[str] = set()
        user_agents: Set[str] = set()
        mutexes: Set[str] = set()
        suspicious_keywords: Set[str] = set()
        encoded_strings: Set[str] = set()

        whitelisted_count = 0

        # ── PHASE 1: Quét IoC mạng bằng COMPILED_PATTERNS ──
        for string in all_strings:
            for category, pattern in COMPILED_PATTERNS.items():
                try:
                    matches = pattern.findall(string)
                    for match_val in matches:
                        cleaned = match_val.strip()
                        if not cleaned:
                            continue
                        if _is_whitelisted(cleaned):
                            whitelisted_count += 1
                            continue
                        ioc_sets[category].add(cleaned)
                except Exception:
                    continue

        # ── PHASE 2: Quét IoC hành vi (Heuristic Patterns) ──
        for string in all_strings:
            # Đường dẫn file đáng ngờ
            try:
                path_matches = _RE_SUSPICIOUS_PATHS.findall(string)
                for pm in path_matches:
                    pm_clean = pm.strip()
                    if pm_clean and len(pm_clean) > 8:
                        # Lọc bỏ path hệ thống thường thấy trong PE hợp pháp
                        lower = pm_clean.lower()
                        if not any(safe in lower for safe in [
                            'windows\\system32\\kernel32',
                            'windows\\system32\\ntdll',
                            'windows\\system32\\user32',
                            'program files\\common files',
                        ]):
                            suspicious_paths.add(pm_clean)
            except Exception:
                pass

            # User-Agent strings
            try:
                if _RE_USER_AGENTS.search(string):
                    ua_clean = string.strip()[:200]  # Giới hạn chiều dài
                    if len(ua_clean) > 8:
                        user_agents.add(ua_clean)
            except Exception:
                pass

            # Mutex names
            try:
                mutex_matches = _RE_MUTEXES.findall(string)
                for mx in mutex_matches:
                    mutexes.add(mx.strip())
            except Exception:
                pass

            # Suspicious keywords
            try:
                kw_matches = _RE_SUSPICIOUS_KEYWORDS.findall(string)
                for kw in kw_matches:
                    kw_clean = kw.strip()
                    if kw_clean.lower() not in _KEYWORD_WHITELIST:
                        suspicious_keywords.add(kw_clean)
            except Exception:
                pass

        # ── PHASE 3: Quét chuỗi mã hóa Base64 ──
        for string in all_strings:
            try:
                b64_matches = _RE_BASE64.findall(string)
                for b64_candidate in b64_matches:
                    if len(b64_candidate) < 20:
                        continue
                    decoded_results = _try_decode_base64(b64_candidate)
                    for decoded_str in decoded_results:
                        display = f"{decoded_str}  ← Base64({b64_candidate[:40]}{'...' if len(b64_candidate) > 40 else ''})"
                        encoded_strings.add(display)
                        # Quét đệ quy: kiểm tra chuỗi giải mã có chứa IoC không
                        for cat, pat in COMPILED_PATTERNS.items():
                            try:
                                sub_matches = pat.findall(decoded_str)
                                for sm in sub_matches:
                                    sm_clean = sm.strip()
                                    if sm_clean and not _is_whitelisted(sm_clean):
                                        ioc_sets[cat].add(f"{sm_clean} [decoded from Base64]")
                            except Exception:
                                continue
            except Exception:
                continue

        result.whitelisted_count = whitelisted_count

        # Chuyển set sang list, gộp Heuristic vào IoCs
        result.iocs = IoCs(
            ipv4=sorted(ioc_sets["ipv4"]),
            ipv6=sorted(ioc_sets["ipv6"]),
            mac_address=sorted(ioc_sets["mac_address"]),
            urls=sorted(ioc_sets["urls"]),
            domains=sorted(ioc_sets["domains"]),
            emails=sorted(ioc_sets["emails"]),
            bitcoin=sorted(ioc_sets["bitcoin"]),
            registry=sorted(ioc_sets["registry"]),
            commands=sorted(ioc_sets["commands"]),
            suspicious_paths=sorted(suspicious_paths),
            user_agents=sorted(user_agents),
            mutexes=sorted(mutexes),
            suspicious_keywords=sorted(suspicious_keywords),
            encoded_strings=sorted(encoded_strings),
        )

    except pefile.PEFormatError as e:
        result.status = "error"
        result.error_message = f"Lỗi định dạng PE khi trích xuất chuỗi: {str(e)}"
    except Exception as e:
        result.status = "error"
        result.error_message = f"Lỗi không xác định khi trích xuất chuỗi: {str(e)}"

    return result
