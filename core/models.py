"""
core/models.py — Định nghĩa tập trung toàn bộ schema dữ liệu (Data Transfer Objects)
cho các module phân tích trong hệ thống PE Static Feature Extractor.

Sử dụng @dataclass thay vì Dict[str, Any] thô nhằm:
- Cho phép IDE auto-complete thuộc tính.
- Loại bỏ rủi ro KeyError khi truy xuất dữ liệu.
- Tăng tính tường minh và khả năng bảo trì mã nguồn.

Lưu ý: File này KHÔNG được phép import bất kỳ module nào khác
trong dự án để tránh Circular Import.
"""
from dataclasses import dataclass, field
from typing import Dict, List


# ═══════════════════════════════════════════════════════════
#  Module: core/hashes.py
# ═══════════════════════════════════════════════════════════
@dataclass
class HashResult:
    """Kết quả tính toán mã băm (Hash) của file PE."""
    status: str = "success"
    error_message: str = ""
    md5: str = "N/A"
    sha256: str = "N/A"
    imphash: str = "N/A"
    tlsh: str = "N/A"


# ═══════════════════════════════════════════════════════════
#  Module: core/signature.py
# ═══════════════════════════════════════════════════════════
@dataclass
class SignatureResult:
    """Kết quả kiểm tra Chữ ký số Authenticode."""
    status: str = "success"
    error_message: str = ""
    is_signed: bool = False


# ═══════════════════════════════════════════════════════════
#  Module: core/yara_scanner.py
# ═══════════════════════════════════════════════════════════
@dataclass
class YaraResult:
    """Kết quả quét file bằng engine YARA."""
    status: str = "success"
    error_message: str = ""
    yara_matches: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════
#  Module: core/sections.py
# ═══════════════════════════════════════════════════════════
@dataclass
class SectionInfo:
    """Thông tin chi tiết của một phân vùng PE (Section)."""
    name: str = ""
    virtual_address: str = "0x0"
    virtual_size: str = "0x0"
    raw_size: str = "0x0"
    entropy: float = 0.0
    perms: Dict[str, bool] = field(default_factory=lambda: {
        "READ": False, "WRITE": False, "EXECUTE": False,
    })
    is_rwx: bool = False
    has_size_anomaly: bool = False
    is_suspicious: bool = False


@dataclass
class SectionsResult:
    """Kết quả phân tích toàn bộ các phân vùng PE."""
    status: str = "success"
    error_message: str = ""
    total_sections: int = 0
    sections: List[SectionInfo] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════
#  Module: core/imports_exports.py
# ═══════════════════════════════════════════════════════════
@dataclass
class ImportsExportsResult:
    """Kết quả phân tích bảng Import (IAT) và Export (EAT)."""
    status: str = "success"
    error_message: str = ""
    is_dot_net: bool = False
    imports: Dict[str, List[str]] = field(default_factory=dict)
    exports: List[str] = field(default_factory=list)
    suspicious_imports: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════
#  Module: core/strings_analyzer.py
# ═══════════════════════════════════════════════════════════
@dataclass
class IoCs:
    """Tập hợp các chỉ báo xâm nhập (Indicators of Compromise)."""
    ipv4: List[str] = field(default_factory=list)
    ipv6: List[str] = field(default_factory=list)
    mac_address: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    bitcoin: List[str] = field(default_factory=list)
    registry: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)


@dataclass
class StringsResult:
    """Kết quả trích xuất chuỗi và quét IoC."""
    status: str = "success"
    error_message: str = ""
    total_strings_count: int = 0
    whitelisted_count: int = 0
    iocs: IoCs = field(default_factory=IoCs)


# ═══════════════════════════════════════════════════════════
#  Module: core/scoring.py
# ═══════════════════════════════════════════════════════════
@dataclass
class ScoringResult:
    """Kết quả đánh giá mức độ rủi ro (Threat Risk Assessment)."""
    risk_score: int = 0
    risk_level: str = "SAFE"
    is_dot_net: bool = False
    is_signed: bool = False
    reasons: List[str] = field(default_factory=list)
