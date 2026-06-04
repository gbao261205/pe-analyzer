import re
from typing import Dict, Any, List

from core.constants import (
    DEFAULT_ENTROPY_THRESHOLD,
    SCORE_LIMIT_SAFE,
    SCORE_LIMIT_LOW,
    SCORE_LIMIT_MEDIUM,
    SCORE_LIMIT_HIGH,
    WEIGHT_YARA_CRYPTO,
    WEIGHT_YARA_PACKER,
    WEIGHT_YARA_MALICIOUS,
    WEIGHT_YARA_DEFAULT,
    BONUS_AUTHENTICODE_SIGNED,
    PENALTY_RWX_SECTION,
    PENALTY_HIGH_ENTROPY,
    PENALTY_SUSPICIOUS_API_MULTIPLIER,
    PENALTY_SUSPICIOUS_API_MAX,
    PENALTY_NETWORK_IOC,
    PENALTY_COMMAND_IOC,
    PENALTY_REGISTRY_IOC
)

# --- Phân loại trọng số YARA theo từ khóa trong tên rule ---
_YARA_CRYPTO_KEYWORDS = re.compile(
    r'Big_Numbers|Crypto|MD5|SHA1|SHA256|AES|RSA|Base64',
    re.IGNORECASE
)
_YARA_PACKER_KEYWORDS = re.compile(
    r'UPX|Themida|VMProtect|Packer|Packed|ASPack|PECompact|MPRESS|Enigma',
    re.IGNORECASE
)
_YARA_MALWARE_KEYWORDS = re.compile(
    r'Ransomware|WannaCry|Trojan|Malware|APT|Webshell|Backdoor|Worm|Exploit|RAT|Stealer|Miner|Keylogger',
    re.IGNORECASE
)


def calculate_risk_score(section_data: Dict[str, Any], import_data: Dict[str, Any], strings_data: Dict[str, Any], yara_data: Dict[str, Any] = None, signature_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Tính toán điểm rủi ro (Risk Score) từ 0-100 dựa trên kết quả phân tích từ các module.
    Có nhận thức ngữ cảnh (Context-Aware): Tự động giảm điểm cho file .NET hợp pháp
    và phân loại trọng số YARA theo mức độ nguy hiểm của rule.
    
    Args:
        section_data (Dict[str, Any]): Dữ liệu sections.
        import_data (Dict[str, Any]): Dữ liệu imports/exports.
        strings_data (Dict[str, Any]): Dữ liệu strings/iocs.
        yara_data (Dict[str, Any], optional): Dữ liệu quét YARA.
        signature_data (Dict[str, Any], optional): Dữ liệu chữ ký số.
        
    Returns:
        Dict[str, Any]: Điểm số, Xếp loại rủi ro, và danh sách các lý do cộng điểm.
    """
    score = 0
    reasons: List[str] = []

    # Nhận diện file .NET
    is_dot_net = import_data.get("is_dot_net", False)

    # --- 1. Đánh giá Sections ---
    sections = section_data.get("sections", [])

    has_rwx = any(sec.get("is_rwx", False) for sec in sections)
    if has_rwx:
        score += PENALTY_RWX_SECTION
        reasons.append("Phát hiện phân vùng có quyền RWX (Read/Write/Execute)")

    for sec in sections:
        entropy = sec.get("entropy", 0)
        sec_name = sec.get("name", "").strip().lower()

        if entropy > DEFAULT_ENTROPY_THRESHOLD:
            # File .NET: Bỏ qua entropy cao của section .rsrc (chứa tài nguyên IL)
            if is_dot_net and sec_name == ".rsrc":
                reasons.append(
                    f"Bỏ qua Entropy cao ({entropy:.2f}) của .rsrc — đây là file .NET Framework"
                )
            else:
                score += PENALTY_HIGH_ENTROPY
                reasons.append(
                    f"Phân vùng '{sec_name}' có Entropy cao ({entropy:.2f}) — khả năng bị Pack/Mã hóa"
                )
                break  # Chỉ cộng 1 lần cho toàn bộ sections

    # --- 2. Đánh giá Imports ---
    suspicious_apis = import_data.get("suspicious_imports", [])
    api_count = len(suspicious_apis)
    if api_count > 0:
        added_score = min(api_count * PENALTY_SUSPICIOUS_API_MULTIPLIER, PENALTY_SUSPICIOUS_API_MAX)
        score += added_score
        reasons.append(f"Tìm thấy {api_count} API khả nghi")

    # --- 3. Đánh giá Strings & IoCs ---
    iocs = strings_data.get("iocs", {})
    if iocs.get("ipv4") or iocs.get("ipv6") or iocs.get("domains") or iocs.get("urls"):
        score += PENALTY_NETWORK_IOC
        reasons.append("Chứa dấu hiệu kết nối mạng (IP, Domains, URLs)")
        
    if iocs.get("commands"):
        score += PENALTY_COMMAND_IOC
        reasons.append("Phát hiện chuỗi lệnh thực thi hệ thống đáng ngờ (Commands)")
        
    if iocs.get("registry"):
        score += PENALTY_REGISTRY_IOC
        reasons.append("Truy xuất hoặc chỉnh sửa Registry keys")

    # --- 4. Đánh giá YARA (Phân loại trọng số theo tên rule) ---
    if yara_data:
        yara_matches = yara_data.get("yara_matches", [])
        for match_name in yara_matches:
            if _YARA_MALWARE_KEYWORDS.search(match_name):
                score += WEIGHT_YARA_MALICIOUS
                reasons.append(f"YARA [MALWARE]: Khớp rule nguy hiểm '{match_name}' (+{WEIGHT_YARA_MALICIOUS})")
            elif _YARA_PACKER_KEYWORDS.search(match_name):
                score += WEIGHT_YARA_PACKER
                reasons.append(f"YARA [PACKER]: Khớp rule đóng gói '{match_name}' (+{WEIGHT_YARA_PACKER})")
            elif _YARA_CRYPTO_KEYWORDS.search(match_name):
                score += WEIGHT_YARA_CRYPTO
                reasons.append(f"YARA [CRYPTO]: Khớp rule mã hóa/toán học '{match_name}' (+{WEIGHT_YARA_CRYPTO})")
            else:
                score += WEIGHT_YARA_DEFAULT
                reasons.append(f"YARA [GENERIC]: Khớp rule '{match_name}' (+{WEIGHT_YARA_DEFAULT})")

    # --- 5. Đánh giá Chữ ký số (Authenticode) ---
    is_signed = False
    if signature_data:
        is_signed = signature_data.get("is_signed", False)
    if is_signed:
        score = max(0, score - BONUS_AUTHENTICODE_SIGNED)
        reasons.append(f"File có đính kèm Chữ ký số Authenticode (Giảm rủi ro -{BONUS_AUTHENTICODE_SIGNED})")

    # --- 6. Tổng hợp & Chuẩn hóa ---
    score = min(score, 100)

    # Phân loại mức độ rủi ro
    if score > SCORE_LIMIT_HIGH:
        risk_level = "CRITICAL"
    elif score > SCORE_LIMIT_MEDIUM:
        risk_level = "HIGH"
    elif score > SCORE_LIMIT_LOW:
        risk_level = "MEDIUM"
    elif score > SCORE_LIMIT_SAFE:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "is_dot_net": is_dot_net,
        "is_signed": is_signed,
        "reasons": reasons
    }
