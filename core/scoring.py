import re
from typing import List

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
from core.models import (
    SectionsResult,
    SectionInfo,
    ImportsExportsResult,
    StringsResult,
    YaraResult,
    SignatureResult,
    ScoringResult,
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


def calculate_risk_score(section_data: SectionsResult, import_data: ImportsExportsResult, strings_data: StringsResult, yara_data: YaraResult = None, signature_data: SignatureResult = None) -> ScoringResult:
    """
    Tính toán điểm rủi ro (Risk Score) từ 0-100 dựa trên kết quả phân tích từ các module.
    Có nhận thức ngữ cảnh (Context-Aware): Tự động giảm điểm cho file .NET hợp pháp
    và phân loại trọng số YARA theo mức độ nguy hiểm của rule.
    
    Args:
        section_data (SectionsResult): Dữ liệu sections.
        import_data (ImportsExportsResult): Dữ liệu imports/exports.
        strings_data (StringsResult): Dữ liệu strings/iocs.
        yara_data (YaraResult, optional): Dữ liệu quét YARA.
        signature_data (SignatureResult, optional): Dữ liệu chữ ký số.
        
    Returns:
        ScoringResult: Điểm số, Xếp loại rủi ro, và danh sách các lý do cộng điểm.
    """
    score = 0
    reasons: List[str] = []

    # Nhận diện file .NET
    is_dot_net = import_data.is_dot_net

    # --- 1. Đánh giá Sections ---
    sections = section_data.sections

    has_rwx = any(sec.is_rwx for sec in sections)
    if has_rwx:
        score += PENALTY_RWX_SECTION
        reasons.append("Phát hiện phân vùng có quyền RWX (Read/Write/Execute)")

    for sec in sections:
        entropy = sec.entropy
        sec_name = sec.name.strip().lower()

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
    suspicious_apis = import_data.suspicious_imports
    api_count = len(suspicious_apis)
    if api_count > 0:
        added_score = min(api_count * PENALTY_SUSPICIOUS_API_MULTIPLIER, PENALTY_SUSPICIOUS_API_MAX)
        score += added_score
        reasons.append(f"Tìm thấy {api_count} API khả nghi")

    # --- 3. Đánh giá Strings & IoCs ---
    iocs = strings_data.iocs
    if iocs.ipv4 or iocs.ipv6 or iocs.domains or iocs.urls:
        score += PENALTY_NETWORK_IOC
        reasons.append("Chứa dấu hiệu kết nối mạng (IP, Domains, URLs)")
        
    if iocs.commands:
        score += PENALTY_COMMAND_IOC
        reasons.append("Phát hiện chuỗi lệnh thực thi hệ thống đáng ngờ (Commands)")
        
    if iocs.registry:
        score += PENALTY_REGISTRY_IOC
        reasons.append("Truy xuất hoặc chỉnh sửa Registry keys")

    # --- 3b. Đánh giá Heuristic IoCs (v2) ---
    if iocs.suspicious_keywords:
        kw_score = min(len(iocs.suspicious_keywords) * 3, 15)
        score += kw_score
        reasons.append(f"Phát hiện {len(iocs.suspicious_keywords)} từ khóa hành vi đáng ngờ (Heuristic) (+{kw_score})")

    if iocs.user_agents:
        score += 5
        reasons.append("Phát hiện chuỗi User-Agent nhúng trong binary (+5)")

    if iocs.mutexes:
        score += 10
        reasons.append(f"Phát hiện {len(iocs.mutexes)} tên Mutex (Infection Marker) (+10)")

    if iocs.encoded_strings:
        enc_score = min(len(iocs.encoded_strings) * 5, 15)
        score += enc_score
        reasons.append(f"Phát hiện {len(iocs.encoded_strings)} chuỗi mã hóa Base64 chứa nội dung khả nghi (+{enc_score})")

    # --- 4. Đánh giá YARA (Phân loại trọng số theo tên rule) ---
    if yara_data:
        yara_matches = yara_data.yara_matches
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
        is_signed = signature_data.is_signed
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

    return ScoringResult(
        risk_score=score,
        risk_level=risk_level,
        is_dot_net=is_dot_net,
        is_signed=is_signed,
        reasons=reasons
    )
