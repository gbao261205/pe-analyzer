from typing import Dict, Any, List

def calculate_risk_score(section_data: Dict[str, Any], import_data: Dict[str, Any], strings_data: Dict[str, Any], yara_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Tính toán điểm rủi ro (Risk Score) từ 0-100 dựa trên kết quả phân tích từ các module.
    
    Args:
        section_data (Dict[str, Any]): Dữ liệu sections.
        import_data (Dict[str, Any]): Dữ liệu imports/exports.
        strings_data (Dict[str, Any]): Dữ liệu strings/iocs.
        yara_data (Dict[str, Any], optional): Dữ liệu quét YARA.
        
    Returns:
        Dict[str, Any]: Điểm số, Xếp loại rủi ro, và danh sách các lý do cộng điểm.
    """
    score = 0
    reasons: List[str] = []

    # --- 1. Đánh giá Sections ---
    sections = section_data.get("sections", [])
    has_rwx = any(sec.get("is_rwx", False) for sec in sections)
    if has_rwx:
        score += 30
        reasons.append("Phát hiện phân vùng có quyền RWX (Read/Write/Execute)")
        
    has_high_entropy = any(sec.get("entropy", 0) > 7.2 for sec in sections)
    if has_high_entropy:
        score += 20
        reasons.append("Phát hiện phân vùng có mức độ hỗn loạn cao (khả năng bị Pack/Mã hóa)")

    # --- 2. Đánh giá Imports ---
    suspicious_apis = import_data.get("suspicious_imports", [])
    api_count = len(suspicious_apis)
    if api_count > 0:
        added_score = min(api_count * 5, 30)
        score += added_score
        reasons.append(f"Tìm thấy {api_count} API khả nghi")

    # --- 3. Đánh giá Strings & IoCs ---
    iocs = strings_data.get("iocs", {})
    if iocs.get("IPv4") or iocs.get("IPv6") or iocs.get("Domains") or iocs.get("URLs"):
        score += 10
        reasons.append("Chứa dấu hiệu kết nối mạng (IP, Domains, URLs)")
        
    if iocs.get("Commands"):
        score += 15
        reasons.append("Phát hiện chuỗi lệnh thực thi hệ thống đáng ngờ (Commands)")
        
    if iocs.get("Registry"):
        score += 10
        reasons.append("Truy xuất hoặc chỉnh sửa Registry keys")

    # --- 4. Đánh giá YARA ---
    if yara_data:
        yara_matches = yara_data.get("yara_matches", [])
        if yara_matches:
            score += 50
            reasons.append(f"Khớp với luật YARA: {', '.join(yara_matches)}")

    # --- 5. Tổng hợp & Chuẩn hóa ---
    score = min(score, 100)

    # Phân loại mức độ rủi ro
    if score >= 90:
        risk_level = "CRITICAL"
    elif score >= 70:
        risk_level = "HIGH"
    elif score >= 40:
        risk_level = "MEDIUM"
    elif score >= 16:
        risk_level = "LOW"
    else:
        risk_level = "SAFE"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }
