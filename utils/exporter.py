import os
import json
from datetime import datetime
from typing import Dict, Any, Optional

def export_to_json(file_path: str, hash_data: Dict[str, Any], yara_data: Dict[str, Any], signature_data: Dict[str, Any], section_data: Dict[str, Any], import_data: Dict[str, Any], strings_data: Dict[str, Any], scoring_data: Dict[str, Any]) -> Optional[str]:
    """
    Xuất báo cáo phân tích PE ra file JSON.
    
    Args:
        file_path (str): Đường dẫn tới file PE gốc.
        hash_data (Dict[str, Any]): Dữ liệu mã băm (Hashes).
        yara_data (Dict[str, Any]): Dữ liệu kết quả quét YARA.
        signature_data (Dict[str, Any]): Dữ liệu chữ ký số Authenticode.
        section_data (Dict[str, Any]): Dữ liệu phân tích Sections.
        import_data (Dict[str, Any]): Dữ liệu phân tích Imports/Exports.
        strings_data (Dict[str, Any]): Dữ liệu phân tích Strings/IoCs.
        scoring_data (Dict[str, Any]): Dữ liệu điểm rủi ro.
        
    Returns:
        Optional[str]: Đường dẫn tuyệt đối tới file báo cáo vừa tạo, hoặc None nếu có lỗi.
    """
    try:
        # Lấy tên file gốc
        base_name = os.path.basename(file_path)
        name, ext = os.path.splitext(base_name)
        safe_ext = ext.replace(".", "_") if ext else ""
        
        # Lấy thời gian hiện tại
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Tên file báo cáo
        report_filename = f"{name}{safe_ext}_report_{timestamp}.json"
        
        # Xác định thư mục reports ở gốc project (ngang hàng với utils/)
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(current_dir)
        reports_dir = os.path.join(project_root, "reports")
        
        # Tạo thư mục reports nếu chưa tồn tại
        os.makedirs(reports_dir, exist_ok=True)
        
        report_path = os.path.join(reports_dir, report_filename)
        
        # Gộp dữ liệu thành Master Report
        master_report = {
            "scan_time": datetime.now().isoformat(),
            "target_file": file_path,
            "risk_assessment": scoring_data,
            "analysis_results": {
                "hashes": hash_data,
                "signature": signature_data,
                "yara": yara_data,
                "sections": section_data,
                "imports_exports": import_data,
                "strings_iocs": strings_data
            }
        }
        
        # Ghi ra file JSON
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(master_report, f, indent=4, ensure_ascii=False)
            
        return report_path
        
    except Exception:
        return None
