import os
import logging
from typing import Dict, Any, Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# Cấu hình logging để tránh in ra màn hình làm vỡ giao diện
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def compile_yara_rules() -> Optional["yara.Rules"]:
    """
    Biên dịch tất cả các file luật YARA (*.yar, *.yara) trong thư mục 'rules/'.
    
    Returns:
        yara.Rules: Đối tượng luật đã biên dịch nếu thành công, hoặc None nếu lỗi/không có luật.
    """
    if not YARA_AVAILABLE:
        return None

    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    rules_dir = os.path.join(project_root, "rules")
    
    if not os.path.exists(rules_dir):
        try:
            os.makedirs(rules_dir)
        except OSError as e:
            logger.error(f"Cannot create rules directory: {e}")
            return None

    filepaths = {}
    for root, _, files in os.walk(rules_dir):
        for f in files:
            if f.endswith(".yar") or f.endswith(".yara"):
                file_path = os.path.join(root, f)
                # Dùng filepath làm key để yara.compile có thể gom nhóm các rules
                filepaths[f] = file_path

    if not filepaths:
        return None

    try:
        compiled_rules = yara.compile(filepaths=filepaths)
        return compiled_rules
    except Exception as e:
        logger.error(f"YARA Compile Error: {e}")
        return None

def scan_with_yara(file_path: str, compiled_rules: Optional["yara.Rules"]) -> Dict[str, Any]:
    """
    Quét file bằng engine YARA dựa trên các tập luật tự định nghĩa.
    
    Args:
        file_path (str): Đường dẫn tới file cần quét.
        compiled_rules (Optional["yara.Rules"]): Đối tượng luật YARA đã được biên dịch.
        
    Returns:
        Dict[str, Any]: Kết quả quét YARA.
    """
    result = {
        "status": "success",
        "error_message": None,
        "yara_matches": []
    }
    
    if not YARA_AVAILABLE:
        result["status"] = "error"
        result["error_message"] = "Thư viện yara-python chưa được cài đặt."
        return result
        
    if compiled_rules is None:
        result["status"] = "no_rules"
        result["error_message"] = "Không tìm thấy file luật YARA (.yar) hoặc lỗi biên dịch."
        return result

    try:
        matches = compiled_rules.match(file_path)
        
        # Chỉ lấy tên các rule (rule name) match
        match_names = [match.rule for match in matches]
        result["yara_matches"] = match_names
        
    except Exception as e:
        result["status"] = "error"
        result["error_message"] = f"Lỗi trong quá trình quét YARA: {str(e)}"
        
    return result
