import hashlib
import pefile
from typing import Dict, Any

try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False

def calculate_hashes(file_path: str, pe: pefile.PE) -> Dict[str, Any]:
    """
    Tính toán các mã băm (Hashes) phổ biến của file PE: MD5, SHA-256, Imphash, và TLSH.
    
    Args:
        file_path (str): Đường dẫn đến file.
        pe (pefile.PE): Đối tượng file PE đã nạp qua thư viện pefile.
        
    Returns:
        Dict[str, Any]: Dictionary chứa kết quả các mã băm.
    """
    result = {
        "status": "success",
        "error_message": None,
        "md5": "",
        "sha256": "",
        "imphash": "",
        "tlsh": "Not Available"
    }
    
    try:
        # Đọc dữ liệu file thô để tính MD5, SHA-256
        with open(file_path, "rb") as f:
            data = f.read()
            
        if not data:
            result["status"] = "error"
            result["error_message"] = "File rỗng"
            return result
            
        # Tính MD5
        md5_hash = hashlib.md5()
        md5_hash.update(data)
        result["md5"] = md5_hash.hexdigest()
        
        # Tính SHA-256
        sha256_hash = hashlib.sha256()
        sha256_hash.update(data)
        result["sha256"] = sha256_hash.hexdigest()
        
        # Tính TLSH (Fuzzy Hash) nếu khả dụng và file đủ 50 bytes
        if TLSH_AVAILABLE:
            if len(data) >= 50:
                try:
                    result["tlsh"] = tlsh.hash(data)
                except Exception:
                    result["tlsh"] = "Lỗi tính toán TLSH"
            else:
                result["tlsh"] = "Not Available (File < 50 bytes)"
        else:
            result["tlsh"] = "Not Available (Thư viện tlsh chưa cài đặt)"
            
        # Lấy Imphash từ đối tượng pefile
        try:
            imphash = pe.get_imphash()
            result["imphash"] = imphash if imphash else "Không có bảng Import"
        except Exception:
            result["imphash"] = "Lỗi khi lấy Imphash"
            
    except Exception as e:
        result["status"] = "error"
        result["error_message"] = f"Lỗi trong quá trình tính toán hash: {str(e)}"
        
    return result
