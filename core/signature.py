import pefile
from typing import Dict, Any


def check_signature(pe: pefile.PE) -> Dict[str, Any]:
    """
    Kiểm tra sự tồn tại của Chữ ký số Authenticode trong file PE
    bằng cách truy xuất IMAGE_DIRECTORY_ENTRY_SECURITY trong DATA_DIRECTORY.

    Args:
        pe (pefile.PE): Đối tượng file PE đã được nạp bằng thư viện pefile.

    Returns:
        Dict[str, Any]: Dictionary chứa trạng thái chữ ký số.
    """
    result: Dict[str, Any] = {
        "status": "success",
        "error_message": None,
        "is_signed": False
    }

    try:
        security_index = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_index]

        # Lưu ý: VirtualAddress ở đây thực chất là File Offset trên đĩa
        if security_dir.VirtualAddress > 0 and security_dir.Size > 0:
            result["is_signed"] = True

    except (IndexError, AttributeError):
        # File PE bị hỏng hoặc không có đủ Data Directory entries
        result["status"] = "error"
        result["error_message"] = "Không thể truy xuất DATA_DIRECTORY cho Security."
    except Exception as e:
        result["status"] = "error"
        result["error_message"] = f"Lỗi khi kiểm tra chữ ký số: {str(e)}"

    return result
