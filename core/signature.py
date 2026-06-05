import pefile

from core.models import SignatureResult
from utils.logger import get_app_logger

logger = get_app_logger()


def check_signature(pe: pefile.PE) -> SignatureResult:
    """
    Kiểm tra sự tồn tại của Chữ ký số Authenticode trong file PE
    bằng cách truy xuất IMAGE_DIRECTORY_ENTRY_SECURITY trong DATA_DIRECTORY.

    Args:
        pe (pefile.PE): Đối tượng file PE đã được nạp bằng thư viện pefile.

    Returns:
        SignatureResult: Đối tượng chứa trạng thái chữ ký số.
    """
    result = SignatureResult()

    try:
        security_index = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[security_index]

        # Lưu ý: VirtualAddress ở đây thực chất là File Offset trên đĩa
        if security_dir.VirtualAddress > 0 and security_dir.Size > 0:
            result.is_signed = True

    except (IndexError, AttributeError) as e:
        # File PE bị hỏng hoặc không có đủ Data Directory entries
        logger.warning(f"Không thể đọc thông tin Security Directory: {e}")
        result.status = "error"
        result.error_message = "Không thể truy xuất DATA_DIRECTORY cho Security."
    except Exception as e:
        logger.error(f"Lỗi hệ thống khi kiểm tra chữ ký số: {e}", exc_info=True)
        result.status = "error"
        result.error_message = f"Lỗi khi kiểm tra chữ ký số: {str(e)}"

    return result
