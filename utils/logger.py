import os
import logging
from logging.handlers import RotatingFileHandler

_APP_LOGGER_NAME = "PE_Analyzer"
_LOG_FILE_NAME = "app.log"

def get_log_file_path() -> str:
    """Xác định và trả về đường dẫn tới file log tập trung."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    reports_dir = os.path.join(project_root, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    return os.path.join(reports_dir, _LOG_FILE_NAME)

def get_standard_formatter() -> logging.Formatter:
    """Tạo Formatter chuẩn hóa cho mọi dòng log."""
    return logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)s] [%(module)s:%(lineno)d]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

def setup_global_logging() -> logging.Logger:
    """
    Khởi tạo cấu hình logging toàn cục cho ứng dụng.
    Chỉ ghi log ra file bằng RotatingFileHandler, tuyệt đối không dùng StreamHandler.
    """
    logger = logging.getLogger(_APP_LOGGER_NAME)
    
    # Tránh gắn handler nhiều lần nếu hàm được gọi lại
    if logger.hasHandlers():
        return logger
        
    logger.setLevel(logging.INFO)
    logger.propagate = False  # Ngăn log rò rỉ ra console
    
    log_path = get_log_file_path()
    # Tự động xoay vòng file log định kỳ: tối đa 5MB, giữ 3 bản backup
    file_handler = RotatingFileHandler(log_path, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(get_standard_formatter())
    
    logger.addHandler(file_handler)
    return logger

def get_app_logger() -> logging.Logger:
    """Hàm helper để lấy logger toàn cục nhanh chóng."""
    return logging.getLogger(_APP_LOGGER_NAME)
