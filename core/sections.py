import math
import pefile
from typing import Dict
from core.constants import DEFAULT_ENTROPY_THRESHOLD
from core.models import SectionInfo, SectionsResult

def calculate_entropy(data: bytes) -> float:
    """
    Tính toán Shannon Entropy của một mảng byte.
    Giá trị entropy càng cao (tối đa 8.0) cho thấy dữ liệu càng hỗn loạn (có thể bị pack/obfuscate).
    
    Args:
        data (bytes): Dữ liệu thô của section.
        
    Returns:
        float: Giá trị Shannon Entropy. Trả về 0.0 nếu dữ liệu rỗng.
    """
    if not data:
        return 0.0
    
    entropy = 0.0
    length = len(data)
    
    # Tính tần suất xuất hiện của mỗi byte (0-255)
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
        
    # Tính Shannon Entropy
    for count in byte_counts:
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)
            
    return round(entropy, 2)

def get_permissions(characteristics: int) -> Dict[str, bool]:
    """
    Trích xuất quyền truy cập (Read, Write, Execute) từ trường Characteristics của section.
    Sử dụng toán tử bitwise AND để kiểm tra từng cờ.

    Args:
        characteristics (int): Giá trị Characteristics 32-bit của section.

    Returns:
        Dict[str, bool]: Dictionary chứa trạng thái của 3 quyền READ, WRITE, EXECUTE.
    """
    try:
        read = bool(characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'])
        write = bool(characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'])
        execute = bool(characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])
    except Exception:
        # Fallback an toàn nếu không lấy được bitmask
        read = False
        write = False
        execute = False

    return {
        "READ": read,
        "WRITE": write,
        "EXECUTE": execute
    }

def analyze_sections(pe: pefile.PE) -> SectionsResult:
    """
    Phân tích các section của file PE: trích xuất thông tin cơ bản, tính Shannon Entropy,
    và kiểm tra quyền truy cập (Permissions) bao gồm phát hiện cờ RWX.
    
    Args:
        pe (pefile.PE): Đối tượng file PE đã được nạp bằng thư viện pefile.
        
    Returns:
        SectionsResult: Đối tượng chứa thông tin các section và trạng thái phân tích.
    """
    result = SectionsResult()
    
    try:
        if not hasattr(pe, 'sections') or not pe.sections:
            result.total_sections = 0
            return result
            
        result.total_sections = len(pe.sections)
        
        for section in pe.sections:
            # Lấy tên section, decode utf-8 và bỏ các byte null
            # Dùng tham số errors='replace' hoặc 'ignore' để loại bỏ hoàn toàn nguy cơ crash 
            # do lỗi giải mã chuỗi, và thay thế các ký tự lạ bằng dấu '?'.
            # rstrip('\x00') được giữ nguyên để cắt bỏ các byte null ở cuối (đặc trưng của tên section trong PE).
            try:
                name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            except Exception:
                name = "UNKNOWN" # Nếu nát quá không đọc được thì trả về UNKNOWN
                
            virtual_address = hex(section.VirtualAddress)
            virtual_size = section.Misc_VirtualSize
            raw_size = section.SizeOfRawData
            
            # Lấy raw data của section để tính entropy
            try:
                data = section.get_data()
            except Exception:
                data = b"" # Fallback an toàn nếu có lỗi khi đọc section data
                
            entropy = calculate_entropy(data)
            
            # Trích xuất quyền truy cập của section
            perms = get_permissions(section.Characteristics)
            is_rwx = perms["READ"] and perms["WRITE"] and perms["EXECUTE"]
            
            # Kiểm tra chênh lệch kích thước: Virtual Size lớn hơn Raw Size >= 20%
            # Đây là dấu hiệu của section chứa dữ liệu giải nén (unpack) tại runtime.
            has_size_anomaly = raw_size > 0 and virtual_size >= raw_size * 1.2
            
            # Section bị suspicious nếu entropy cao HOẶC có cờ RWX HOẶC kích thước bất thường
            is_suspicious = entropy > DEFAULT_ENTROPY_THRESHOLD or is_rwx or has_size_anomaly
            
            section_info = SectionInfo(
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_size=raw_size,
                entropy=entropy,
                perms=perms,
                is_rwx=is_rwx,
                has_size_anomaly=has_size_anomaly,
                is_suspicious=is_suspicious
            )
            result.sections.append(section_info)
            
    except pefile.PEFormatError as e:
        result.status = "error"
        result.error_message = f"Lỗi định dạng PE khi phân tích sections: {str(e)}"
    except Exception as e:
        result.status = "error"
        result.error_message = f"Lỗi không xác định khi phân tích sections: {str(e)}"
        
    return result
