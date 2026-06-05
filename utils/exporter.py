import os
import json
import dataclasses
from datetime import datetime
from typing import Any, Optional

from core.models import (
    HashResult, SignatureResult, YaraResult,
    SectionsResult, ImportsExportsResult, StringsResult, ScoringResult
)


def export_to_json(
    file_path: str,
    hash_data: HashResult,
    yara_data: YaraResult,
    signature_data: SignatureResult,
    section_data: SectionsResult,
    import_data: ImportsExportsResult,
    strings_data: StringsResult,
    scoring_data: ScoringResult,
) -> Optional[str]:
    """
    Xuất báo cáo phân tích PE ra file JSON.

    Sử dụng dataclasses.asdict() để chuyển đổi tự động các đối tượng
    dataclass sang dictionary trước khi serialize JSON.

    Args:
        file_path (str): Đường dẫn tới file PE gốc.
        hash_data (HashResult): Dữ liệu mã băm (Hashes).
        yara_data (YaraResult): Dữ liệu kết quả quét YARA.
        signature_data (SignatureResult): Dữ liệu chữ ký số Authenticode.
        section_data (SectionsResult): Dữ liệu phân tích Sections.
        import_data (ImportsExportsResult): Dữ liệu phân tích Imports/Exports.
        strings_data (StringsResult): Dữ liệu phân tích Strings/IoCs.
        scoring_data (ScoringResult): Dữ liệu điểm rủi ro.

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

        # Chuyển đổi dataclass -> dict an toàn trước khi serialize
        def _to_dict(obj: Any) -> Any:
            if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
                return dataclasses.asdict(obj)
            return obj

        # Gộp dữ liệu thành Master Report
        master_report = {
            "scan_time": datetime.now().isoformat(),
            "target_file": file_path,
            "risk_assessment": _to_dict(scoring_data),
            "analysis_results": {
                "hashes": _to_dict(hash_data),
                "signature": _to_dict(signature_data),
                "yara": _to_dict(yara_data),
                "sections": _to_dict(section_data),
                "imports_exports": _to_dict(import_data),
                "strings_iocs": _to_dict(strings_data),
            }
        }

        # Ghi ra file JSON
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(master_report, f, indent=4, ensure_ascii=False)

        return report_path

    except Exception:
        return None
