# PROGRESS TRACKER & WORKING MEMORY

## 🎯 Current Sprint Goal
Hoàn thiện Batch Scan và xuất báo cáo JSON/CSV. Hệ thống đã chạy end-to-end với `main.py`.

## 📋 To-Do (Backlog)
- *(Không có task nào trong backlog)*

## ⏳ In Progress


- [ ] Xây dựng khung kiểm thử (Testing Framework): Cài đặt pytest và viết các bài unit test đầu tiên cho cấu phần chấm điểm rủi ro (core/scoring.py) bằng cách sử dụng kỹ thuật mock dữ liệu đầu vào.
- [ ] Áp dụng Multiprocessing: Cải tiến tính năng Batch Scan bằng cách tích hợp concurrent.futures.ProcessPoolExecutor để tận dụng tối đa sức mạnh đa nhân của CPU khi xử lý hàng loạt file nặng.  
- [ ] Phân rã God Script (main.py): Tách cấu trúc tuần tự của main.py thành các lớp đối tượng có trách nhiệm rõ ràng như CLIApp (điều phối menu), ScannerEngine (quét luồng đơn) và BatchProcessor (quét luồng song song).  
- [ ] Chuyển đổi sang src/ Layout: Tái cấu trúc thư mục dự án theo chuẩn phân phối mã nguồn Python hiện đại, đưa toàn bộ mã nguồn ứng dụng vào bên trong thư mục src/.

## ✅ Done
- [x] Tích hợp Python Logging: Xây dựng hệ thống log chuẩn sử dụng RotatingFileHandler, hợp nhất log của Single Scan và Batch Scan về `reports/app.log` an toàn, không làm hỏng CLI `rich`.
- [x] Tái cấu trúc bằng Dataclasses: Thay thế toàn bộ kiểu trả về dạng Dict[str, Any] bằng các dataclass tường minh.
- [x] Cập nhật UI & Exporter: Refactor ui/renderer.py và utils/exporter.py truy xuất dữ liệu qua thuộc tính của đối tượng.
- [x] Đóng gói Dependency: Sinh file `requirements.txt` chuẩn hóa với các phiên bản thư viện cố định (pinned versions) để bảo vệ môi trường chạy.
- [x] Bảo vệ luồng Batch Scan: Tách khối `except` thành `PEFormatError` / `Exception`, ghi log lỗi hệ thống chi tiết ra `reports/error.log` kèm traceback.
- [x] Quản lý cấu hình & Ngưỡng rủi ro: Tách toàn bộ các tham số cấu hình (Entropy, Risk Limits, YARA weights) ra file tập trung `core/constants.py`.
- [x] Tối ưu hóa YARA Compile (Pre-compile): Biên dịch luật một lần tại Application Startup để giảm hao phí CPU khi quét hàng loạt.
- [x] Nâng cấp giao diện hiển thị Chữ ký số (Authenticode) tại Single Scan và Batch Scan (Presence Check) nhằm đảm bảo tính khách quan bảo mật.
- [x] Kiểm tra Chữ ký số Authenticode (`core/signature.py`) & giảm điểm cho file đã ký.
- [x] Nhận diện .NET Framework & Tinh chỉnh Scoring Engine (Context-Aware, YARA Weights).
- [x] Bổ sung cơ chế Whitelist (Danh sách trắng) cho IoC: Lọc bỏ Local IPs, Microsoft/Windows Domains, hãng chứng chỉ số.
- [x] Hoàn thiện `core/scoring.py`: Tách thuật toán tính điểm rủi ro thành module độc lập, chuẩn hóa thang điểm 0-100.
- [x] Xây dựng module `core/yara_scanner.py`: Tích hợp `yara-python` để quét PE file bằng luật YARA.
- [x] Xây dựng module `core/hashes.py`: Trích xuất MD5, SHA-256, Imphash và Fuzzy Hashing (TLSH).
- [x] Tích hợp tính năng xuất báo cáo JSON ra thư mục `reports/`.
- [x] Xây dựng hàm quét thư mục hàng loạt (Batch Scan) với Progress Bar `rich`.
- [x] Xây dựng `main.py` Entry Point với Interactive Menu và Graceful Exit.
- [x] Xây dựng module UI Renderer (`ui/renderer.py`) với `rich` (Sections, Imports, IoCs).
- [x] Xây dựng bộ Regex trích xuất Smart Strings và IoCs (IPv4, URL, Registry, Commands).
- [x] Trích xuất bảng Imports/Exports và phát hiện API khả nghi.
- [x] Phân tích Section Permissions (Tìm cờ RWX).
- [x] Xây dựng module tính toán Entropy cho các section.
- [x] Tạo các file Markdown cấu hình Memory Bank.
- [x] Lên ý tưởng cấu trúc thư mục (core, ui, utils).

## 🐛 Known Bugs / Issues
- *(Agent sẽ điền các lỗi phát sinh trong quá trình code vào đây, ví dụ: lỗi đọc file PE quá lớn bị tràn RAM).*

## 🛠 Tech Debt (Cần refactor)
- *(Agent sẽ note lại các đoạn code chạy được nhưng chưa tối ưu để sau này sửa lại).*