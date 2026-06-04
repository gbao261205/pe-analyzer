# PRODUCT REQUIREMENTS DOCUMENT (PRD)
**Project:** PE File Static Feature Extractor
**Maintainer:** Nguyễn Gia Bảo
**Type:** CLI-based Cybersecurity Tool / Static Analysis

## 1. Mục tiêu dự án
Xây dựng một công cụ Python tự động trích xuất và phân tích các đặc trưng tĩnh (Static features) từ định dạng file Portable Executable (PE). Công cụ phục vụ cho quá trình phân tích mã độc (Malware Analysis), tập trung vào việc hiển thị trực quan trên CLI và xuất dữ liệu chuẩn hóa để có thể dễ dàng tích hợp vào các 파ipelines của hệ thống SOC tự động hóa hoặc SIEM.

## 2. Kiến trúc Hệ thống (Architecture)
Dự án áp dụng kiến trúc Modular, tách biệt hoàn toàn phần lõi xử lý (Core) và phần giao diện (UI).
- `core/`: Chứa các module phân tích nhị phân (header, sections, imports...). Hàm luôn trả về kiểu dữ liệu Dictionary/JSON.
- `ui/`: Chứa các module vẽ giao diện CLI, nhận dữ liệu từ `core` và render bằng thư viện `rich`.
- `utils/`: Các hàm hỗ trợ (ví dụ: regex pattern matching, file handling).

## 3. Danh sách Tính năng (Features)

### 3.1. Tính năng Cốt lõi (Core - Bắt buộc)
1. **Xác thực & Định danh:** 
   - Kiểm tra Magic Bytes (`MZ`, `PE\0\0`).
   - Tính toán Hash: MD5, SHA-256, Imphash (Import Hash).
2. **PE Header Parsing:**
   - Trích xuất: TimeDateStamp, Architecture, Subsystem.
   - Kiểm tra DLL Characteristics (ASLR, DEP/NX).
3. **Phân tích Sections (Phân vùng):**
   - Lấy tên, Raw Size, Virtual Size.
   - Phân tích Quyền (Permissions): Cảnh báo cờ `RWX`.
   - Tính Shannon Entropy (cảnh báo > 7.2).
4. **Bảng Nhập/Xuất & Tài nguyên (Imports, Exports, Resources):**
   - Bảng Imports: Trích xuất các DLL và hàm API được gọi.
   - Bảng Exports: Tên các hàm export.
   - Resources: Liệt kê các tài nguyên, phát hiện file PE nhúng kèm.
5. **Overlay Data:** Phát hiện và trích xuất dữ liệu thừa nằm ngoài cấu trúc PE.

### 3.2. Tính năng Nâng cao (Advanced)
1. **Smart Strings Extraction:** Dùng Regex gom nhóm IPv4/IPv6, Domains, Registry Keys, Commands.
2. **Anomaly Scoring Engine:** Chấm điểm mức độ khả nghi (0-100) dựa trên các cờ thu thập được (VD: Entropy cao, cờ RWX, tắt ASLR).

## 4. Input & Output
- **Input:** Đường dẫn file PE hợp lệ hoặc thư mục chứa các file PE.
- **Output:** 
  - Hiển thị trực tiếp trên Terminal (Interactive Menu, Bảng biểu, Màu sắc).
  - Tùy chọn xuất ra file `report.json` hoặc `report.csv`.