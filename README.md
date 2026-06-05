# PE Static Feature Extractor

**PE Static Feature Extractor** là một công cụ phân tích tĩnh mã độc (Static Malware Analysis) chuyên nghiệp chạy trên giao diện dòng lệnh (CLI). Công cụ này hỗ trợ bóc tách các đặc trưng của tệp thực thi Windows (PE - Portable Executable) để phát hiện sớm các rủi ro bảo mật thông qua hàng loạt các kỹ thuật phát hiện và thuật toán chấm điểm rủi ro.

![PE Analyzer CLI](https://img.shields.io/badge/UI-Rich_Terminal-blue?style=flat-square)
![Python 3](https://img.shields.io/badge/Python-3.8%2B-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Stable-success?style=flat-square)

## 🌟 Các tính năng nổi bật
* **Cryptographic & Fuzzy Hashes**: Tính toán MD5, SHA-256, Imphash (Import Hash) và đặc biệt là TLSH (Fuzzy Hashing) để nhận dạng độ tương đồng mã độc.
* **Authenticode Signature Check**: Kiểm tra chữ ký số trực tiếp từ PE Data Directory, hiển thị trạng thái Signed/Unsigned ngay trên giao diện nhằm phân tách nhanh các file vô danh.
* **YARA Rule Engine**: Tích hợp quét YARA để đối chiếu file với các mẫu nhận diện (signatures). Phân loại trọng số thông minh theo 4 nhóm rule: Malware, Packer, Crypto, Generic.
* **Context-Aware Entropy & Sections**: Trích xuất các phân vùng `.text`, `.data`...; phát hiện các cờ nghi vấn như RWX. Nhận diện kiến trúc phần mềm (VD: C# .NET) để bỏ qua các cảnh báo Entropy giả trên `.rsrc`.
* **Phân tích Imports / Exports**: Quét Bảng Import (IAT) để tìm kiếm các Windows API nguy hiểm (Process Injection, Keylogging, Network communication...).
* **Trích xuất IoCs & Smart Whitelist**: Sử dụng Biểu thức chính quy (Regex) tối ưu để trích xuất IPv4, IPv6, URL, Domain, Email Ransomware, Wallet, Registry. Đặc biệt trang bị **Whitelist Filter** để loại bỏ 100% cảnh báo giả từ Local IPs, Microsoft Domains, hãng chứng chỉ và Namespace .NET.
* **Threat Risk Assessment (Chấm điểm rủi ro)**: Đánh giá file theo thang điểm từ `0` đến `100` với 5 mức độ (SAFE, LOW, MEDIUM, HIGH, CRITICAL). Trả về danh sách chi tiết nguyên nhân (Reasons) của điểm số. Tích hợp **Configuration Management** giúp dễ dàng tinh chỉnh các ngưỡng điểm, trọng số YARA và Entropy tại file `core/constants.py` duy nhất.
* **Kiến trúc hướng Dữ liệu (Dataclass-driven)**: Chuyển đổi toàn bộ luồng truyền tải dữ liệu giữa các module từ dạng Dictionary lỏng lẻo sang các kiểu dữ liệu có cấu trúc (`dataclasses` trong `core/models.py`), mang lại sự minh bạch và tránh triệt để các lỗi truy xuất động (KeyError).
* **Batch Scan An Toàn (Safe Execution)**: Hỗ trợ quét hàng loạt tệp với thanh tiến trình. Xử lý ngoại lệ an toàn ở từng file riêng lẻ.
* **Hệ thống Logging Tập trung & Đa tiến trình**: Quản lý song song giao diện `rich` và log hệ thống ẩn. Toàn bộ nhật ký vòng đời (quét đơn, quét đa tiến trình, lỗi crash) được thu thập an toàn bằng `QueueListener` và lưu xoay vòng bằng `RotatingFileHandler` vào tệp `reports/app.log`, tuyệt đối không làm vỡ giao diện đồ họa CLI.
* **Giao diện Terminal chuyên nghiệp**: Giao diện thiết kế theo chuẩn công cụ SOC (Vuông vắn, chống xê lệch ở mọi độ phân giải Terminal) sử dụng thư viện `rich` với các khối màu trực quan.
* **Tối ưu Hóa Hiệu Suất YARA**: Cơ chế **Pre-compile YARA Rules** tại Application Startup (Khởi động ứng dụng), giúp tăng vọt hiệu suất khi quét hàng loạt file.
## ⚙️ Cài đặt

1. Đảm bảo bạn đã cài đặt Python 3.8+ trên hệ thống.
2. Clone mã nguồn về máy:
   ```bash
   git clone https://github.com/gbao261205/pe-analyzer.git
   cd pe-analyzer
   ```
3. Khởi tạo môi trường ảo và cài đặt thư viện được ghim phiên bản (Pinned Dependencies):
   ```bash
   python -m venv venv
   source venv/bin/activate  # (Linux/MacOS)
   venv\Scripts\activate     # (Windows)
   pip install -r requirements.txt
   ```

> [!WARNING]
> **CẢNH BÁO QUAN TRỌNG VỀ YARA:** Bạn bắt buộc phải cài đặt thư viện bằng file `requirements.txt` (sử dụng thư viện `yara-python`). TUYỆT ĐỐI KHÔNG gõ lệnh `pip install yara`. Thư viện có tên `yara` trên PyPI là một bản cũ/lỗi, sẽ gây ra xung đột nghiêm trọng (`FileNotFoundError: Could not find module libyara.dll`) và làm sập toàn bộ tính năng phân tích của công cụ!

> [!NOTE]
> *Lưu ý:* Nếu bạn không thể cài đặt `tlsh` hoặc `yara-python` trên môi trường của mình (ví dụ thiếu trình biên dịch C++), công cụ vẫn sẽ tự động vô hiệu hóa tính năng đó và hoạt động bình thường trên các module còn lại.

## 🚀 Hướng dẫn sử dụng

Chạy file `main.py` ở thư mục gốc để khởi động giao diện điều khiển (Menu):

```bash
python main.py
```

### Chế độ hoạt động (Scan Modes)
1. **Single Scan**: Bạn sẽ được hỏi đường dẫn của **1 file PE duy nhất** (ví dụ: `malware.exe`). Sau khi phân tích, bạn có thể chọn các Menu nhỏ để hiển thị chi tiết (Hashes, Sections, Imports, IoCs).
2. **Batch Scan**: Bạn sẽ được hỏi đường dẫn của **1 thư mục**. Công cụ sẽ đệ quy thu thập tất cả file thực thi (`.exe`, `.dll`, `.sys`, `.bin`) và tiến hành quét bằng đa luồng/tuần tự kèm thanh Tiến trình. Sau đó in ra Top 20 tệp khả nghi nhất.

### Xuất báo cáo (Export JSON)
Trong chế độ Single Scan, chọn tùy chọn `[4]` để lưu trữ toàn bộ dữ liệu phân tích ra thư mục `reports/` ở dạng file JSON với timestamp (Ví dụ: `malware_exe_report_20260524_190000.json`).

## 📁 Cấu trúc dự án
pe_analyzer/
├── main.py                  # Entry Point chạy CLI Menu. Điều phối luồng và Error Logging.
├── requirements.txt         # File cố định phiên bản các thư viện môi trường (Pinned versions).
├── rules/                   # Thư mục thả các file luật YARA (.yar, .yara).
├── reports/                 # Nơi lưu trữ file JSON báo cáo và hệ thống app.log.
├── core/                    # Mã nguồn các module phân tích:
│   ├── constants.py         # Quản lý cấu hình tập trung (Ngưỡng điểm, Entropy, Extensions).
│   ├── models.py            # Khai báo cấu trúc dữ liệu Dataclasses chuẩn hóa.
│   ├── hashes.py            # Xử lý MD5, SHA-256, Imphash, TLSH.
│   ├── imports_exports.py   # Quét bảng IAT, EAT, phát hiện API độc hại.
│   ├── scoring.py           # Thuật toán chấm điểm rủi ro Context-aware 0-100.
│   ├── sections.py          # Xử lý PE Sections, Entropy, Permissions.
│   ├── signature.py         # Kiểm tra sự tồn tại của Chữ ký số Authenticode.
│   ├── strings_analyzer.py  # Trích xuất Strings, quét IoC với Regex & Whitelist.
│   └── yara_scanner.py      # Module quét và compile YARA.
├── ui/                      # Giao diện
│   └── renderer.py          # Render giao diện bằng thư viện `rich`.
└── utils/
    ├── exporter.py          # Đóng gói và ghi Master Report JSON.
    └── logger.py            # Khởi tạo hệ thống RotatingFileHandler Logging tập trung.
```

## 🛡️ Tuyên bố miễn trừ trách nhiệm (Disclaimer)
Dự án được tạo ra với mục đích phục vụ giáo dục, nghiên cứu phân tích mã độc và tự động hóa các quy trình Threat Hunting của đội ngũ phòng thủ (Blue Team/SOC). Vui lòng không sử dụng với các mục đích trái pháp luật.
