# Cấu hình hệ thống & Ngưỡng số liệu (Constants)

# Ngưỡng cấu hình PE & Sections
DEFAULT_ENTROPY_THRESHOLD: float = 7.2

# Các mốc phân loại điểm rủi ro (Risk Levels)
SCORE_LIMIT_SAFE: int = 15
SCORE_LIMIT_LOW: int = 39
SCORE_LIMIT_MEDIUM: int = 69
SCORE_LIMIT_HIGH: int = 89

# Trọng số điểm phạt YARA (YARA Rule Weights)
WEIGHT_YARA_CRYPTO: int = 10
WEIGHT_YARA_PACKER: int = 30
WEIGHT_YARA_MALICIOUS: int = 60
WEIGHT_YARA_DEFAULT: int = 30

# Cấu hình hệ thống & UI
PE_EXTENSIONS: set = {".exe", ".dll", ".sys", ".bin"}
MAX_BATCH_SUMMARY_DISPLAY: int = 20

# Điểm thưởng & Phạt (Bonus/Penalties)
BONUS_AUTHENTICODE_SIGNED: int = 20
PENALTY_RWX_SECTION: int = 30
PENALTY_HIGH_ENTROPY: int = 20
PENALTY_SUSPICIOUS_API_MULTIPLIER: int = 5
PENALTY_SUSPICIOUS_API_MAX: int = 30
PENALTY_NETWORK_IOC: int = 10
PENALTY_COMMAND_IOC: int = 15
PENALTY_REGISTRY_IOC: int = 10
