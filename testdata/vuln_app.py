import os

# EXPOSE-001: Exposed internal IP addresses
DB_HOST = "10.0.2.15"
REDIS_HOST = "172.16.0.50"
SERVICE_URL = "http://payments.internal.corp/api"

# EXPOSE-002: Exposed email addresses
ADMIN_CONTACT = "root@company.com"
DEV_EMAIL = "developer@internal.corp"

# EXPOSE-003: Exposed system paths
SHADOW_FILE = "/etc/shadow"
LOG_DIR = "/var/log/auth"
WINDOWS_PATH = "C:\\Windows\\System32\\drivers"


def get_system_info():
    proc_path = "/proc/self/environ"
    return os.path.exists(proc_path)


# EXPOSE-004: Exposed version information
RESPONSE_HEADERS = {
    "Server": "Nginx/1.21.3",
    "X-Powered-By": "Django/4.2",
}
