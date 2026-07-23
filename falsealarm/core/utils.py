import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from typing import Any

def is_valid_domain(domain: str) -> bool:
    """Check if a string is a valid domain name."""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))

def is_valid_url(url: str) -> bool:
    """Check if a string is a valid URL."""
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except ValueError:
        return False

def normalize_url(url: str) -> str:
    """Ensure the URL has https:// prefix if no scheme is provided."""
    if not url.startswith(('http://', 'https://')):
        return f"https://{url}"
    return url

def extract_domain(url: str) -> str:
    """Extract domain from a URL."""
    try:
        parsed = urlparse(normalize_url(url))
        return parsed.netloc.split(':')[0]
    except Exception:
        return ""

def parse_ports(port_str: str) -> list[int]:
    """Parse port string like '80,443,8080-8090' into a list of integers."""
    if not port_str:
        return []
    ports = set()
    parts = port_str.split(',')
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            start_str, end_str = part.split('-', 1)
            try:
                start = int(start_str)
                end = int(end_str)
                if start <= end:
                    ports.update(range(start, end + 1))
            except ValueError:
                pass
        else:
            try:
                ports.add(int(part))
            except ValueError:
                pass
    return sorted(list(ports))

import secrets

def get_timestamp() -> str:
    """Get current timestamp in ISO format."""
    return datetime.utcnow().isoformat() + "Z"

def generate_scan_id() -> str:
    """Generate a unique scan ID."""
    return f"fa_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(3)}"

def get_data_path(filename: str) -> Path:
    """Get the path to a data file."""
    base_dir = Path(__file__).resolve().parent.parent / "data"
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / filename

def chunk_list(lst: list[Any], n: int) -> list[list[Any]]:
    """Split a list into chunks of size n."""
    if n <= 0:
        return [lst]
    return [lst[i:i + n] for i in range(0, len(lst), n)]
