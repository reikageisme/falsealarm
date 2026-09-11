# FalseAlarm — Đánh giá mã nguồn & Lộ trình phát triển

*Ngày review: 21/08/2026 · Phạm vi: toàn bộ `falsealarm/` + `engine-go/` (~4.200 dòng Python + Go)*
*Trạng thái test: `pytest` — **50/50 pass** · CI (GitHub Actions) cấu hình hợp lý (Linux+Windows, Py3.10/3.13, Go engine).*

---

## 1. Nhận định tổng quan

Đây là một dự án **chất lượng tốt, có kiến trúc rõ ràng** hơn hẳn phần lớn recon tool tự viết:

- Kiến trúc module + auto-discovery (`BaseModule`) sạch, dễ mở rộng.
- Pipeline dạng DAG (subdomain → httpprobe → tech → vulnscan…) là ý tưởng đúng.
- Có test thật (50 test), CI đa nền tảng, SARIF output, YAML template engine kiểu nuclei, rate-limit token-bucket, diff giữa các lần scan, notify Discord/Slack/Telegram — bộ tính năng rất đầy đủ.
- README chuyên nghiệp, có phần đạo đức/pháp lý rõ ràng.

Tuy nhiên có **một số bug logic thật sự làm giảm chất lượng kết quả scan** và một vài chỗ README nói quá so với code. Dưới đây là các phát hiện đã được **kiểm chứng bằng code chạy thực tế**, không phải suy đoán.

---

## 2. Bug đã xác nhận (nên sửa sớm)

### 🔴 BUG-1 — Cờ `--adaptive-rate` hoàn toàn không hoạt động
**File:** `falsealarm/core/engine.py`, hàm `start()` (dòng ~56).

`AsyncEngine` khởi tạo rate limiter mà **không truyền `adaptive`**:

```python
self._rate_limiter = TokenBucketRateLimiter(
    rate=float(self.config.rate),
    burst=min(self.config.rate, 50),
    per_host_rate=float(self.config.rate) / 2,
)   # thiếu adaptive=self.config.adaptive_rate
```

`TokenBucketRateLimiter.report_status()` có dòng `if not self.adaptive: return` ngay đầu → toàn bộ logic tự giảm tốc khi gặp 429/503/timeout **không bao giờ chạy**. Trớ trêu là scheduler vẫn in *"Adaptive rate limiting will adjust automatically"* nên người dùng tưởng đang bật.

**Kiểm chứng:** với `ScanConfig(adaptive_rate=True)`, `engine._rate_limiter.adaptive == False`.

**Sửa:** thêm `adaptive=self.config.adaptive_rate,` vào constructor.

---

### 🔴 BUG-2 — Port web bị bỏ sót khi đẩy sang pipeline downstream
**File:** `falsealarm/core/scheduler.py`, `_extract_downstream_targets()` (dòng ~305).

```python
elif module_name == "portscan":
    port = item.get("port")
    if port in [8080, 8443] and target:                 # ❌ chỉ 8080/8443
        protocol = "https" if port in [443, 8443] else "http"  # ❌ 443 không bao giờ tới đây
        targets.append(f"{protocol}://{target}:{port}")
```

Portscan tìm ra dịch vụ web trên **80, 443, 8000, 8888…** nhưng chỉ **8080/8443** được đẩy tiếp vào `httpprobe`/`tech`/`vulnscan`. Nhánh `"https" if port in [443,...]` là **dead code** vì 443 đã bị lọc ở dòng trên. Hậu quả: chạy `-A`/`insane`, một web server mở trên cổng 80/443/8000 do portscan phát hiện **không được scan tiếp** — mất phủ.

**Kiểm chứng:** input 4 port `[80,443,8000,8080]` → chỉ trả về `['http://ex.com:8080']`.

**Sửa gợi ý:**
```python
HTTP_PORTS = {80, 8080, 8000, 8008, 8888}
HTTPS_PORTS = {443, 8443}
if port in HTTP_PORTS | HTTPS_PORTS and target:
    scheme = "https" if port in HTTPS_PORTS else "http"
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        targets.append(f"{scheme}://{target}")
    else:
        targets.append(f"{scheme}://{target}:{port}")
```

---

### 🟠 BUG-3 — CORS test-origin bị dựng sai (giảm khả năng phát hiện)
**File:** `falsealarm/modules/cors.py` (dòng ~18).

```python
origins_to_test = [
    "https://evil.com",
    "null",
    f"{target}.evil.com",                       # -> "http://example.com.evil.com" (dính cả scheme)
    f"https://evil{urlparse(target).hostname}", # -> "https://evilexample.com" (không có dấu chấm)
]
```

Hai case cuối lấy từ **URL đầy đủ** thay vì hostname:
- Prefix-bypass ra `http://example.com.evil.com` (kèm scheme của target, sai ngữ nghĩa Origin).
- Suffix-bypass ra `https://evilexample.com` — đúng ra phải là `https://evil.example.com` hoặc `https://example.com.evil.com`.

Kết quả: hai kỹ thuật bypass phổ biến nhất (prefix/suffix match) **test không đúng payload** → dễ bỏ sót lỗ hổng thật.

**Sửa gợi ý** (dựng từ `host = urlparse(target).hostname`):
```python
host = urlparse(target).hostname or ""
origins_to_test = [
    "https://evil.com", "null",
    f"https://{host}.evil.com",   # suffix bypass
    f"https://evil-{host}",       # prefix bypass thực sự
    f"https://{host}.attacker.io",
]
```

---

### 🟠 BUG-4 — `pyjsparser` không build được trên setuptools mới → `pip install` fail
**File:** `requirements.txt` / `pyproject.toml`.

`pyjsparser>=2.7` dùng `setup.py` cũ, lỗi `AttributeError: install_layout` với setuptools hiện đại (Python 3.12+). Trên môi trường sạch, `pip install -e .` **fail ngay ở bước build wheel** — đây là rào cản cài đặt cho người mới, ngược với slogan "out-of-the-box".

Trầm trọng hơn: trong `js_analysis.py`, kết quả `parse()` được gọi rồi **vứt đi** (`pass` — dòng ~91-94), tức là dependency nặng này **hiện không đóng góp gì** cho kết qura (regex đã làm hết việc).

**Sửa gợi ý:** bỏ hẳn `pyjsparser` (regex đang đủ dùng), hoặc thay bằng parser thuần Python còn được maintain. Bỏ đi vừa gỡ bug cài đặt vừa giảm CPU.

---

### 🟡 BUG-5 — Diff portscan key trùng khi scan nhiều host
**File:** `falsealarm/core/diff.py`, `KEY_FIELDS["portscan"] = ("port",)`.

Chỉ key theo `port`, không kèm `target`. Khi một scan có nhiều host, `port 80` của host A và host B bị coi là **cùng một finding** → diff sai. Sửa: `("target", "port")`.

---

## 3. Điểm yếu về OPSEC / stealth (đúng với định vị "evasion")

Đây là các chỗ **âm thầm phá vỡ tính ẩn danh** mà người dùng bug bounty rất quan tâm:

1. **Go engine không đi qua proxy / rate-limit / fingerprint của Python.**
   `dirfuzz` — module ồn ào nhất — chạy binary Go riêng, **không nhận `--proxy`, `--random-agent`, `-r` rate**. Đang dùng Tor mà chạy dirfuzz thì **lộ IP thật** và bắn full tốc độ. Cần truyền proxy/rate/UA xuống Go qua flag (`-proxy`, `-rate`, `-H`).

2. **`headers_ssl._get_ssl_cert()` mở socket TLS trực tiếp** (`socket.create_connection`) — bỏ qua proxy hoàn toàn → cũng lộ IP thật khi dùng proxy chain.

3. **`subdomain` / `wayback` gọi crt.sh & web.archive.org qua engine** nhưng các API này thường nằm ngoài scope — nếu người dùng cấu hình proxy nội bộ thì OK, nhưng nên tách rõ "passive OSINT egress" khỏi "traffic tới target".

4. **Header `Accept-Encoding` quảng cáo `zstd`** (`fingerprint.py`) trong khi aiohttp không giải nén được zstd → body có thể lỗi giải mã ở một số server. Nên bỏ `zstd` khỏi danh sách.

---

## 4. README nói quá so với code (nên chỉnh để giữ uy tín)

| README tuyên bố | Thực tế trong code |
|---|---|
| Subdomain qua "crt.sh, **TLS certs, DNS brute**" | `subdomain.py` **chỉ có crt.sh**; không có brute-force/DNS/TLS cert. `subdomains_top1k.txt` có sẵn nhưng không dùng. |
| "JavaScript **AST Parsing**" | AST parse được gọi rồi bỏ (`pass`); thực chất chỉ regex. |
| "HTTP/2", "TLS handshake rotation" | `config.http2` có nhưng không được dùng; không có JA3/TLS rotation. |
| "Automatic node health checks" (proxy) | `health_check_all()` tồn tại nhưng **không được gọi** trong luồng scan. |

Không phải bug, nhưng cộng đồng infosec rất "soi" — nên hoặc **implement** hoặc **hạ tông** mô tả để tránh mất niềm tin.

---

## 5. Góp ý nhỏ về chất lượng code

- `scheduler.run()` bắt `except KeyboardInterrupt` trong vòng lặp, nhưng `asyncio.gather` trong các module có thể nuốt Ctrl+C — nên test lại luồng graceful shutdown mà README nhấn mạnh.
- `engine.request()` retry cả `aiohttp.ClientError` chung → có thể retry cả lỗi không nên retry (vd DNS sai). Cân nhắc lọc theo loại lỗi.
- `db.py` mỗi `save_result` gọi `commit()` riêng — với scan lớn (dirfuzz hàng nghìn path) sẽ chậm; cân nhắc batch commit.
- Thiếu `ruff`/`mypy` trong CI dù có trong `requirements-dev.txt` — thêm bước lint sẽ bắt sớm các bug kiểu BUG-2.
- `LICENSE` (Research & Security) + `LICENSE-MIT` song song, README nói "MIT" ở badge nhưng lại có license kép — nên làm rõ để tránh nhập nhằng pháp lý cho người đóng góp.

---

## 6. Lộ trình để cộng đồng dùng "như một thói quen"

Muốn một tool recon trở thành *thói quen hằng ngày* (như `httpx`, `nuclei`, `subfinder` của ProjectDiscovery), yếu tố quyết định **không phải nhiều tính năng hơn**, mà là: cài dễ, chạy nhanh, tin được kết quả, và cắm được vào workflow tự động. Đề xuất theo thứ tự ưu tiên:

### Giai đoạn 1 — Làm cho "tin được" (1-2 tuần)
1. Sửa BUG-1→5 ở trên (đặc biệt BUG-2 và BUG-4 vì ảnh hưởng trực tiếp độ phủ và khả năng cài).
2. Thêm `ruff` + `mypy` vào CI.
3. Đồng bộ README với code (mục 4). Uy tín > hào nhoáng.

### Giai đoạn 2 — Làm cho "cài dễ" (yếu tố số 1 của thói quen)
4. **Phát hành lên PyPI thật** (`pip install falsealarm`) — badge hiện là `v1.0.0-dev` nhưng chưa có trên PyPI.
5. **Nhúng sẵn binary Go** cho Linux/macOS/Windows qua GitHub Releases + fallback tự tải, để người dùng không phải cài Go compiler. Đây là điểm nghẽn lớn nhất hiện tại.
6. Đóng gói `pipx` + Docker image publish lên GHCR (`docker pull ghcr.io/...`).

### Giai đoạn 3 — Cắm vào workflow (giữ chân người dùng)
7. **stdin/stdout thân thiện pipe** kiểu ProjectDiscovery: `subfinder -d x | falsealarm httpprobe | falsealarm vulnscan`. Đây là "văn hoá" khiến tool được dùng hằng ngày.
8. **Chế độ monitor thật sự**: `--diff` + `--notify` đã có → gói thành `falsealarm monitor` chạy cron/systemd, chỉ báo khi có thay đổi (asset mới, port mới, vuln mới). Đây chính là "thói quen" — người ta để nó chạy nền.
9. **Kho template cộng đồng**: tách templates ra repo riêng + lệnh `falsealarm templates update` (giống `nuclei -update-templates`). Template dễ đóng góp = cộng đồng tự nuôi tool.

### Giai đoạn 4 — Cộng đồng & niềm tin
10. Resolver/wildcard filtering chuẩn cho subdomain, đo false-positive rate công khai (benchmark vs subfinder/httpx). Dân bug bounty chọn tool theo tỉ lệ nhiễu.
11. Tài liệu `docs/` + ví dụ workflow thật (recon → triage → report). `CONTRIBUTING.md` đã có, thêm "good first issue" từ chính danh sách bug này.
12. Làm rõ license kép; cân nhắc MIT thuần để hạ rào cản đóng góp.

---

## 7. Tóm tắt ưu tiên

| # | Vấn đề | Mức độ | Công sức sửa |
|---|---|:---:|:---:|
| BUG-2 | Port web bị bỏ sót khỏi pipeline | Cao | Thấp |
| BUG-4 | pyjsparser làm fail `pip install` | Cao | Thấp |
| BUG-1 | `--adaptive-rate` không chạy | Cao | Rất thấp |
| BUG-3 | CORS origin dựng sai | Trung bình | Thấp |
| OPSEC-1 | Go engine lộ IP (không qua proxy) | Trung bình–Cao | Trung bình |
| BUG-5 | Diff portscan key trùng | Thấp | Rất thấp |
| README | Nói quá so với code | Thấp | Thấp |

4 bug đầu đều **sửa nhanh** và tạo khác biệt lớn nhất về độ tin cậy — nên làm trước tiên.
