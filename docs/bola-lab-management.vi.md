# Management API cho Controlled BOLA Lab

> **Trạng thái triển khai:** contract và kiểm thử local có coverage cho lifecycle, credential registry và console. Triển khai Machine B với mTLS thật, systemd, firewall/Tailscale ACL, proxy header stripping, Docker/NAT/IPv6 và nghiệm thu nhiều máy vẫn là **NOT VERIFIED**.

Management API là control plane riêng cho operator. Nó không thay đổi public BOLA data plane (`GET /health`, `GET /me`, `GET /books/{book_id}`), không thêm route lifecycle hoặc token vào public service và không dùng bearer token BOLA để xác thực quản trị.

## Ranh giới mTLS và quyền operator

Service bind `127.0.0.1`; TLS terminator phải xác thực mTLS, loại mọi identity/certificate header do client gửi, rồi mới inject `BOLA_MGMT_TLS_VERIFIED=SUCCESS` và WSGI `bola.mtls.identity`. `BOLA_MGMT_ROLE_MAPPING` map subject đã xác thực sang `reader`, `operator` hoặc `evaluator`.

CA trust **không đủ** để cấp quyền Token kiểm thử: chỉ principal có role `operator` được gọi credential endpoints hoặc nhận HTML chứa controls token. `reader`/`evaluator`, BOLA bearer và header tự gửi đều không được xem metadata hay token.

## Token kiểm thử

Console chỉ có ba lifecycle action: **Start, Reset, Stop**. Start đầu tiên tự tạo và validate private run (users, books, ownership/share, markers, manifest, answer sheet và credential registry), rồi khởi động duy nhất một lab. Reset chỉ chạy từ `STOPPED`: nó thay run bằng state mới đã validate và để lab ở `READY`; operator bấm Start để chạy replacement. Stop bị chặn khi còn evaluation lease chưa release và thu hồi credential active trước khi dừng service.

Mỗi Start đầu tiên hoặc Reset tự provision credential metadata cho đúng ba principal; raw bearer chỉ được ký khi operator chủ động **Hiện** hoặc **Sao chép** lúc lab đang `RUNNING`:

| Principal | Role |
| --- | --- |
| `admin` | `admin` |
| `userA` | `user` |
| `userB` | `user` |

Console hiển thị account, role, lúc cấp, hết hạn và `NOT_ISSUED`/`ACTIVE`/`EXPIRED`/`REVOKED`; token luôn bị che mặc định. Operator phải chủ động **Hiện** hoặc **Sao chép** từng token. Giá trị raw chỉ nằm trong memory tab sau response no-store, bị xóa khi pagehide, timeout, reset hoặc revoke; không dùng URL, localStorage, sessionStorage, IndexedDB, service-worker cache, analytics hay console log. Clipboard thuộc quyền kiểm soát của operator và phải xóa sau khi dùng.

Management API chỉ có trong mTLS control plane:

| Route | Quyền | Mục đích |
| --- | --- | --- |
| `GET /credentials` | operator | Metadata redacted của ba credential. |
| `POST /credentials/{subject}/reveal` | operator | Hiện tạm một token active và ghi audit không chứa value. |
| `POST /credentials/{subject}/copy-audit` | operator | Ghi việc operator yêu cầu copy, không mang credential. |
| `GET /credentials/audit` | operator | Lịch sử actor/action/account/time/result redacted. |

Mọi Start/Reset/Stop cần `Idempotency-Key` và `If-Match`. `UNKNOWN` chặn mọi transition và credential reveal/copy cho đến khi đối soát ngoài băng. Stop thu hồi credential active; Reset tạo signing secret/registry mới nên tất cả token cũ bị từ chối sau request kế tiếp.

Credential registry nằm trong private `lab.sqlite3`; không lưu serialized bearer. Token v2 mang `sub`, `role`, `jti`, `exp`, ký HMAC bằng signing secret private. Public GET service kiểm signature/expiry **và** lookup registry ở mỗi request. Token revoked, expired, malformed hoặc từ run cũ luôn nhận neutral `401 {"error":"unauthorized"}` mà không restart service.

## Audit, caching và console security

Control journal/audit chỉ lưu actor, action, subject/role, timestamp, request hash, operation ID/state và safe result code. Nó không lưu bearer, token payload, `jti`, signing secret, response body, marker, state path hoặc body request thô. `GET /operations/{id}` tiếp tục redacted.

Mọi response management (kể cả token-bearing response) có `Cache-Control: no-store, max-age=0`, `Pragma: no-cache`, `Expires: 0`, CSP same-origin, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` và `nosniff`. Browser mutation cần exact configured Origin, Fetch Metadata same-origin, `X-Management-Console`, CSRF HMAC bind subject + certificate fingerprint. Không bật CORS.

## Lifecycle và vận hành

Start, Reset và Stop giữ interlock lifecycle/lease. Không có token artifact `issued-tokens.json`, manual issue/reissue/revoke endpoint hoặc local `show-token` command. Controller seed private data/manifest; lifecycle tự provision registry claims, còn operator mTLS chỉ reveal/copy raw bearer cho lab đang chạy. Public API vẫn GET-only và OpenAPI public không chứa credential, registry, management, reset hoặc private state route.

Luồng operator: **Start → mở Token kiểm thử → hiện/sao chép theo role qua protected channel → chạy kiểm thử → Stop → Reset khi cần run mới → Start**. Khi real deployment được nghiệm thu phải kiểm mTLS negative cases, proxy stripping, access logs không ghi `Authorization`/management response body, no-store, firewall/LAN/NAT/IPv6 và token revoked từ Machine A bị từ chối.
