# Management API cho Controlled BOLA Lab

> **Trạng thái triển khai:** contract và kiểm thử local có coverage cho lifecycle, credential registry và console. Triển khai Machine B với mTLS thật, systemd, firewall/Tailscale ACL, proxy header stripping, Docker/NAT/IPv6 và nghiệm thu nhiều máy vẫn là **NOT VERIFIED**.

Management API là control plane riêng cho operator. Nó không thay đổi public BOLA data plane (`GET /health`, `GET /me`, `GET /books/{book_id}`), không thêm route lifecycle hoặc token vào public service và không dùng bearer token BOLA để xác thực quản trị.

## Ranh giới mTLS và quyền operator

Service bind `127.0.0.1`; TLS terminator phải xác thực mTLS, loại mọi identity/certificate header do client gửi, rồi mới inject `BOLA_MGMT_TLS_VERIFIED=SUCCESS` và WSGI `bola.mtls.identity`. `BOLA_MGMT_ROLE_MAPPING` map subject đã xác thực sang `reader`, `operator` hoặc `evaluator`.

CA trust **không đủ** để cấp quyền Token kiểm thử: chỉ principal có role `operator` được gọi credential endpoints hoặc nhận HTML chứa controls token. `reader`/`evaluator`, BOLA bearer và header tự gửi đều không được xem metadata hay token.

## Token kiểm thử

Sau `init → validate → start`, operator mở `GET /management/console`, vào **Token kiểm thử**, chọn TTL 300–86.400 giây và cấp credential cho đúng ba principal:

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
| `POST /credentials/issue` | operator | Cấp initial batch với `token_ttl_seconds`. Response bearer là `no-store`. |
| `POST /credentials/{subject}/reissue` | operator | Cấp lại sau `EXPIRED`/`REVOKED`; response xác nhận token cũ đã vô hiệu. |
| `POST /credentials/revoke-all` | operator | Thu hồi ngay mọi token active. |
| `POST /credentials/{subject}/reveal` | operator | Hiện tạm một token active và ghi audit không chứa value. |
| `POST /credentials/{subject}/copy-audit` | operator | Ghi việc operator yêu cầu copy, không mang credential. |
| `GET /credentials/audit` | operator | Lịch sử actor/action/account/time/result redacted. |

Mọi issue/reissue/revoke cần `Idempotency-Key` và `If-Match`. Issue/reissue bị chặn khi lifecycle `UNKNOWN`; `revoke-all` vẫn được chấp nhận vì chỉ giảm quyền. Reissue không âm thầm thay token active: chỉ credential đã hết hạn hoặc bị thu hồi mới đủ điều kiện. Reset tạo signing secret/registry mới nên tất cả token cũ bị từ chối sau request kế tiếp.

Credential registry nằm trong private `lab.sqlite3`; không lưu serialized bearer. Token v2 mang `sub`, `role`, `jti`, `exp`, ký HMAC bằng signing secret private. Public GET service kiểm signature/expiry **và** lookup registry ở mỗi request. Token revoked, expired, malformed hoặc từ run cũ luôn nhận neutral `401 {"error":"unauthorized"}` mà không restart service.

## Audit, caching và console security

Control journal/audit chỉ lưu actor, action, subject/role, timestamp, request hash, operation ID/state và safe result code. Nó không lưu bearer, token payload, `jti`, signing secret, response body, marker, state path hoặc body request thô. `GET /operations/{id}` tiếp tục redacted.

Mọi response management (kể cả token-bearing response) có `Cache-Control: no-store, max-age=0`, `Pragma: no-cache`, `Expires: 0`, CSP same-origin, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` và `nosniff`. Browser mutation cần exact configured Origin, Fetch Metadata same-origin, `X-Management-Console`, CSRF HMAC bind subject + certificate fingerprint. Không bật CORS.

## Lifecycle và vận hành

`init`, `validate`, `start`, `stop`, `reset` giữ nguyên interlock lifecycle/lease. Không có token artifact `issued-tokens.json` hoặc local `show-token` command nữa. Controller chỉ seed data/private manifest; credential do operator mTLS issue sau khi lab chạy. Public API vẫn GET-only và OpenAPI public không chứa credential, registry, management, reset hoặc private state route.

Luồng operator: **Khởi tạo → Validate → Start → mở Token kiểm thử → cấp/hiện/sao chép theo role qua protected channel → chạy kiểm thử → Thu hồi toàn bộ → Stop**. Khi real deployment được nghiệm thu phải kiểm mTLS negative cases, proxy stripping, access logs không ghi `Authorization`/management response body, no-store, firewall/LAN/NAT/IPv6 và token revoked từ Machine A bị từ chối.
