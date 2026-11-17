# Management API cho Controlled BOLA Lab

> **Trạng thái triển khai:** contract và kiểm thử local đã có. Triển khai Machine B, mTLS thực, systemd, firewall/Tailscale ACL, proxy header stripping, Docker/NAT/IPv6 và nghiệm thu nhiều máy vẫn là **NOT VERIFIED**.

Management API là control plane riêng cho operator. Nó **không** thay đổi public BOLA data plane (`GET /health`, `GET /me`, `GET /books/{book_id}`), không thêm route lifecycle vào public service và không sử dụng bearer token BOLA làm thông tin xác thực quản trị.

## Phạm vi hiện có

Prefix là `/management/v1`; đặc tả máy đọc được nằm tại [`openapi_specs/bola-lab-management.openapi.json`](../openapi_specs/bola-lab-management.openapi.json).

| Route | Role | Mục đích |
| --- | --- | --- |
| `GET /status` | reader/operator/evaluator | trạng thái redacted, version, expiry, generation, lease summary |
| `GET /scenarios` | reader/operator/evaluator | danh sách S01–S12 và mô tả public |
| `POST /init`, `/validate`, `/start`, `/stop`, `/reset` | operator | lifecycle có idempotency và optimistic version |
| `GET /operations/{operation_id}` | reader/operator/evaluator | trạng thái operation redacted |
| `POST /evaluation-leases`, `renew`, `DELETE` | evaluator | interlock hữu hạn cho lượt đánh giá |

`POST /credential-handoffs` **chưa tồn tại**. Không có endpoint nào trả bearer token, signing secret, marker, answer sheet, SQLite, state path hoặc controller stdout. Credential handoff bị BLOCKED cho đến khi receiver mTLS và secret storage được thiết kế/triển khai riêng.

## Ranh giới mTLS bắt buộc

Service bind `127.0.0.1` mặc định. Một TLS terminator/operator-managed WSGI integration phải:

1. thực hiện mTLS thật với CA/CRL/certificate policy của operator;
2. xoá mọi header identity/certificate/forwarding do client gửi;
3. chỉ khi xác thực thành công mới inject `BOLA_MGMT_TLS_VERIFIED=SUCCESS` và WSGI environ `bola.mtls.identity` chứa JSON canonical `{"subject":"...","fingerprint":"..."}`;
4. đặt `BOLA_MGMT_ROLE_MAPPING` là JSON mapping protected từ subject sang `reader`, `operator` hoặc `evaluator`.

App không đọc `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `X-Client-Cert`, Authorization bearer hoặc bất kỳ header client nào để nhận diện operator. Thiếu/malformed boundary trả `401` trung tính.

## Cấu hình và systemd

Management launcher cần các biến operator-controlled sau; chúng không được nhận qua HTTP request:

```bash
export BOLA_LAB_STATE_DIR=/var/lib/bola-lab
export BOLA_MGMT_STATE_DIR=/var/lib/bola-lab-management
export BOLA_MGMT_SYSTEMD_UNIT=vampi-bola-lab.service
export BOLA_MGMT_PORT=5443
export BOLA_MGMT_ROLE_MAPPING='{"spiffe://lab/operator":"operator","spiffe://lab/auditor":"reader","spiffe://lab/evaluator":"evaluator"}'
# HTTPS origin chính xác, canonical, không có path và không ghi :443.
export BOLA_MGMT_CONSOLE_ORIGIN=https://management.example.test
# Secret riêng, tối thiểu 32 byte; chỉ cấp cho service account/proxy đáng tin cậy.
export BOLA_MGMT_CONSOLE_CSRF_SECRET='replace-with-a-32-byte-minimum-operator-secret'
# Tuỳ chọn, 300–1800 giây; mặc định 900.
export BOLA_MGMT_CONSOLE_CSRF_TTL_SECONDS=900
```

```bash
python bola_lab_management_app.py
```

`BOLA_MGMT_SYSTEMD_UNIT` chỉ chấp nhận một service unit name hợp lệ, được đọc lúc startup. Worker chỉ gọi `systemctl is-active|start|stop` với unit đã pin; request không thể truyền command, argv, unit, state path, target URL hoặc Docker socket. Quyền service account phải dùng policy systemd/polkit/sudo hạn chế đúng unit này. Không chạy launcher trực tiếp trên LAN/Internet; TLS/mTLS reverse proxy là deployment prerequisite.

Control journal dùng `control.sqlite3` trong `BOLA_MGMT_STATE_DIR` mode `0700`/`0600`, tách khỏi `lab.sqlite3` để reset lab không xoá audit/idempotency/lease. Journal chỉ lưu actor, action, request hash, operation ID, lifecycle/version/generation và safe code — không lưu secret/token/body thô. Khi khởi động, operation `RUNNING` bị gián đoạn chuyển `UNKNOWN`; lifecycle write tiếp theo bị chặn để operator reconcile, không tự retry.

## Management Console cùng origin

Console tối giản nằm tại `GET /management/console` trên **cùng HTTPS origin và boundary mTLS** với management API. Đây không phải public BOLA UI, không được thêm vào public OpenAPI và không chạy origin/process riêng. Browser phải đi qua TLS terminator đã xác thực certificate như phần mTLS ở trên; launcher vẫn chỉ bind loopback.

- Console chỉ dùng same-origin request tới `/management/v1/*`; không bật CORS, không dùng bearer token và không dùng CDN/third-party script.
- HTML, CSS, JS và API đều yêu cầu management identity. `reader` chỉ xem status/scenario/operation; `operator` chỉ có lifecycle; `evaluator` chỉ có lease.
- Mỗi mutation do browser phát phải có `X-Management-Console: 1`, CSRF HMAC ngắn hạn bind theo subject + certificate fingerprint, `Origin` đúng bằng `BOLA_MGMT_CONSOLE_ORIGIN`, và Fetch Metadata same-origin (`Sec-Fetch-Site: same-origin`, `Sec-Fetch-Mode: cors`, `Sec-Fetch-Dest: empty`). Direct mTLS automation không đặt marker này vẫn theo contract API hiện có.
- Token CSRF, operation ID và lease ID chỉ ở memory của trang. Không có URL parameter, localStorage, analytics, service worker cache hay UI để xem/cấp/handoff token BOLA, signing secret, marker, answer sheet, private file/database/state path hay controller log.
- Response gửi `no-store`, CSP chỉ local `self`, anti-frame, `nosniff` và `no-referrer`. HSTS là trách nhiệm TLS proxy và **không được claim verified** bởi Flask.
- Console tạo một idempotency key cho mỗi lần lifecycle do người dùng chủ động gửi. Nó poll `Location` tới terminal operation rồi refresh status; không coi `202` là success và không tự tạo mutation retry. Sau `409`/`412`, refresh trạng thái và người vận hành phải gửi lại có chủ đích.
- Reset vẫn cần checkbox xác nhận trong UI và `confirm_invalidate_tokens=true` qua API. `UNKNOWN` chỉ hiển thị block/escalation; không có force-reconcile/retry trong browser.

> **NOT VERIFIED:** Browser certificate selection, TLS terminator header stripping/injection, exact `Origin` serialization phía proxy, CSP enforcement trên browser triển khai thực và đường mạng Machine A/B phải được nghiệm thu trên Machine B trước khi công nhận deployment.

## Lifecycle và concurrency

- State ban đầu: `UNINITIALIZED`.
- `init` chỉ khi private state chưa tồn tại và service pinned đang inactive/failed.
- `validate` yêu cầu service stopped; thành công tạo `STOPPED` + `validated=true`.
- `start` yêu cầu state validated và token chưa hết hạn; supervisor phải xác nhận `active`.
- `stop` và `reset` bị chặn khi có **bất kỳ lease chưa release** nào, kể cả lease đã hết hạn; hết hạn không chứng minh evaluation đã dừng. Evaluator phải release tường minh sau khi hoàn tất, hoặc operator phải reconcile ngoài băng trước khi thay đổi lifecycle.
- `reset` chỉ ở `STOPPED`, cần `confirm_invalidate_tokens=true`; token/marker cũ bị rotate và generation tăng.
- Timeout/supervisor error, final supervisor state `activating`/`deactivating`/`unknown`, hoặc operation interrupted không được coi là success/failure chắc chắn; state `UNKNOWN` yêu cầu reconcile operator.

Mọi lifecycle mutation cần hai header:

```text
Idempotency-Key: <16-128-character opaque value>
If-Match: <state_version from GET /status>
```

Cùng actor/key/route/body trả operation cũ; cùng key nhưng body khác trả `409`; header thiếu trả `428`; version stale trả `412`. Mutation trả `202` và `Location: /management/v1/operations/<opaque-id>`; `GET operation` không chứa private run ID.

Lease là interlock có giới hạn, không chứng minh chắc chắn rằng client manual không còn dùng token. Vì vậy quy trình operator vẫn phải quiesce mọi consumer không được lease tracking bao phủ trước reset. Expiry lease không tự reset hoặc restart lab.

## Khôi phục và rollback

1. Khi management service/service unit crash hoặc status `UNKNOWN`, dừng mọi lifecycle write.
2. Operator kiểm tra pinned systemd unit, public `/health`, ownership `server.lock`, private artifact permissions và control journal trên Machine B.
3. Chỉ sau khi reconcile thực tế mới cập nhật/quyết định transition theo quy trình operator; không xoá lock hoặc khôi phục token cũ tự động.
4. Rollback management service không rollback credential generation hay phát hành lại token cũ.

## Kiểm thử thực tế còn phải làm

Các test local chỉ dùng fake systemd và test identity provider. Trước khi công nhận deployment cần chạy LCA-01…LCA-12 theo LAB-CONTROL-API-01: mTLS certificate/role negative cases, systemd privilege boundary, stop/reset races, crash staging/recovery, token rotation/handoff (sau khi receiver tồn tại), public S01–S12 regression, firewall/Tailscale ACL, spoofed forwarding header, IPv6/direct routing và từ ít nhất một host bị từ chối. Không ghi token, marker, answer-sheet, state path hoặc raw controller output vào evidence Machine A.
