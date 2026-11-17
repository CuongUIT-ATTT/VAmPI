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
```

```bash
python bola_lab_management_app.py
```

`BOLA_MGMT_SYSTEMD_UNIT` chỉ chấp nhận một service unit name hợp lệ, được đọc lúc startup. Worker chỉ gọi `systemctl is-active|start|stop` với unit đã pin; request không thể truyền command, argv, unit, state path, target URL hoặc Docker socket. Quyền service account phải dùng policy systemd/polkit/sudo hạn chế đúng unit này. Không chạy launcher trực tiếp trên LAN/Internet; TLS/mTLS reverse proxy là deployment prerequisite.

Control journal dùng `control.sqlite3` trong `BOLA_MGMT_STATE_DIR` mode `0700`/`0600`, tách khỏi `lab.sqlite3` để reset lab không xoá audit/idempotency/lease. Journal chỉ lưu actor, action, request hash, operation ID, lifecycle/version/generation và safe code — không lưu secret/token/body thô. Khi khởi động, operation `RUNNING` bị gián đoạn chuyển `UNKNOWN`; lifecycle write tiếp theo bị chặn để operator reconcile, không tự retry.

## Lifecycle và concurrency

- State ban đầu: `UNINITIALIZED`.
- `init` chỉ khi private state chưa tồn tại và service pinned đang inactive/failed.
- `validate` yêu cầu service stopped; thành công tạo `STOPPED` + `validated=true`.
- `start` yêu cầu state validated và token chưa hết hạn; supervisor phải xác nhận `active`.
- `stop` và `reset` bị chặn khi có evaluation lease active.
- `reset` chỉ ở `STOPPED`, cần `confirm_invalidate_tokens=true`; token/marker cũ bị rotate và generation tăng.
- Timeout/supervisor error hoặc operation interrupted không được coi là success/failure chắc chắn; state `UNKNOWN` yêu cầu reconcile operator.

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
