# 固定内网区域主备 DNS（FastAPI + SQLite + dnslib）

为固定内网区域 `internal.local`（可用 `DNS_ZONE` 修改）提供主备两台权威 DNS：

- **主机 (primary)**：通过 REST API 接收一次提交、最多 8 条 A 记录的**完整区域**；
  仅在整份区域校验并落库成功后才把序号 (serial) 加 1。发布不依赖备用机。
- **备用机 (backup)**：从主机 HTTP 拉取**整份版本**，支持手动同步、后台自动同步和
  版本查询；两机各自使用独立 SQLite 数据库（不同文件/卷）。
- 两机都通过 **UDP 53 风格端口（默认 5053）** 回答区域内 A 查询，每个回答只取自
  **一份不可变的完整版本**快照，绝不混版。

## 设计要点与需求对应

| 需求 | 实现方式 |
| --- | --- |
| 单次提交 ≤8 条 A 记录的完整区域 | `app/models.py`：非空、≤8、仅 IPv4、名称必须在固定区域内、禁止重名 |
| 发布成功才递增序号 | `Storage.next_publish()`：单事务 `BEGIN IMMEDIATE` 内插入新版本并切换 active 指针；校验失败在进事务前返回 422，序号不变 |
| 两机独立数据库 | 各自 `DB_PATH`（compose 中 `primary-data` / `backup-data` 两个卷） |
| 单次回答只用一份完整版本 | `zone_versions` 存不可变整份快照；DNS 解析前一次性读取 active 版本，再在内存中查表回答 |
| 手动同步 + 版本查询 | `POST /api/sync`、`GET /api/version`、`GET /api/zone` |
| 慢传/断传期间继续回答旧版 | 传输失败（连接拒绝、超时、HTTP 错误、坏报文）不触碰 active 版本，旧版本继续服务；同步状态写入 `state` 表 |
| 断开/重启后自动追到最新版 | 备用机启动即拉取一次，之后按 `SYNC_INTERVAL` 后台循环，直到与上游同序号 |
| 迟到旧传输不得回退 | `commit_version()` 拒绝任何 `serial <= active_serial` 的版本（返回 `ignored_stale`/False），事务保护 |
| 任一方失败仍供原版 | 发布失败保留旧 active；同步失败保留旧 active；DNS 与 HTTP 在同一进程内独立运行 |
| 主机发布无需等待备用 | 主机 API 不调用备用机；e2e 中备用停机时发布仍在毫秒级成功 |
| 区域诊断接口 | `POST /api/diagnose`：最多 4 个区域内 A 域名，读取两机当前快照 + 直查两机 UDP，逐名给出结论（见下节） |
| Docker Compose 双服务 + Swagger | `docker-compose.yml` 起 primary/backup；`http://<host>:8080/docs`、`http://<host>:8081/docs` |

### 数据模型（SQLite，WAL 模式）

```
zone_versions(serial INTEGER PRIMARY KEY, records_json TEXT,
              record_count INTEGER, published_at TEXT)   -- 不可变整份版本
state(key TEXT PRIMARY KEY, value TEXT)
        active_serial      当前生效版本指针
        last_sync_*        备用机最近一次同步状态（at/status/error）
        upstream_serial    最近看到的上游序号
```

版本切换 = 插入新版本行 + 更新 `active_serial` 指针，在同一个事务里提交，
因此外部观察到的永远是“某一份完整版本”，不存在中间态。

## 端口与 API

| 角色 | API/Swagger | UDP DNS |
| --- | --- | --- |
| primary | 主机 8080 → 容器 8000 | 主机 5053 → 容器 5053/udp |
| backup  | 主机 8081 → 容器 8000 | 主机 5054 → 容器 5053/udp |

- `GET  /health` 健康检查
- `GET  /api/version` 角色、当前序号、记录数、备用机同步状态
- `GET  /api/zone` 当前完整区域（含 serial、records、published_at）
- `POST /api/zone` **仅主机**，请求体 `{"records":[{"name":"db.internal.local","ip":"10.0.0.11"}]}`，成功返回 201 与新 serial
- `POST /api/sync` **仅备用机**，立即拉取一次，返回 `synced` / `ignored_stale` / `failed`
- `POST /api/diagnose` 区域诊断（两机均可调用），见下节

### 区域诊断 `POST /api/diagnose`

请求体最多 4 个区域内 A 域名（大小写/末尾点会被规范化，重复、区域外、非 A
名称一律 422）：

```json
{"names": ["db.internal.local", "web.internal.local"]}
```

一次诊断依次执行：

1. 通过 REST API 读取**两机当前区域快照**（`GET /api/zone`，本机端口不可达时
   退回本地存储并在 `snapshot.source` 标注 `local`）；
2. 向两台 UDP DNS 各发一个 A 查询（并发送出、整体受 deadline 约束）；
3. 再次读取两机快照，确认整段检查期间没有换版。

逐名返回：`verdict`、说明 `detail`、两机的 `snapshot`（版本号、该名地址、
是否可读）与 `udp`（是否应答、rcode、实际地址、超时原因）。响应顶层还有
`versions_at_start` / `versions_at_end` 与 `retest_required`。

判定优先级（每名只有一个结论）：

| verdict | 含义 | 触发条件 |
| --- | --- | --- |
| `consistent` | 一致 | 两机同版本、快照相同，且各自 UDP 应答与快照一致 |
| `backup_behind` | 备用落后 | 两机版本不同，备用序号更小（**不**跨版本比对 UDP 应答） |
| `content_mismatch` | 同号内容不一致 | 两机序号相同但快照中该名地址不同 |
| `node_answer_abnormal` | 节点应答异常 | 某机 UDP 应答与**它自己**的快照矛盾（地址或 rcode 不符），或版本对异常 |
| `udp_no_response` | UDP 无响应 | 至少一台超时无应答；仍返回另一台已得到的结果 |
| `retest_required` | 待复测 | 检查期间任一节点换版（start/end 序号不同或无法复核）：**不会**把不同版本的应答拼成故障 |
| `diagnosis_incomplete` | 无法比对 | 某机快照读取失败，内容无法比较（非故障结论） |

示例（compose 起来后，两机已同步同一版本）：

```bash
curl -sX POST http://localhost:8080/api/diagnose \
  -H 'content-type: application/json' \
  -d '{"names":["db.internal.local","web.internal.local"]}' | python -m json.tool
```

```json
{
  "zone": "internal.local",
  "checked_at": "2026-11-16T00:00:00Z",
  "versions_at_start": {"primary": 3, "backup": 3},
  "versions_at_end":   {"primary": 3, "backup": 3},
  "retest_required": false,
  "names": [
    {
      "name": "db.internal.local",
      "verdict": "consistent",
      "detail": "serial=3 on both nodes, snapshot and UDP answer agree: 10.0.0.11",
      "primary": {
        "role": "primary", "api_base": "http://127.0.0.1:8000",
        "snapshot": {"serial": 3, "published_at": "...", "found": true,
                     "addresses": ["10.0.0.11"], "error": null,
                     "available": true, "source": "api"},
        "udp": {"responded": true, "rcode": "NOERROR",
                "addresses": ["10.0.0.11"], "error": null}
      },
      "backup": {
        "role": "backup", "api_base": "http://backup:8000",
        "snapshot": {"serial": 3, "published_at": "...", "found": true,
                     "addresses": ["10.0.0.11"], "error": null,
                     "available": true, "source": "api"},
        "udp": {"responded": true, "rcode": "NOERROR",
                "addresses": ["10.0.0.11"], "error": null}
      }
    }
  ]
}
```

诊断不参与发布/同步：只在调用方请求内做只读快照与 UDP 查询，不持有发布或
同步的锁，异步 I/O 期间事件循环可继续处理发布、后台同步与区域内 UDP 解析。
单次 UDP 查询和整次诊断分别受 `DIAGNOSE_UDP_TIMEOUT` 与 `DIAGNOSE_DEADLINE`
限制。

DNS 行为：区域内 A 查询命中返回 NOERROR+A；区域内不存在的名称 NXDOMAIN；
区域内非 A 查询（如 AAAA）返回 NOERROR NODATA；区域外查询 REFUSED。

## 运行方式

### Docker Compose（推荐）

```bash
docker compose up --build
# 主机 Swagger:  http://localhost:8080/docs
# 备用 Swagger:  http://localhost:8081/docs

curl -sX POST http://localhost:8080/api/zone -H 'content-type: application/json' \
  -d '{"records":[{"name":"db.internal.local","ip":"10.0.0.11"},
                  {"name":"web.internal.local","ip":"10.0.0.21"}]}'

# 手动同步（后台也会每 3 秒自动同步）
curl -sX POST http://localhost:8081/api/sync

# 区域诊断：核对两机快照与实际 UDP 应答
curl -sX POST http://localhost:8080/api/diagnose \
  -H 'content-type: application/json' \
  -d '{"names":["db.internal.local","web.internal.local"]}'

# UDP 查询
dig @127.0.0.1 -p 5053 db.internal.local A
dig @127.0.0.1 -p 5054 db.internal.local A   # 备用机
```

### 本地直接运行（无 Docker 时）

```bash
python3 -m venv .venv --without-pip   # 或普通 venv
.venv/bin/pip install -r requirements.txt
DNS_ROLE=primary DB_PATH=./data/primary.db DNS_PORT=15053 API_PORT=18000 \
  .venv/bin/python -m uvicorn app.main:app --port 18000
DNS_ROLE=backup  DB_PATH=./data/backup.db  DNS_PORT=15054 API_PORT=18001 \
  PRIMARY_API_URL=http://127.0.0.1:18000 \
  .venv/bin/python -m uvicorn app.main:app --port 18001
```

## 测试

```bash
.venv/bin/python -m pytest tests/test_unit.py tests/test_diagnose_unit.py -q  # 单元（校验/事务/防回退/诊断判定）
.venv/bin/python -I tests/e2e_test.py                # 双进程端到端 30 项
.venv/bin/python -I tests/auto_sync_test.py          # 自动同步/幂等/Swagger 8 项
.venv/bin/python -I tests/diagnose_test.py           # 区域诊断 41 项
```

`tests/diagnose_test.py` 覆盖：两机一致的正常结论、请求校验（0/5 个、区域外、
重复、大小写与末尾点）、备用机调用、Swagger/OpenAPI；随后用可控的假备用机
分别制造备用落后、同号内容不一致、自相矛盾应答、UDP 静默、检查期间换版
（必须 `retest_required` 而非故障）、慢上游期间发布/解析/同步不被阻塞。

端到端覆盖：启动空版本 NXDOMAIN、非法发布不升序号、发布后 UDP 应答、
手动与自动同步、黑洞上游期间旧版持续服务、恢复后自动追平、
迟到旧版本注入被拒且不回退、进程重启持久化与追赶、备用停机时主机照常发布。

## 配置（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DNS_ROLE` | `primary` | `primary` 或 `backup` |
| `DNS_ZONE` | `internal.local` | 固定内网区域名 |
| `DB_PATH` | `/data/dns.db` | 本机独立 SQLite 文件 |
| `DNS_PORT` / `API_PORT` | `5053` / `8000` | UDP DNS / HTTP 端口 |
| `PRIMARY_API_URL` | `http://primary:8000` | 备用机指向上机 API |
| `SYNC_INTERVAL` | `5` | 备用机后台同步间隔秒 |
| `HTTP_TIMEOUT` | `10` | 拉取区域 HTTP 超时秒 |
| `MAX_RECORDS` | `8` | 单次区域最大 A 记录数 |
| `BACKUP_API_URL` | 空 | **主机**访问备用机 API 的地址（诊断用；compose 已配 `http://backup:8000`） |
| `SELF_API_URL` | 空 | 诊断读取本机快照的 API 地址；空则 `http://127.0.0.1:<API_PORT>` |
| `PRIMARY_DNS_ADDR` | `primary:5053` | 诊断时直查的主机 UDP 地址 |
| `BACKUP_DNS_ADDR` | `backup:5053` | 诊断时直查的备用 UDP 地址 |
| `DIAGNOSE_UDP_TIMEOUT` | `2` | 单次 UDP 查询超时秒 |
| `DIAGNOSE_UDP_ATTEMPTS` | `1` | 单次 UDP 查询重试次数 |
| `DIAGNOSE_DEADLINE` | `6` | 整次诊断总预算秒 |

## 已知边界

- 仅支持 A 记录与 IPv4（题目范围）；区域固定为一个，区域名通过配置设定。
- 传输为整份区域拉取（无增量/AXFR 分帧）；区域上限 8 条，单份报文很小。
- 单机内嵌一个 UDP 解析线程与一个 uvicorn 进程；未做水平扩展与 TSIG 鉴权，
  内网部署时应限制 `/api/zone` 的调用来源。
- 诊断是**诊断时的抽样**：它比较的是触发请求那一刻两机快照与 UDP 实际应答，
  不追溯历史；若检查窗口内换版则明确给出 `retest_required` 而不下故障结论。
  它也不判断终端侧缓存（TTL 30s）——终端仍解析到旧地址时，若两机当前一致，
  说明旧答案来自更早的缓存/更早的版本，需在终端或中间解析器侧核查。
- 诊断要求两机 API 互通（`BACKUP_API_URL` / `PRIMARY_API_URL`）；未配置时接口
  返回 503 并说明缺哪个设置。
