# SNMP 服务器监控系统

基于 Python + Flask + SNMP 的轻量级服务器硬件资源监控平台，通过 SNMP 协议主动采集服务器的 CPU、内存、磁盘使用率，并通过 Web 界面实时展示，支持企业微信机器人告警通知。

## 功能特性

- **硬件监控** — 通过 SNMP v2c 协议主动采集服务器 CPU、内存、磁盘分区使用率
- **实时面板** — Web 界面展示所有被控端设备状态，进度条直观显示资源占用
- **历史趋势** — 每台设备提供 CPU 和内存的历史趋势折线图（ECharts）
- **多字段排序** — 首页列表支持按名称、IP、系统类型、状态、CPU、内存升序/降序排序
- **自动刷新** — 首页支持下拉选择 10秒 / 30秒 / 60秒自动刷新，设置后记忆保留
- **告警通知** — 指标超阈值或设备离线时，自动推送企业微信群机器人通知
- **双机器人推送** — 支持配置 2 个企业微信群机器人，填写几个就发几个群
- **独立阈值** — 每台设备可单独设置 CPU、内存、磁盘的告警阈值，也可使用全局阈值
- **告警去重** — 同一设备同一指标 1 小时内仅发送一次告警，恢复正常时自动发送恢复通知
- **离线检测** — 连续多次采集失败自动标记设备离线，恢复后自动通知
- **并发采集** — 线程池并发采集（最多 20 台同时），适用于大规模服务器集群
- **数据清理** — 支持配置历史数据保留天数，每天凌晨自动清理过期数据
- **完全离线** — 前端资源（Bootstrap、ECharts）全部本地化，无需联网即可使用
- **多系统支持** — 支持 Linux、Windows 及其他 SNMP 兼容系统

## 截图预览

> 首页仪表盘展示所有被控端设备的 CPU、内存、磁盘使用率，顶部统计在线/离线设备数量，支持多字段排序和自动刷新。

## 技术栈

| 组件 | 技术 |
|---|---|
| 后端框架 | Flask |
| 数据库 | SQLite（SQLAlchemy ORM） |
| SNMP 采集 | pysnmp 4.4.12 |
| 定时调度 | APScheduler |
| 前端样式 | Bootstrap 5（本地离线） |
| 图表 | ECharts（本地离线） |
| 通知推送 | 企业微信群机器人 Webhook |

## 项目结构

```
snmp-monitor/
├── app.py                      # 主程序（Flask 应用、SNMP 采集、告警、路由）
├── asyncore.py                 # Python 3.12+ 兼容补丁
├── README.md
├── static/
│   ├── bootstrap.min.css       # Bootstrap CSS（离线）
│   ├── bootstrap.bundle.min.js # Bootstrap JS（离线）
│   └── echarts.min.js          # ECharts 图表库（离线）
└── templates/
    ├── base.html               # 基础布局模板（导航栏）
    ├── index.html              # 首页（设备列表、排序、自动刷新）
    ├── config.html             # 系统全局配置页
    └── history.html            # 历史趋势图表页
```

## 环境要求

- **Python 3.9 ~ 3.11**（推荐）
- Python 3.12 / 3.13 需额外安装兼容补丁（见下方说明）
- 被控端需开启 SNMP v2c 服务并配置 Community（团体字）

## 快速开始

### 1. 安装依赖

```bash
pip install flask flask-sqlalchemy apscheduler requests pysnmp==4.4.12 pysmi==0.3.4 pyasn1==0.4.8
```

> 使用国内镜像加速：
> ```bash
> pip install flask flask-sqlalchemy apscheduler requests pysnmp==4.4.12 pysmi==0.3.4 pyasn1==0.4.8 -i https://mirrors.aliyun.com/pypi/simple/
> ```

### 2. 启动服务

```bash
python app.py
```

启动后默认监听 `http://0.0.0.0:888`

### 3. 访问 Web 界面

浏览器打开 `http://<服务器IP>:888` 即可进入监控面板。

### 4. 添加被控端

在首页点击「添加被控端」按钮，填写设备信息：

| 字段 | 说明 |
|---|---|
| 设备名称 | 备注名称，方便识别（选填） |
| IP 地址 | 被监控服务器的 IP 地址（必填） |
| SNMP 团体字 | Community 字符串，默认 `hxu` |
| 系统类型 | Linux / Windows / 其他 |

### 5. 配置告警（可选）

进入「系统配置」页面，可配置：

- 全局 CPU / 内存 / 磁盘报警阈值（默认 90%）
- 企业微信群机器人 Webhook URL（最多 2 个）
- 轮询间隔、历史数据保留天数等

## 被控端 SNMP 配置参考

### Linux（以 net-snmp 为例）

安装并配置 SNMP 服务：

```bash
# CentOS / RHEL
yum install net-snmp net-snmp-utils
systemctl enable --now snmpd

# Ubuntu / Debian
apt install snmpd snmp
systemctl enable --now snmpd
```

编辑 `/etc/snmp/snmpd.conf`，添加：

```
rocommunity hxu
```

> 将 `hxu` 替换为你实际使用的团体字，然后重启 `snmpd` 服务。

确保防火墙放通 UDP 161 端口：

```bash
firewall-cmd --permanent --add-port=161/udp
firewall-cmd --reload
```

### Windows

Windows Server 可通过「服务器管理器」添加 SNMP 服务功能，配置 Community 和允许的监控主机 IP。

## Python 3.12+ 兼容说明

Python 3.12 移除了标准库中的 `asyncore` 模块，而 pysnmp 4.4.12 依赖它。

**解决方法：** 将项目自带的 `asyncore.py` 文件复制到 Python 的 `site-packages` 目录下即可：

```
# 示例路径，请根据实际安装位置调整
cp asyncore.py /usr/local/lib/python3.12/site-packages/

# Windows 示例
copy asyncore.py C:\Users\<用户名>\AppData\Local\Programs\Python\Python312\Lib\site-packages\
```

> 该文件来自 Python 3.11 标准库，已去除弃用警告，不影响其他功能。

## 配置参数说明

| 参数 | 默认值 | 说明 |
|---|---|---|
| 轮询间隔 | 60 秒 | 采集所有设备的间隔时间 |
| 每页显示机器数 | 100 | 首页列表分页大小 |
| 全局 CPU 报警阈值 | 90% | CPU 使用率超过此值触发告警 |
| 全局内存报警阈值 | 90% | 内存使用率超过此值触发告警 |
| 全局硬盘报警阈值 | 90% | 磁盘分区使用率超过此值触发告警 |
| 连续几次无响应判定离线 | 10 次 | 连续采集失败次数达到后标记离线 |
| 历史数据保留天数 | 180 天 | 超过此天数的历史记录自动清理 |
| 企业微信机器人 Webhook | 空 | 填写后启用告警推送 |
| 企业微信机器人 Webhook（第 2 个） | 空 | 选填，填写后同时推送到两个群 |

## 告警规则

- **超阈值告警** — CPU / 内存 / 磁盘使用率达到阈值，且距上次告警超过 1 小时
- **恢复通知** — 之前告警的指标恢复正常后自动推送
- **设备离线** — 连续采集失败次数达到设定值时告警
- **设备上线** — 离线设备重新恢复通信时通知
- **独立阈值** — 每台设备可单独设置阈值，填 0 则使用全局阈值

## SNMP 采集 OID 说明

| 采集项 | OID | 说明 |
|---|---|---|
| CPU | 1.3.6.1.2.1.25.3.3.1.2 | hrProcessorLoad，遍历所有核心取平均值 |
| 内存 | 1.3.6.1.2.1.25.2.3.1.* | hrStorageTable，筛选 hrStorageRam 类型 |
| 磁盘 | 1.3.6.1.2.1.25.2.3.1.* | hrStorageTable，筛选 hrStorageFixedDisk 类型 |

## 开源协议

MIT License
