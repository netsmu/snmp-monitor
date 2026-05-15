import os
import json
import time
import requests
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
from pysnmp.hlapi import *

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///monitor.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.urandom(24)  # flash 消息依赖 session，需要 secret_key

# 高并发数据库连接池配置，防止 QueuePool 溢出崩溃
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 50,
    'max_overflow': 100,
    'pool_timeout': 60
}

db = SQLAlchemy(app)

# ================= 数据库模型 =================
class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.String(200), nullable=False)

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), default='')  # 新增：被控端名称备注
    ip = db.Column(db.String(50), unique=True, nullable=False)
    community = db.Column(db.String(50), default='hxu')
    os_type = db.Column(db.String(20), default='unknown') 
    cpu_threshold = db.Column(db.Integer, default=0)
    mem_threshold = db.Column(db.Integer, default=0)
    disk_threshold = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='unknown')
    fail_count = db.Column(db.Integer, default=0)

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'))
    timestamp = db.Column(db.DateTime, default=datetime.now)
    cpu_usage = db.Column(db.Float)
    mem_usage = db.Column(db.Float)
    disk_data = db.Column(db.Text) 

alert_cache = {}

# 修改：默认历史记录保留天数改为 180 天
DEFAULT_CONFIG = {
    'interval': '60', 'per_page': '100', 'global_cpu': '90', 
    'global_mem': '90', 'global_disk': '90', 'max_fails': '10', 
    'retention_days': '180', 'wechat_webhook': '', 'wechat_webhook2': ''
}

def init_db():
    with app.app_context():
        db.create_all()
        for k, v in DEFAULT_CONFIG.items():
            if not Config.query.filter_by(key=k).first():
                db.session.add(Config(key=k, value=v))
        db.session.commit()

def get_config(key, default_type=int):
    with app.app_context():
        c = Config.query.filter_by(key=key).first()
        val = c.value if c else DEFAULT_CONFIG.get(key)
        return default_type(val) if val else ""

import requests

def send_wechat_alert(content, msg_type="warning"):
    prefix = "【警告】" if msg_type == "warning" else "【通知】"
    data = {
        "msgtype": "text",
        "text": {
            "content": f"{prefix} 系统通知\n{content}"
        }
    }

    for key in ('wechat_webhook', 'wechat_webhook2'):
        webhook = get_config(key, str)
        if not webhook:
            continue
        try:
            requests.post(webhook, json=data, timeout=5)
        except Exception:
            pass

def check_and_alert(device, metric_name, current_val, global_thresh, custom_thresh):
    thresh = custom_thresh if custom_thresh > 0 else global_thresh
    cache_key = f"{device.ip}_{metric_name}"
    
    # 告警时附带设备名称，方便识别
    dev_label = f"{device.name}({device.ip})" if device.name else device.ip
    
    if current_val >= thresh:
        if cache_key not in alert_cache or (time.time() - alert_cache[cache_key] > 3600):
            send_wechat_alert(f"设备 [{dev_label}] {metric_name} 使用率过高: {current_val}% (阈值: {thresh}%)")
            alert_cache[cache_key] = time.time()
    else:
        if cache_key in alert_cache:
            send_wechat_alert(f"设备 [{dev_label}] {metric_name} 使用率已恢复正常: {current_val}%", "info")
            del alert_cache[cache_key]

# ================= 真实 SNMP 采集模块 =================

def fetch_real_snmp_data(ip, community):
    cpu_cores = []
    mem_usage = 0.0
    disk_data = []

    # 1. 获取 CPU
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((ip, 161), timeout=3, retries=2),
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.25.3.3.1.2')),
        lexicographicMode=False
    ):
        if errorIndication or errorStatus: break
        for varBind in varBinds:
            try:
                cpu_cores.append(int(varBind[1]))
            except:
                pass

    cpu_usage = round(sum(cpu_cores) / len(cpu_cores), 1) if cpu_cores else 0.0

    # 2. 获取 内存 & 磁盘分区
    #
    # 内存计算策略（反映真实内存压力，排除 buff/cache）：
    #   step1: 遍历 hrStorageTable，同时记录下面三类行（单位均换算为 KB）
    #          - Physical Memory (hrStorageRam)         → ram_total_kb, ram_used_kb
    #          - Cached Memory   (descr 含 Cached)      → cached_kb
    #          - Memory Buffers  (descr 含 Buffers)     → buffers_kb
    #          - Available memory(descr 含 Available)   → available_kb（部分系统有此行）
    #   step2: 优先用 available_kb 计算；
    #          若无 available 行，则 available = ram_total - (ram_used - cached - buffers)
    #   最终：真实使用率 = (ram_total - available) / ram_total × 100%
    #
    ram_total_kb  = 0.0   # Physical Memory 总量
    ram_used_kb   = 0.0   # Physical Memory 已用（含 buff/cache）
    cached_kb     = 0.0   # Cached Memory
    buffers_kb    = 0.0   # Memory Buffers
    available_kb  = 0.0   # Available Memory（部分系统才有）

    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((ip, 161), timeout=3, retries=2),
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.25.2.3.1.2')),  # hrStorageType
        ObjectType(ObjectIdentity('1.3.6.1.2.1.25.2.3.1.3')),  # hrStorageDescr
        ObjectType(ObjectIdentity('1.3.6.1.2.1.25.2.3.1.4')),  # hrStorageAllocationUnits (字节/单元)
        ObjectType(ObjectIdentity('1.3.6.1.2.1.25.2.3.1.5')),  # hrStorageSize
        ObjectType(ObjectIdentity('1.3.6.1.2.1.25.2.3.1.6')),  # hrStorageUsed
        lexicographicMode=False
    ):
        if errorIndication or errorStatus: break

        if len(varBinds) == 5:
            s_type  = varBinds[0][1].prettyPrint()
            s_descr = varBinds[1][1].prettyPrint()

            try:
                s_unit = int(varBinds[2][1])          # 每单元字节数
                s_size = float(varBinds[3][1])         # 单元数
                s_used = float(varBinds[4][1])         # 已用单元数
            except (ValueError, TypeError):
                continue

            if s_size <= 0:
                continue

            # 换算为 KB（统一单位，避免不同系统 unit 不同导致误差）
            unit_kb   = s_unit / 1024.0
            size_kb   = s_size * unit_kb
            used_kb   = s_used * unit_kb

            # —— 物理内存行 ——
            if '25.2.1.2' in s_type or 'hrStorageRam' in s_type:
                ram_total_kb = size_kb
                ram_used_kb  = used_kb

            # —— Cached Memory 行（Linux snmpd 会额外报告）——
            elif 'Cached' in s_descr and '25.2.1.2' not in s_type:
                cached_kb = used_kb

            # —— Memory Buffers 行 ——
            elif 'Buffers' in s_descr and '25.2.1.2' not in s_type:
                buffers_kb = used_kb

            # —— Available Memory 行（部分发行版 snmpd 有此行）——
            elif 'Available' in s_descr and '25.2.1.2' not in s_type:
                available_kb = size_kb   # "size" 字段存放的是可用量

            # —— 固定磁盘分区 ——
            elif '25.2.1.4' in s_type or 'hrStorageFixedDisk' in s_type:
                ignore_paths = ('/run', '/sys', '/dev', '/proc', '/boot', '/tmp', 'tmpfs', 'devtmpfs')
                if s_descr.startswith(ignore_paths): continue
                if "Virtual Memory" in s_descr or "Physical Memory" in s_descr: continue
                # 排除 Docker 容器挂载和 Kubernetes kubelet 卷
                if '/containers/' in s_descr or '/kubelet/' in s_descr: continue
                if len(s_descr) >= 2 and s_descr[1] == ':':
                    s_descr = s_descr[:2]
                disk_usage = round((s_used / s_size) * 100, 1)
                disk_data.append({'name': s_descr, 'usage': disk_usage})

    # —— 计算真实内存使用率 ——
    if ram_total_kb > 0:
        if available_kb > 0:
            # 优先用 Available Memory 行（最准确）
            real_used_kb = ram_total_kb - available_kb
        else:
            # 没有 Available 行：从 Physical Memory 的 used 中减去 cached + buffers
            real_used_kb = ram_used_kb - cached_kb - buffers_kb

        real_used_kb = max(0.0, real_used_kb)   # 防止出现负数
        mem_usage = round(real_used_kb / ram_total_kb * 100, 1)

    if not cpu_cores and mem_usage == 0.0 and not disk_data:
        raise Exception("SNMP 获取为空，可能网络不通或未启用 HOST-RESOURCES-MIB")

    return cpu_usage, mem_usage, disk_data


# ================= 轮询调度逻辑（网络与数据库解耦，防止连接池耗尽崩溃） =================
def poll_device_task(dev_id, ip, name, community, cpu_t, mem_t, disk_t):
    """先发网络请求（不锁数据库），获取完毕后再打开数据库瞬间写入"""
    # 1. 纯网络请求（耗时操作，不占用数据库连接）
    try:
        cpu_usage, mem_usage, disk_data = fetch_real_snmp_data(ip, community)
        success = True
        error_msg = ""
    except Exception as e:
        success = False
        error_msg = str(e)
        cpu_usage, mem_usage, disk_data = 0.0, 0.0, []

    # 2. 网络获取完毕，打开数据库瞬间写入并提交
    with app.app_context():
        device = db.session.get(Device, dev_id)
        if not device: return

        if success:
            if device.status in ['offline', 'unknown']:
                dev_label = f"{name}({ip})" if name else ip
                send_wechat_alert(f"设备 [{dev_label}] 已恢复通信，重新上线！", "info")
            device.status = 'online'
            device.fail_count = 0

            g_cpu, g_mem, g_disk = get_config('global_cpu'), get_config('global_mem'), get_config('global_disk')
            check_and_alert(device, "CPU", cpu_usage, g_cpu, cpu_t)
            check_and_alert(device, "内存", mem_usage, g_mem, mem_t)
            for d in disk_data:
                check_and_alert(device, f"硬盘({d['name']})", d['usage'], g_disk, disk_t)

            hist = History(device_id=device.id, cpu_usage=cpu_usage, mem_usage=mem_usage, disk_data=json.dumps(disk_data))
            db.session.add(hist)
        else:
            device.fail_count += 1
            max_fails = get_config('max_fails')
            if device.fail_count >= max_fails and device.status in ['online', 'unknown']:
                device.status = 'offline'
                dev_label = f"{name}({ip})" if name else ip
                send_wechat_alert(f"设备 [{dev_label}] 查询失败 {max_fails} 次，离线！\n> {error_msg}", "warning")

        db.session.commit()

def poll_all_devices():
    # 先快速取出设备信息，释放数据库连接，再交给线程池执行网络请求
    with app.app_context():
        devices = Device.query.all()
        tasks = [(d.id, d.ip, d.name, d.community, d.cpu_threshold, d.mem_threshold, d.disk_threshold) for d in devices]

    with ThreadPoolExecutor(max_workers=20) as executor:
        for task in tasks:
            executor.submit(poll_device_task, *task)

def clean_old_history():
    with app.app_context():
        days = get_config('retention_days')
        cutoff = datetime.now() - timedelta(days=days)
        History.query.filter(History.timestamp < cutoff).delete()
        db.session.commit()

scheduler = BackgroundScheduler()

def start_scheduler():
    interval = get_config('interval')
    scheduler.add_job(poll_all_devices, 'interval', seconds=interval, id='poll_job', replace_existing=True)
    scheduler.add_job(clean_old_history, 'cron', hour=3)
    scheduler.start()

def update_scheduler_interval(new_interval):
    scheduler.reschedule_job('poll_job', trigger='interval', seconds=new_interval)

# ================= Web 路由 =================
@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    per_page = get_config('per_page')

    # 搜索参数（模糊匹配名称或IP）
    q = request.args.get('q', '', type=str).strip()

    # 排序参数
    sort_by  = request.args.get('sort', 'id')        # 默认按 id 排序
    sort_dir = request.args.get('dir',  'asc')       # 默认升序
    reverse  = (sort_dir == 'desc')

    # 基础查询（带搜索过滤）
    base_query = Device.query
    if q:
        base_query = base_query.filter(
            db.or_(
                Device.name.ilike(f'%{q}%'),
                Device.ip.ilike(f'%{q}%')
            )
        )

    # 允许排序的字段白名单
    SORT_FIELDS = {
        'name':    Device.name,
        'ip':      Device.ip,
        'os_type': Device.os_type,
        'status':  Device.status,
        'id':      Device.id,
    }

    sort_col = SORT_FIELDS.get(sort_by, Device.id)
    order_expr = sort_col.desc() if reverse else sort_col.asc()

    # CPU / 内存排序需要联合 History 表，单独处理
    if sort_by in ('cpu_usage', 'mem_usage'):
        # 先拉所有设备，再用最新 History 数据排序（数据量不大，内存排序可接受）
        all_devices = base_query.all()
        latest_map = {}
        for dev in all_devices:
            hist = History.query.filter_by(device_id=dev.id).order_by(History.id.desc()).first()
            latest_map[dev.id] = hist

        def sort_key(dev):
            h = latest_map.get(dev.id)
            if h is None:
                return -1.0
            return getattr(h, sort_by) or 0.0

        all_devices.sort(key=sort_key, reverse=reverse)

        # 手动分页
        total = len(all_devices)
        start = (page - 1) * per_page
        end   = start + per_page
        page_items = all_devices[start:end]

        # 构造与 Pagination 对象相同接口的简单命名空间
        from types import SimpleNamespace
        import math
        pages_count = max(1, math.ceil(total / per_page))
        devices = SimpleNamespace(
            items     = page_items,
            page      = page,
            pages     = pages_count,
            has_prev  = page > 1,
            has_next  = page < pages_count,
            prev_num  = page - 1,
            next_num  = page + 1,
        )
        latest_data = latest_map
    else:
        devices = base_query.order_by(order_expr).paginate(page=page, per_page=per_page, error_out=False)
        latest_data = {}
        for dev in devices.items:
            hist = History.query.filter_by(device_id=dev.id).order_by(History.id.desc()).first()
            latest_data[dev.id] = hist

    # ======= 统计设备状态数量 =======
    stats = {
        'total':   Device.query.count(),
        'online':  Device.query.filter_by(status='online').count(),
        'offline': Device.query.filter_by(status='offline').count(),
        'unknown': Device.query.filter_by(status='unknown').count()
    }

    return render_template('index.html', devices=devices, latest_data=latest_data,
                           stats=stats, sort_by=sort_by, sort_dir=sort_dir, q=q)

@app.route('/device/add', methods=['POST'])
def add_device():
    name = request.form.get('name', '').strip()
    ip = request.form.get('ip').strip()
    community = request.form.get('community', 'hxu').strip()
    os_type = request.form.get('os_type', 'linux')
    if not ip:
        flash('IP 地址不能为空', 'danger')
    elif Device.query.filter_by(ip=ip).first():
        flash(f'添加失败：IP [{ip}] 已存在，不能重复添加！', 'danger')
    else:
        db.session.add(Device(name=name, ip=ip, community=community, os_type=os_type))
        db.session.commit()
        flash(f'设备 [{name or ip}] 添加成功！', 'success')
    return redirect(url_for('index'))

@app.route('/device/edit/<int:device_id>', methods=['POST'])
def edit_device(device_id):
    device = db.get_or_404(Device, device_id)
    device.name = request.form.get('name', '').strip()
    
    # 修改IP时防止重复冲突
    new_ip = request.form.get('ip', '').strip()
    ip_changed = False
    if new_ip and new_ip != device.ip:
        if Device.query.filter_by(ip=new_ip).first():
            flash(f'修改失败：IP [{new_ip}] 已被其他设备使用！', 'danger')
            db.session.rollback()
            return redirect(url_for('index'))
        else:
            device.ip = new_ip
            ip_changed = True
    
    device.os_type = request.form.get('os_type', 'linux')
    device.community = request.form.get('community', 'hxu').strip()
    device.cpu_threshold = request.form.get('cpu_threshold', type=int, default=0)
    device.mem_threshold = request.form.get('mem_threshold', type=int, default=0)
    device.disk_threshold = request.form.get('disk_threshold', type=int, default=0)
    db.session.commit()
    flash(f'设备 [{device.name or device.ip}] 修改成功！', 'success')
    return redirect(url_for('index'))

@app.route('/device/delete/<int:device_id>', methods=['POST'])
def delete_device(device_id):
    device = db.get_or_404(Device, device_id)
    History.query.filter_by(device_id=device.id).delete()
    db.session.delete(device)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/config', methods=['GET', 'POST'])
def config_page():
    if request.method == 'POST':
        try:
            interval_changed = False
            for k in DEFAULT_CONFIG.keys():
                val = request.form.get(k)
                if val is not None:
                    c = Config.query.filter_by(key=k).first()
                    if k == 'interval' and c.value != val:
                        interval_changed = True
                    c.value = val
            db.session.commit()
            if interval_changed:
                update_scheduler_interval(int(request.form.get('interval')))
            flash('配置保存成功，已立即生效！', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'配置保存失败：{str(e)}', 'danger')
        return redirect(url_for('config_page'))
    
    configs = {c.key: c.value for c in Config.query.all()}
    return render_template('config.html', configs=configs)

@app.route('/history/<int:device_id>')
def history_page(device_id):
    device = db.get_or_404(Device, device_id)
    return render_template('history.html', device=device)

@app.route('/api/history/<int:device_id>')
def api_history(device_id):
    hists = History.query.filter_by(device_id=device_id).order_by(History.id.desc()).limit(100).all()
    hists.reverse()
    times = [h.timestamp.strftime('%H:%M:%S') for h in hists]
    cpu = [h.cpu_usage for h in hists]
    mem = [h.mem_usage for h in hists]
    return jsonify({"times": times, "cpu": cpu, "mem": mem})

if __name__ == '__main__':
    init_db()
    start_scheduler()
    app.run(host='0.0.0.0', port=888, threaded=True)
