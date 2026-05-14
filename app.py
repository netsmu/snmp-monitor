import os
import json
import time
import requests
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
from pysnmp.hlapi import *

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///monitor.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
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
    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((ip, 161), timeout=3, retries=2),
        ContextData(),
        ObjectType(ObjectIdentity('1.3.6.1.2.1.25.2.3.1.2')), 
        ObjectType(ObjectIdentity('1.3.6.1.2.1.25.2.3.1.3')), 
        ObjectType(ObjectIdentity('1.3.6.1.2.1.25.2.3.1.5')), 
        ObjectType(ObjectIdentity('1.3.6.1.2.1.25.2.3.1.6')), 
        lexicographicMode=False
    ):
        if errorIndication or errorStatus: break

        if len(varBinds) == 4:
            s_type = varBinds[0][1].prettyPrint()
            s_descr = varBinds[1][1].prettyPrint()
            
            try:
                s_size = float(varBinds[2][1])
                s_used = float(varBinds[3][1])
            except ValueError:
                continue

            if s_size > 0:
                usage = round((s_used / s_size) * 100, 1)

                if '25.2.1.2' in s_type or 'hrStorageRam' in s_type: 
                    mem_usage = usage
                
                elif '25.2.1.4' in s_type or 'hrStorageFixedDisk' in s_type: 
                    ignore_paths = ('/run', '/sys', '/dev', '/proc', 'tmpfs', 'devtmpfs')
                    if s_descr.startswith(ignore_paths): continue
                    if "Virtual Memory" in s_descr or "Physical Memory" in s_descr: continue
                    if len(s_descr) >= 2 and s_descr[1] == ':':
                        s_descr = s_descr[:2]
                    disk_data.append({'name': s_descr, 'usage': usage})

    if not cpu_cores and mem_usage == 0.0 and not disk_data:
        raise Exception("SNMP 获取为空，可能网络不通或未启用 HOST-RESOURCES-MIB")

    return cpu_usage, mem_usage, disk_data


# ================= 轮询调度逻辑 =================
def poll_device(device_id):
    with app.app_context():
        device = db.session.get(Device, device_id)
        if not device: return
        
        try:
            cpu_usage, mem_usage, disk_data = fetch_real_snmp_data(device.ip, device.community)
            
            if device.status == 'offline' or device.status == 'unknown':
                if device.status == 'offline':
                    dev_label = f"{device.name}({device.ip})" if device.name else device.ip
                    send_wechat_alert(f"设备 [{dev_label}] 已恢复通信，重新上线！", "info")
                device.status = 'online'
            
            device.fail_count = 0
            
            g_cpu, g_mem, g_disk = get_config('global_cpu'), get_config('global_mem'), get_config('global_disk')
            check_and_alert(device, "CPU", cpu_usage, g_cpu, device.cpu_threshold)
            check_and_alert(device, "内存", mem_usage, g_mem, device.mem_threshold)
            for d in disk_data:
                check_and_alert(device, f"硬盘({d['name']})", d['usage'], g_disk, device.disk_threshold)

            hist = History(device_id=device.id, cpu_usage=cpu_usage, mem_usage=mem_usage, disk_data=json.dumps(disk_data))
            db.session.add(hist)

        except Exception as e:
            device.fail_count += 1
            max_fails = get_config('max_fails')
            if device.fail_count >= max_fails and device.status in ['online', 'unknown']:
                device.status = 'offline'
                dev_label = f"{device.name}({device.ip})" if device.name else device.ip
                send_wechat_alert(f"设备 [{dev_label}] 查询失败 {max_fails} 次，离线！\n> {str(e)}", "warning")
        
        db.session.commit()

def poll_all_devices():
    with app.app_context():
        devices = Device.query.all()
        with ThreadPoolExecutor(max_workers=20) as executor:
            for dev in devices:
                executor.submit(poll_device, dev.id)

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

    # 排序参数
    sort_by  = request.args.get('sort', 'id')        # 默认按 id 排序
    sort_dir = request.args.get('dir',  'asc')       # 默认升序
    reverse  = (sort_dir == 'desc')

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
        all_devices = Device.query.all()
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
        devices = Device.query.order_by(order_expr).paginate(page=page, per_page=per_page, error_out=False)
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
                           stats=stats, sort_by=sort_by, sort_dir=sort_dir)

@app.route('/device/add', methods=['POST'])
def add_device():
    name = request.form.get('name', '').strip()
    ip = request.form.get('ip').strip()
    community = request.form.get('community', 'hxu').strip()
    os_type = request.form.get('os_type', 'linux')
    if ip and not Device.query.filter_by(ip=ip).first():
        db.session.add(Device(name=name, ip=ip, community=community, os_type=os_type))
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/device/edit/<int:device_id>', methods=['POST'])
def edit_device(device_id):
    device = db.get_or_404(Device, device_id)
    device.name = request.form.get('name', '').strip()
    
    # 修改IP时防止重复冲突
    new_ip = request.form.get('ip', '').strip()
    if new_ip and new_ip != device.ip:
        if not Device.query.filter_by(ip=new_ip).first():
            device.ip = new_ip
            
    device.os_type = request.form.get('os_type', 'linux')
    device.community = request.form.get('community', 'hxu').strip()
    device.cpu_threshold = request.form.get('cpu_threshold', type=int, default=0)
    device.mem_threshold = request.form.get('mem_threshold', type=int, default=0)
    device.disk_threshold = request.form.get('disk_threshold', type=int, default=0)
    db.session.commit()
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