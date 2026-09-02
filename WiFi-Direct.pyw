import tkinter as tk
import threading
import time
import ctypes
import sys
import socket
import struct
import os
import json
import re
from collections import deque
from ctypes import Structure, POINTER, c_ulong, c_ubyte, c_wchar, c_ushort, byref

# ============================================================================
#  1. 配置管理
# ============================================================================
CONFIG_FILE = "monitor_config.json"
DEFAULT_CONFIG = {
    "gateway_ip": "192.168.137.1",
    "target_ip": "",
    "bg_color": "#ffffff",
    "opacity": 0.95,
    "line_color_native": "#1565c0",
    "line_color_scapy": "#cc9966",
    "alert_enabled": True,
    "alert_silence_min": 10,
    "alert_duration_sec": 3,
    "mode": "native"
}

class ConfigManager:
    def __init__(self):
        self.data = self.load()

    def load(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    return {**DEFAULT_CONFIG, **json.load(f)}
            except:
                return DEFAULT_CONFIG.copy()
        return DEFAULT_CONFIG.copy()

    def save(self):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.data, f, indent=4)
        except: pass

cfg = ConfigManager()

# ============================================================================
#  2. 依赖检测 (Npcap & Windows API)
# ============================================================================
NPCAP_EXISTS = False
try:
    # 检测 System32 下是否有 wpcap.dll
    if os.path.exists(os.path.join(os.environ['WINDIR'], 'System32', 'wpcap.dll')):
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        from scapy.all import AsyncSniffer, conf
        NPCAP_EXISTS = True
except ImportError:
    NPCAP_EXISTS = False

# 定义 Windows API 网卡信息结构体
iphlpapi = ctypes.windll.iphlpapi

class MIB_IFROW(Structure):
    _fields_ = [
        ("wszName", c_wchar * 256), ("dwIndex", c_ulong), ("dwType", c_ulong),
        ("dwMtu", c_ulong), ("dwSpeed", c_ulong), ("dwPhysAddrLen", c_ulong),
        ("bPhysAddr", c_ubyte * 8), ("dwAdminStatus", c_ulong), ("dwOperStatus", c_ulong),
        ("dwLastChange", c_ulong), ("dwInOctets", c_ulong), ("dwInUcastPkts", c_ulong),
        ("dwInNUcastPkts", c_ulong), ("dwInDiscards", c_ulong), ("dwInErrors", c_ulong),
        ("dwInUnknownProtos", c_ulong), ("dwOutOctets", c_ulong), ("dwOutUcastPkts", c_ulong),
        ("dwOutNUcastPkts", c_ulong), ("dwOutDiscards", c_ulong), ("dwOutErrors", c_ulong),
        ("dwOutQLen", c_ulong), ("dwDescrLen", c_ulong), ("bDescr", c_ubyte * 256)
    ]

class MIB_IPADDRROW(Structure):
    _fields_ = [
        ("dwAddr", c_ulong), ("dwIndex", c_ulong), ("dwMask", c_ulong),
        ("dwBCastAddr", c_ulong), ("dwReasmSize", c_ulong),
        ("unused1", c_ushort), ("wType", c_ushort)
    ]

class MIB_IPADDRTABLE(Structure):
    _fields_ = [("dwNumEntries", c_ulong), ("table", MIB_IPADDRROW * 1)]

# ============================================================================
#  3. 监控策略
# ============================================================================

# 策略 A: Native (读取网卡计数器)
class NativeStrategy:
    def __init__(self):
        self.lock = threading.Lock()
        self.running = True
        self.if_index = None
        self.rx = 0
        self.tx = 0
        self.last_in = 0
        self.last_out = 0
        self.last_time = 0
        self.gateway = cfg.data["gateway_ip"]

    def find_index(self):
        try:
            size = c_ulong(0)
            iphlpapi.GetIpAddrTable(None, byref(size), 0)
            buf = ctypes.create_string_buffer(size.value)
            table = ctypes.cast(buf, POINTER(MIB_IPADDRTABLE))
            if iphlpapi.GetIpAddrTable(table, byref(size), 0) == 0:
                target = struct.unpack("I", socket.inet_aton(self.gateway))[0]
                for i in range(table.contents.dwNumEntries):
                    row = ctypes.cast(ctypes.addressof(table.contents.table), POINTER(MIB_IPADDRROW))[i]
                    if row.dwAddr == target:
                        return row.dwIndex
        except: pass
        return None

    def start(self):
        while self.running:
            try:
                if self.if_index is None:
                    self.if_index = self.find_index()
                    if not self.if_index:
                        with self.lock:
                            self.rx, self.tx = 0, 0
                        time.sleep(1)
                        continue

                row = MIB_IFROW()
                row.dwIndex = self.if_index
                # 这里的非0判断意味着接口读取失败（可能热点已关闭）
                if iphlpapi.GetIfEntry(byref(row)) != 0:
                    self.if_index = None
                    continue

                now = time.time()
                cin, cout = row.dwInOctets, row.dwOutOctets
                if self.last_time > 0:
                    dt = now - self.last_time
                    if dt > 0:
                        # 处理32位计数器溢出逻辑
                        din = cin - self.last_in if cin >= self.last_in else (cin + 0xFFFFFFFF - self.last_in)
                        dout = cout - self.last_out if cout >= self.last_out else (cout + 0xFFFFFFFF - self.last_out)
                        with self.lock:
                            self.rx = (dout * 8) / dt
                            self.tx = (din * 8) / dt

                self.last_in, self.last_out, self.last_time = cin, cout, now
                time.sleep(1)
            except:
                time.sleep(1)

    def get_data(self):
        with self.lock: return self.tx, self.rx, True

    def stop(self):
        self.running = False

# 策略 B: Scapy (监控特定连接IP)
class ScapyStrategy:
    def __init__(self):
        self.lock = threading.Lock()
        self.running = True
        self.rx_bytes = 0
        self.tx_bytes = 0
        self.sniffer = None
        self.gateway = cfg.data["gateway_ip"]
        self.target = cfg.data["target_ip"]

    def find_iface(self):
        if not NPCAP_EXISTS:
            return None
        try:
            # 先查现有，再尝试重载查找，确保热点重启后能重新发现
            for i in range(2):
                if i == 1: conf.ifaces.reload()
                for iface in conf.ifaces.values():
                    if iface.ip == self.gateway: return iface.name
        except: pass
        return None

    def pkt_callback(self, pkt):
        try:
            l = len(pkt)
            if pkt['IP'].src == self.target:
                with self.lock: self.tx_bytes += l
            else:
                with self.lock: self.rx_bytes += l
        except: pass

    def start(self):
        if not NPCAP_EXISTS or not self.target: return
        while self.running:
            iname = self.find_iface()
            if not iname:
                time.sleep(1)
                continue
            try:
                self.sniffer = AsyncSniffer(iface=iname, filter=f"host {self.target}", prn=self.pkt_callback, store=0)
                self.sniffer.start()
                while self.running and self.sniffer.running:
                    time.sleep(1)
                    # 实时检测网卡状态，防止关闭后卡死
                    if not self.find_iface():
                        self.sniffer.stop()
                        break
            except:
                time.sleep(2)
            finally:
                if self.sniffer:
                    try: self.sniffer.stop()
                    except: pass

    def get_data(self):
        with self.lock:
            r, t = self.rx_bytes, self.tx_bytes
            self.rx_bytes, self.tx_bytes = 0, 0
        return t * 8, r * 8, (self.sniffer and self.sniffer.running)

    def stop(self):
        self.running = False
        if self.sniffer:
            try: self.sniffer.stop()
            except: pass

# ============================================================================
#  4. 自定义组件
# ============================================================================
class ScrollableFrame(tk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        self.canvas = tk.Canvas(self, borderwidth=0, background="#ffffff")
        self.scrollbar = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, background="#ffffff")

        self.scrollable_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")

# ============================================================================
#  5. 设置窗口
# ============================================================================
class SettingsWindow:
    def __init__(self, parent, app):
        self.window = tk.Toplevel(parent)
        self.window.title("Settings")
        
        # 应用 DPI 缩放
        self.dpi_scale = app.dpi_scale
        self.app = app
        
        # 尺寸设定
        w, h = self.s(360), self.s(420)
        x = parent.winfo_x() + self.s(20)
        y = parent.winfo_y() + self.s(20)
        
        self.window.geometry(f"{w}x{h}+{x}+{y}")
        self.window.attributes('-topmost', True)
        self.window.configure(bg="white")

        # 滚动容器
        scroll_container = ScrollableFrame(self.window)
        scroll_container.pack(fill="both", expand=True, padx=self.s(5), pady=self.s(5))
        content = scroll_container.scrollable_frame

        # 1. 网络配置
        self.add_section_label(content, "网络配置")
        self.add_label(content, "网络适配器 IP:")
        self.entry_gw = self.add_entry(content, cfg.data["gateway_ip"])
        
        self.add_label(content, "特定连接 IP:")
        self.entry_ip = self.add_entry(content, cfg.data["target_ip"])
        if not NPCAP_EXISTS:
            self.entry_ip.config(state="disabled")

        # 2. 外观配置
        self.add_section_label(content, "外观颜色 (Hex #RRGGBB)")
        self.temp_colors = {
            "bg": cfg.data["bg_color"],
            "native": cfg.data["line_color_native"],
            "scapy": cfg.data["line_color_scapy"]
        }
        
        self.create_hex_input(content, "背景颜色", "bg", True)
        self.create_hex_input(content, "总流量线色", "native", True)
        self.create_hex_input(content, "特定连接IP线色", "scapy", NPCAP_EXISTS)

        self.add_label(content, "透明度 (0.1 - 1.0):")
        sl = self.s(250)
        self.scale_alpha = tk.Scale(content, from_=0.1, to=1.0, resolution=0.05, orient=tk.HORIZONTAL, bg="white", length=sl)
        self.scale_alpha.set(cfg.data["opacity"])
        self.scale_alpha.pack(padx=self.s(15), anchor='w')

        # 3. 预警配置
        self.add_section_label(content, "突发流量预警 (仅特定连接IP模式有效)")
        self.var_alert = tk.BooleanVar(value=cfg.data["alert_enabled"])
        self.chk_alert = tk.Checkbutton(content, text="开启预警", variable=self.var_alert, bg="white")
        self.chk_alert.pack(anchor='w', padx=self.s(15))
        
        frame_alert = tk.Frame(content, bg="white")
        frame_alert.pack(fill='x', padx=self.s(15), pady=self.s(5))
        tk.Label(frame_alert, text="静默(分):", bg="white").pack(side='left')
        self.entry_silence = tk.Entry(frame_alert, width=5)
        self.entry_silence.insert(0, str(cfg.data["alert_silence_min"]))
        self.entry_silence.pack(side='left', padx=self.s(5))
        
        tk.Label(frame_alert, text="持续(秒):", bg="white").pack(side='left', padx=(self.s(10),0))
        self.entry_duration = tk.Entry(frame_alert, width=5)
        self.entry_duration.insert(0, str(cfg.data["alert_duration_sec"]))
        self.entry_duration.pack(side='left', padx=self.s(5))

        if not NPCAP_EXISTS:
            self.chk_alert.config(state="disabled")
            self.entry_silence.config(state="disabled")
            self.entry_duration.config(state="disabled")

        # 底部按钮
        btn_frame = tk.Frame(self.window, bg="#f0f0f0", height=self.s(40))
        btn_frame.pack(fill='x', side='bottom')
        tk.Button(btn_frame, text="保存", width=10, bg="#e0e0e0", command=self.save_config).pack(side='right', padx=self.s(20), pady=self.s(8))
        tk.Button(btn_frame, text="取消", width=10, bg="white", command=self.window.destroy).pack(side='right', pady=self.s(8))

    # 辅助方法：自动计算缩放后的像素值
    def s(self, val):
        return int(val * self.dpi_scale)

    def add_section_label(self, parent, text):
        tk.Label(parent, text=text, font=("Segoe UI", 10, "bold"), bg="white").pack(anchor='w', padx=self.s(10), pady=(self.s(15), self.s(5)))

    def add_label(self, parent, text):
        tk.Label(parent, text=text, bg="white").pack(anchor='w', padx=self.s(20), pady=(self.s(2),0))

    def add_entry(self, parent, value):
        e = tk.Entry(parent, width=30)
        e.insert(0, value)
        e.pack(anchor='w', padx=self.s(20), pady=(0, self.s(5)))
        return e

    def create_hex_input(self, parent, label_text, key, enabled):
        frame = tk.Frame(parent, bg="white")
        frame.pack(fill='x', padx=self.s(20), pady=self.s(2))
        
        tk.Label(frame, text=label_text + ":", bg="white", width=12, anchor='w').pack(side='left')
        entry = tk.Entry(frame, width=10)
        entry.insert(0, self.temp_colors[key])
        entry.pack(side='left', padx=self.s(5))
        
        preview = tk.Label(frame, width=4, bg=self.temp_colors[key], relief="solid", bd=1)
        preview.pack(side='left', padx=self.s(5))
        
        if not enabled:
            entry.config(state="disabled")

        # 绑定输入事件用于预览颜色
        entry.bind('<KeyRelease>', lambda e: self.on_hex_change(entry, preview, key))
        setattr(self, f"entry_hex_{key}", entry)

    def on_hex_change(self, entry, preview, key):
        val = entry.get().strip()
        if re.match(r'^#(?:[0-9a-fA-F]{3}){1,2}$', val):
            try:
                preview.config(bg=val)
                self.temp_colors[key] = val
            except: pass

    def save_config(self):
        cfg.data["gateway_ip"] = self.entry_gw.get().strip()
        cfg.data["target_ip"] = self.entry_ip.get().strip()
        cfg.data["bg_color"] = self.entry_hex_bg.get().strip()
        cfg.data["line_color_native"] = self.entry_hex_native.get().strip()
        cfg.data["line_color_scapy"] = self.entry_hex_scapy.get().strip()
        cfg.data["opacity"] = self.scale_alpha.get()
        cfg.data["alert_enabled"] = self.var_alert.get()
        try:
            cfg.data["alert_silence_min"] = int(self.entry_silence.get())
            cfg.data["alert_duration_sec"] = int(self.entry_duration.get())
        except: pass
        
        cfg.save()
        self.app.apply_settings_update()
        self.window.destroy()

# ============================================================================
#  6. 主程序 UI
# ============================================================================
class App:
    def __init__(self, root):
        self.root = root
        
        # 获取系统DPI缩放 (标准96DPI=1.0)
        try:
            self.dpi_scale = self.root.winfo_fpixels('1i') / 96.0
        except: 
            self.dpi_scale = 1.0
            
        self.history_len = 50
        self.history = deque([0]*self.history_len, maxlen=self.history_len)
        
        self.last_upload_time = time.time()
        self.alert_end_time = 0
        
        self.current_mode = tk.StringVar()
        
        # 模式选择逻辑
        saved_mode = cfg.data["mode"]
        if saved_mode == "scapy" and NPCAP_EXISTS and cfg.data["target_ip"]:
            self.current_mode.set("scapy")
            self.monitor = ScapyStrategy()
        else:
            self.current_mode.set("native")
            self.monitor = NativeStrategy()

        self.setup_ui()
        self.update_visuals_state()
        self.create_menu()
        
        self.thread = threading.Thread(target=self.monitor.start, daemon=True)
        self.thread.start()
        self.update_loop()

    def s(self, val):
        return int(val * self.dpi_scale)

    def setup_ui(self):
        self.root.title("NetMon")
        w, h = self.s(260), self.s(90)
        self.root.geometry(f"{w}x{h}")
        
        self.root.overrideredirect(True)
        self.root.attributes('-topmost', True)

        self.frame_text = tk.Frame(self.root, width=self.s(130))
        self.frame_text.pack(side=tk.RIGHT, fill=tk.Y)
        self.frame_text.pack_propagate(False)

        self.frame_chart = tk.Frame(self.root)
        self.frame_chart.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.canvas = tk.Canvas(self.frame_chart, highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True, padx=(self.s(5), 0), pady=self.s(5))

        self.ctn = tk.Frame(self.frame_text)
        self.ctn.pack(fill=tk.BOTH, expand=True, padx=self.s(5), pady=self.s(8))

        self.lbl_status = tk.Label(self.ctn, text="Init", font=("Segoe UI", 9), anchor='w')
        self.lbl_status.pack(fill=tk.X, pady=(0, self.s(2)))

        self.lbl_down = tk.Label(self.ctn, text="↓ 0 Kbps", font=("Segoe UI", 11, "bold"), anchor='w')
        self.lbl_down.pack(fill=tk.X)
        self.lbl_up = tk.Label(self.ctn, text="↑ 0 Kbps", font=("Segoe UI", 10, "bold"), anchor='w')
        self.lbl_up.pack(fill=tk.X)

        self.bind_move(self.root)

    def bind_move(self, widget):
        widget.bind('<Button-1>', self.start_move)
        widget.bind('<B1-Motion>', self.do_move)
        for child in widget.winfo_children(): self.bind_move(child)

    def get_current_line_color(self):
        return cfg.data["line_color_scapy"] if self.current_mode.get() == "scapy" else cfg.data["line_color_native"]

    def update_visuals_state(self):
        bg = cfg.data["bg_color"]
        self.root.attributes('-alpha', cfg.data["opacity"])
        self.root.configure(bg=bg)
        for w in [self.frame_text, self.frame_chart, self.ctn, self.canvas, self.lbl_status, self.lbl_down, self.lbl_up]:
            w.configure(bg=bg)
        
        if self.current_mode.get() == "scapy":
            txt = f"IP: {cfg.data['target_ip']}"
        else:
            txt = "Total Traffic Mode"
        self.lbl_status.config(text=txt, fg="#000000")

    def create_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        mode_menu = tk.Menu(self.context_menu, tearoff=0)
        
        self.context_menu.add_cascade(label="模式 (Mode)", menu=mode_menu)
        mode_menu.add_radiobutton(label="总流量 (Total)", variable=self.current_mode, value="native", command=self.switch_mode)
        
        can_scapy = "disabled"
        label_scapy = "特定连接IP: "
        if NPCAP_EXISTS:
            if cfg.data["target_ip"]:
                can_scapy = "normal"
                label_scapy += cfg.data["target_ip"]
            else:
                label_scapy += "(未设置)"
        else:
            label_scapy += "(未安装Npcap)"
        mode_menu.add_radiobutton(label=label_scapy, variable=self.current_mode, value="scapy", command=self.switch_mode, state=can_scapy)
        
        self.context_menu.add_separator()
        self.context_menu.add_command(label="设置 (Settings)...", command=self.open_settings)
        self.context_menu.add_command(label="关于 (About)", command=self.show_about)
        self.context_menu.add_command(label="退出 (Exit)", command=self.quit_app)
        
        def show(e): self.context_menu.post(e.x_root, e.y_root)
        def bind_r(w):
            w.bind("<Button-3>", show)
            for c in w.winfo_children(): bind_r(c)
        bind_r(self.root)

    def show_about(self):
        win = tk.Toplevel(self.root)
        win.title("关于")
        
        w, h = self.s(350), self.s(300)
        win.geometry(f"{w}x{h}")
        win.attributes('-topmost', True)
        win.configure(bg="white")
        
        x = self.root.winfo_x() + self.s(20)
        y = self.root.winfo_y() + self.s(20)
        win.geometry(f"+{x}+{y}")

        tk.Label(win, text="网络适配器流量监控程序", font=("Segoe UI", 16, "bold"), bg="white", fg="#1565c0").pack(pady=(self.s(20), self.s(5)))
        tk.Label(win, text="Network Adapter Traffic Monitor", font=("Segoe UI", 14, "bold"), bg="white", fg="#1565c0").pack(pady=(0, self.s(5)))
        tk.Label(win, text="Version 1.0.1", font=("Segoe UI", 10), bg="white").pack()
        
        info = "双模式监控 / 突发流量警告\n" \
               "作者 (Author): Gemini 3.0 Pro Preview, Darkgreen World\n" \
               "反馈 (Feedback): darkgreen_world@outlook.com"
        tk.Label(win, text=info, bg="white", fg="#666", justify="center", font=("Segoe UI", 9)).pack(pady=self.s(20), padx=self.s(15))
        
        tk.Button(win, text="关闭", command=win.destroy, bg="#f0f0f0", width=10).pack(side="bottom", pady=self.s(15))
    
    def open_settings(self):
        SettingsWindow(self.root, self)

    def apply_settings_update(self):
        self.update_visuals_state()
        self.create_menu()
        self.switch_mode()

    def switch_mode(self):
        target = self.current_mode.get()
        if self.monitor: self.monitor.stop()
        self.history = deque([0]*self.history_len, maxlen=self.history_len)
        
        if target == "scapy" and NPCAP_EXISTS and cfg.data["target_ip"]:
            self.monitor = ScapyStrategy()
        else:
            self.current_mode.set("native")
            self.monitor = NativeStrategy()
            
        self.update_visuals_state()
        self.thread = threading.Thread(target=self.monitor.start, daemon=True)
        self.thread.start()

    def draw_chart(self):
        try:
            self.canvas.delete("all")
            w = self.canvas.winfo_width()
            h = self.canvas.winfo_height()
            if w < 5: return
            max_val = max(self.history)
            if max_val < 50: max_val = 50
            max_val *= 1.1
            points = [0, h]
            step = w / (self.history_len - 1)
            for i, val in enumerate(self.history):
                x = i * step
                y = h - (val / max_val * h)
                points.extend([x, y])
            points.extend([w, h])
            
            line_c = self.get_current_line_color()
            self.canvas.create_polygon(points, fill="#f5f5f5", outline="")
            if len(points) > 4:
                self.canvas.create_line(points[2:-2], fill=line_c, width=1.5, smooth=True)
        except: pass

    def format_speed(self, bps):
        if bps > 1024*1024: return f"{bps/1024/1024:.1f} Mbps"
        return f"{int(bps/1024)} Kbps"

    def update_loop(self):
        tx, rx, active = self.monitor.get_data()
        total = (tx + rx) / 1024.0
        self.history.append(total)
        
        now = time.time()
        is_alerting = False
        
        # 突发流量预警逻辑
        if self.current_mode.get() == "scapy" and cfg.data["alert_enabled"]:
            if tx > 2048: # 上传 > 2Kbps
                silence = now - self.last_upload_time
                if silence > (cfg.data["alert_silence_min"] * 60):
                    self.alert_end_time = now + cfg.data["alert_duration_sec"]
                self.last_upload_time = now
            if now < self.alert_end_time:
                is_alerting = True

        if not active and max(self.history) < 1:
             self.lbl_down.config(text="Wait...", fg="#bdbdbd", bg=cfg.data["bg_color"])
             self.lbl_up.config(text="", fg="#bdbdbd", bg=cfg.data["bg_color"])
        else:
            txt_d = f"↓ {self.format_speed(rx)}"
            txt_u = f"↑ {self.format_speed(tx)}"
            
            if is_alerting:
                # 警报模式
                self.lbl_down.config(text=txt_d, fg="#ff0000", bg="#ffcccc")
                self.lbl_up.config(text=txt_u, fg="#ff0000", bg="#ffcccc")
            else:
                # 正常模式
                bg = cfg.data["bg_color"]
                self.lbl_down.config(text=txt_d, fg='#000000', bg=bg)
                self.lbl_up.config(text=txt_u, fg='#000000', bg=bg)

        self.draw_chart()
        self.root.after(1000, self.update_loop)

    def start_move(self, e): self.x = e.x; self.y = e.y
    def do_move(self, e):
        self.root.geometry(f"+{self.root.winfo_x()+(e.x-self.x)}+{self.root.winfo_y()+(e.y-self.y)}")
    
    def quit_app(self):
        self.monitor.stop()
        cfg.data["mode"] = self.current_mode.get()
        cfg.save()
        self.root.destroy()
        sys.exit(0)

# ============================================================================
#  7. 启动
# ============================================================================
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

if __name__ == "__main__":
    if is_admin():
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except:
            try: ctypes.windll.user32.SetProcessDPIAware()
            except: pass
        root = tk.Tk()
        app = App(root)
        root.mainloop()
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
