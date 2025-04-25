#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Android调试助手主程序
作者: Assistant
版本: 1.0.0
"""

import sys
import os
import subprocess
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from tkinter.scrolledtext import ScrolledText
from threading import Event, Thread
import adbutils
from datetime import datetime
from loguru import logger
import hashlib
import binascii
import zipfile

# 配置日志记录
logger.add("debug.log", rotation="500 MB")

# apkutils2导入处理
APKUTILS_AVAILABLE = False
try:
    from apkutils2 import APK
    APKUTILS_AVAILABLE = True
    logger.info("成功导入apkutils2库")
except ImportError:
    APKUTILS_AVAILABLE = False
    logger.error("未安装apkutils2库，APK分析功能将不可用")
    logger.error("请使用pip install apkutils2安装该库")

class ADBCommand:
    """ADB命令封装类"""
    
    @staticmethod
    def execute_command(command):
        """执行ADB命令
        Args:
            command: ADB命令字符串
        Returns:
            执行结果输出
        """
        try:
            result = subprocess.check_output(f"adb {command}", shell=True)
            return result.decode('utf-8')
        except subprocess.CalledProcessError as e:
            return f"错误: {str(e)}"
    
    @staticmethod
    def get_devices():
        """获取已连接设备列表"""
        return ADBCommand.execute_command("devices -l")  # -l 参数显示更详细的设备信息
    
    @staticmethod
    def get_device_info():
        """获取设备信息"""
        return ADBCommand.execute_command("shell getprop")
    
    @staticmethod
    def connect_wireless(ip, port="5555"):
        """无线连接设备
        Args:
            ip: 设备IP地址
            port: 端口号，默认5555
        """
        return ADBCommand.execute_command(f"connect {ip}:{port}")
    
    @staticmethod
    def disconnect_wireless(ip=None):
        """断开无线连接
        Args:
            ip: 设备IP地址，为None时断开所有连接
        """
        if ip:
            return ADBCommand.execute_command(f"disconnect {ip}")
        return ADBCommand.execute_command("disconnect")
    
    @staticmethod
    def get_current_activity():
        """获取当前活动界面"""
        return ADBCommand.execute_command("shell dumpsys activity top")
    
    @staticmethod
    def get_focused_window():
        """获取当前焦点窗口"""
        return ADBCommand.execute_command("shell dumpsys window | grep -i focus")
    
    @staticmethod
    def list_packages(option=None):
        """列出应用包
        Args:
            option: 可选参数，如 -f (带路径)，-s (系统应用)，-3 (第三方应用)
        """
        cmd = "shell pm list packages"
        if option:
            cmd += f" {option}"
        return ADBCommand.execute_command(cmd)
    
    @staticmethod
    def get_app_info(package_name):
        """获取应用详细信息
        Args:
            package_name: 应用包名
        """
        return ADBCommand.execute_command(f"shell dumpsys package {package_name}")
    
    @staticmethod
    def get_cpu_info():
        """获取CPU信息"""
        return ADBCommand.execute_command("shell cat /proc/cpuinfo")
    
    @staticmethod
    def get_memory_info():
        """获取内存信息"""
        return ADBCommand.execute_command("shell cat /proc/meminfo")
    
    @staticmethod
    def get_battery_info():
        """获取电池信息"""
        return ADBCommand.execute_command("shell dumpsys battery")
    
    @staticmethod
    def get_display_info():
        """获取显示信息"""
        return ADBCommand.execute_command("shell dumpsys display")
    
    @staticmethod
    def get_network_stats():
        """获取网络统计信息"""
        return ADBCommand.execute_command("shell dumpsys netstats")
    
    @staticmethod
    def get_wifi_info():
        """获取WiFi信息"""
        return ADBCommand.execute_command("shell dumpsys wifi")
    
    @staticmethod
    def get_ip_address():
        """获取IP地址"""
        return ADBCommand.execute_command("shell ip addr show wlan0")
    
    @staticmethod
    def get_process_stats():
        """获取进程统计信息"""
        return ADBCommand.execute_command("shell dumpsys procstats")
    
    @staticmethod
    def get_gpu_info():
        """获取GPU信息"""
        return ADBCommand.execute_command("shell dumpsys gfxinfo")
    
    @staticmethod
    def get_logcat(filter=None):
        """获取日志
        Args:
            filter: 日志过滤器
        """
        cmd = "logcat -d"
        if filter:
            cmd += f" {filter}"
        return ADBCommand.execute_command(cmd)
    
    @staticmethod
    def clear_logcat():
        """清除日志"""
        return ADBCommand.execute_command("logcat -c")
    
    @staticmethod
    def get_anr_traces():
        """获取ANR信息"""
        return ADBCommand.execute_command("shell cat /data/anr/traces.txt")
    
    @staticmethod
    def input_text(text):
        """输入文本
        Args:
            text: 要输入的文本
        """
        return ADBCommand.execute_command(f"shell input text '{text}'")
    
    @staticmethod
    def input_keyevent(keycode):
        """输入按键事件
        Args:
            keycode: 按键代码
        """
        return ADBCommand.execute_command(f"shell input keyevent {keycode}")
    
    @staticmethod
    def input_tap(x, y):
        """模拟点击
        Args:
            x: x坐标
            y: y坐标
        """
        return ADBCommand.execute_command(f"shell input tap {x} {y}")
    
    @staticmethod
    def get_system_props():
        """获取系统属性"""
        return ADBCommand.execute_command("shell getprop")
    
    @staticmethod
    def set_system_prop(prop, value):
        """设置系统属性
        Args:
            prop: 属性名
            value: 属性值
        """
        return ADBCommand.execute_command(f"shell setprop {prop} {value}")
    
    @staticmethod
    def pull_file(remote_path, local_path):
        """从设备拉取文件
        Args:
            remote_path: 设备上的文件路径
            local_path: 本地保存路径
        """
        try:
            # 确保路径使用正斜杠
            remote_path = remote_path.replace('\\', '/')
            local_path = local_path.replace('\\', '/')
            
            # 检查文件是否存在
            result = ADBCommand.execute_command(f"shell ls {remote_path}")
            if "No such file" in result:
                return f"错误: 文件不存在 - {remote_path}"
                
            # 执行下载
            return ADBCommand.execute_command(f"pull {remote_path} {local_path}")
        except Exception as e:
            return f"错误: {str(e)}"
    
    @staticmethod
    def push_file(local_path, remote_path):
        """推送文件到设备
        Args:
            local_path: 本地文件路径
            remote_path: 设备上的保存路径
        """
        return ADBCommand.execute_command(f"push {local_path} {remote_path}")
    
    @staticmethod
    def list_dir(path):
        """列出目录内容
        Args:
            path: 目录路径
        """
        return ADBCommand.execute_command(f"shell ls -l {path}")
    
    @staticmethod
    def take_screenshot(filename):
        """截图
        Args:
            filename: 保存的文件名
        """
        return ADBCommand.execute_command(f"shell screencap -p /sdcard/{filename}")
    
    @staticmethod
    def start_screenrecord(filename, time_limit=180):
        """开始录屏
        Args:
            filename: 保存的文件名
            time_limit: 录制时长限制（秒）
        """
        return ADBCommand.execute_command(f"shell screenrecord --time-limit {time_limit} /sdcard/{filename}")
    
    @staticmethod
    def reboot_device(mode=None):
        """重启设备
        Args:
            mode: 重启模式，如 bootloader, recovery
        """
        cmd = "reboot"
        if mode:
            cmd += f" {mode}"
        return ADBCommand.execute_command(cmd)
    
    @staticmethod
    def get_imei():
        """获取IMEI号"""
        return ADBCommand.execute_command("shell service call iphonesubinfo 1")
    
    @staticmethod
    def get_android_id():
        """获取Android ID"""
        return ADBCommand.execute_command("shell settings get secure android_id")
    
    @staticmethod
    def get_android_version():
        """获取Android版本"""
        try:
            result = ADBCommand.execute_command("shell getprop ro.build.version.release")
            return result.strip()
        except Exception:
            return "未知"
    
    @staticmethod
    def get_abi():
        """获取系统架构"""
        try:
            result = ADBCommand.execute_command("shell getprop ro.product.cpu.abi")
            return result.strip()
        except Exception:
            return "未知"
    
    @staticmethod
    def get_cpu_usage():
        """获取CPU使用率"""
        try:
            # 使用dumpsys cpuinfo获取CPU信息
            result = ADBCommand.execute_command("shell dumpsys cpuinfo | findstr TOTAL")
            if result:
                # 解析CPU使用率
                total = result.strip().split()[0]
                return total.replace("%", "")
            return "0.0"
        except Exception as e:
            logger.error(f"获取CPU使用率失败: {str(e)}")
            return "0.0"
            
    @staticmethod
    def get_memory_usage():
        """获取内存使用情况"""
        try:
            # 使用dumpsys meminfo获取内存信息
            result = ADBCommand.execute_command("shell dumpsys meminfo | findstr Used")
            if result:
                # 解析内存使用量（MB）
                for line in result.split('\n'):
                    if "Used RAM" in line:
                        # 处理类似 "690,425K" 格式的数值
                        used = line.split(':')[1].strip().split()[0]
                        used = used.replace(',', '').replace('K', '')  # 移除逗号和K后缀
                        return str(int(used) // 1024)  # 转换为MB
            return "0"
        except Exception as e:
            logger.error(f"获取内存使用情况失败: {str(e)}")
            return "0"
            
    @staticmethod
    def get_battery_level():
        """获取电池电量"""
        try:
            result = ADBCommand.execute_command("shell dumpsys battery | findstr level")
            if result:
                return result.split(":")[1].strip()
            return "0"
        except Exception as e:
            logger.error(f"获取电池电量失败: {str(e)}")
            return "0"
            
    @staticmethod
    def get_battery_temp():
        """获取电池温度"""
        try:
            result = ADBCommand.execute_command("shell dumpsys battery | findstr temperature")
            if result:
                temp = float(result.split(":")[1].strip()) / 10
                return f"{temp:.1f}"
            return "0.0"
        except Exception as e:
            logger.error(f"获取电池温度失败: {str(e)}")
            return "0.0"
            
    @staticmethod
    def get_wifi_state():
        """获取WiFi状态"""
        try:
            result = ADBCommand.execute_command("shell dumpsys wifi | findstr \"Wi-Fi is\"")
            return "已连接" if "enabled" in result else "未连接"
        except Exception as e:
            logger.error(f"获取WiFi状态失败: {str(e)}")
            return "未知"
            
    @staticmethod
    def get_network_traffic():
        """获取网络流量"""
        try:
            result = ADBCommand.execute_command("shell dumpsys netstats | findstr \"wlan0\"")
            if result:
                lines = result.split('\n')
                for line in lines:
                    if "rx_bytes" in line and "tx_bytes" in line:
                        parts = line.split()
                        for part in parts:
                            if "rx_bytes" in part:
                                rx = float(part.split("=")[1]) / (1024 * 1024)
                            elif "tx_bytes" in part:
                                tx = float(part.split("=")[1]) / (1024 * 1024)
                        return rx, tx
            return 0.0, 0.0
        except Exception as e:
            logger.error(f"获取网络流量失败: {str(e)}")
            return 0.0, 0.0
            
    @staticmethod
    def get_process_count():
        """获取进程数量"""
        try:
            result = ADBCommand.execute_command("shell ps")
            if result:
                return str(len(result.split('\n')) - 1)  # 减去标题行
            return "0"
        except Exception as e:
            logger.error(f"获取进程数量失败: {str(e)}")
            return "0"

class MonitorThread(Thread):
    """性能监控线程"""
    def __init__(self, callback, interval=1.0):
        super().__init__()
        self.callback = callback
        self.interval = interval
        self.stop_event = Event()
        self.daemon = True  # 设置为守护线程
        
    def run(self):
        while not self.stop_event.is_set():
            try:
                # 获取性能数据
                data = {
                    'cpu_usage': ADBCommand.get_cpu_usage(),
                    'memory_usage': ADBCommand.get_memory_usage(),
                    'battery_level': ADBCommand.get_battery_level(),
                    'battery_temp': ADBCommand.get_battery_temp(),
                    'wifi_state': ADBCommand.get_wifi_state(),
                }
                
                # 获取网络流量
                rx, tx = ADBCommand.get_network_traffic()
                data['network_rx'] = f"{rx:.1f}"
                data['network_tx'] = f"{tx:.1f}"
                
                # 获取进程数量
                data['process_count'] = ADBCommand.get_process_count()
                
                # 回调更新UI
                self.callback(data)
                
            except Exception as e:
                logger.error(f"性能监控错误: {str(e)}")
                
            self.stop_event.wait(self.interval)
            
    def stop(self):
        """停止监控"""
        self.stop_event.set()
        
class LogMonitorThread(Thread):
    """日志监控线程"""
    def __init__(self, callback):
        super().__init__()
        self.callback = callback
        self.stop_event = Event()
        self.daemon = True
        
    def run(self):
        try:
            # 清除之前的日志
            ADBCommand.clear_logcat()
            
            while not self.stop_event.is_set():
                # 获取最新日志
                result = ADBCommand.execute_command("logcat -d")
                if result and isinstance(result, str):
                    # 清除已读取的日志
                    ADBCommand.clear_logcat()
                    
                    # 处理日志行
                    lines = result.split('\n')
                    for line in lines:
                        if line.strip():
                            self.callback(line.strip())
                            
                # 等待一段时间再继续读取
                self.stop_event.wait(0.5)
                    
        except Exception as e:
            logger.error(f"日志监控错误: {str(e)}")
            
    def stop(self):
        """停止监控"""
        self.stop_event.set()

class PacketCaptureThread(Thread):
    """TCP抓包线程"""
    def __init__(self, callback, interface=None):
        super().__init__()
        self.callback = callback
        self.interface = interface
        self.stop_event = Event()
        self.daemon = True
        self.packets = []
        
    def run(self):
        """运行抓包线程"""
        try:
            from scapy.all import sniff, IP, TCP
            
            def packet_callback(packet):
                if not self.stop_event.is_set() and IP in packet and TCP in packet:
                    # 提取TCP包信息
                    ip_src = packet[IP].src
                    ip_dst = packet[IP].dst
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    flags = packet[TCP].flags
                    
                    # 格式化包信息
                    packet_info = {
                        'time': datetime.now().strftime('%H:%M:%S'),
                        'src': f"{ip_src}:{sport}",
                        'dst': f"{ip_dst}:{dport}",
                        'flags': str(flags),
                        'size': len(packet)
                    }
                    
                    # 保存包信息
                    self.packets.append(packet_info)
                    # 回调更新UI
                    self.callback(packet_info)
            
            # 开始抓包
            sniff(iface=self.interface, 
                  prn=packet_callback,
                  store=0,
                  stop_filter=lambda _: self.stop_event.is_set())
                  
        except Exception as e:
            logger.error(f"抓包错误: {str(e)}")
            
    def stop(self):
        """停止抓包"""
        self.stop_event.set()
        
    def get_packets(self):
        """获取已捕获的包"""
        return self.packets
        
    def save_packets(self, filename):
        """保存抓包结果
        Args:
            filename: 保存的文件名
        """
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                for packet in self.packets:
                    f.write(f"时间: {packet['time']}, "
                           f"源: {packet['src']}, "
                           f"目标: {packet['dst']}, "
                           f"标志: {packet['flags']}, "
                           f"大小: {packet['size']}字节\n")
            return True
        except Exception as e:
            logger.error(f"保存抓包结果失败: {str(e)}")
            return False

class MainWindow(tk.Tk):
    """主窗口类"""
    
    def __init__(self):
        """初始化主窗口"""
        super().__init__()  # 调用父类初始化
        
        # 初始化adb客户端
        self.adb = adbutils.adb
        
        # 设置窗口标题和大小
        self.title("Android调试助手")
        self.geometry("1200x800")
        
        # 设置主题和样式
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # 配置全局样式
        self.style.configure('TButton', padding=5)
        self.style.configure('TLabel', padding=5)
        self.style.configure('TFrame', padding=5)
        self.style.configure('TLabelframe', padding=5)
        self.style.configure('TNotebook', padding=5)
        
        # 初始化线程事件
        self.stop_event = Event()
        
        # 初始化设备状态
        self.device = None
        self.device_status = False
        
        # 初始化线程
        self.monitor_thread = None
        self.log_thread = None
        
        # 初始化性能历史数据
        self.perf_history = []
        
        # 初始化设备选择
        self.current_device = None
        self.devices = []
        
        # 初始化抓包线程
        self.capture_thread = None
        
        # 初始化UI组件
        self._init_ui()
        
        # 定期刷新设备列表
        self.after(5000, self.refresh_devices)
        
    def _init_ui(self):
        """初始化UI"""
        # 创建主框架
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 创建顶部工具栏
        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))
        
        # 设备选择下拉框
        ttk.Label(toolbar, text="设备:").pack(side=tk.LEFT, padx=5)
        self.device_combo = ttk.Combobox(toolbar, width=30)
        self.device_combo.pack(side=tk.LEFT, padx=5)
        self.device_combo.bind('<<ComboboxSelected>>', self.on_device_selected)
        
        # 刷新设备按钮
        self.refresh_btn = ttk.Button(toolbar, text="刷新设备", command=self.refresh_devices)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
        
        # 创建标签页
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # 设备信息页
        device_frame = ttk.Frame(notebook)
        notebook.add(device_frame, text="设备信息")
        self._init_device_info_page(device_frame)
        
        # 性能监控页
        perf_frame = ttk.Frame(notebook)
        notebook.add(perf_frame, text="性能监控")
        self._init_performance_page(perf_frame)
        
        # 日志监控页
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="日志监控")
        self._init_log_page(log_frame)
        
        # 文件管理页
        file_frame = ttk.Frame(notebook)
        notebook.add(file_frame, text="文件管理")
        self._init_file_page(file_frame)
        
        # 添加调试命令页
        debug_frame = ttk.Frame(notebook)
        notebook.add(debug_frame, text="调试命令")
        self._init_debug_page(debug_frame)
        
        # 状态栏
        self.status_bar = ttk.Label(main_frame, text="就绪", relief=tk.SUNKEN)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM, pady=(10, 0))
        
    def _init_device_info_page(self, parent):
        """初始化设备信息页"""
        # 创建设备信息显示区域
        info_frame = ttk.LabelFrame(parent, text="设备基本信息")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 设备信息文本框
        self.device_info_text = ScrolledText(info_frame, height=10)
        self.device_info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 控制按钮区域
        btn_frame = ttk.Frame(info_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(btn_frame, text="刷新信息", command=self.refresh_device_info).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="重启设备", command=self.reboot_device).pack(side=tk.LEFT, padx=5)
        
    def _init_performance_page(self, parent):
        """初始化性能监控页"""
        # 创建性能监控控制区域
        control_frame = ttk.LabelFrame(parent, text="监控控制")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.start_monitor_btn = ttk.Button(control_frame, text="开始监控", command=self.toggle_performance_monitoring)
        self.start_monitor_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        # 添加抓包控制按钮
        self.start_capture_btn = ttk.Button(control_frame, text="开始抓包", command=self.toggle_packet_capture)
        self.start_capture_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.save_capture_btn = ttk.Button(control_frame, text="保存抓包", command=self.save_packet_capture)
        self.save_capture_btn.pack(side=tk.LEFT, padx=5, pady=5)
        self.save_capture_btn['state'] = 'disabled'
        
        # 创建性能数据显示区域
        data_frame = ttk.LabelFrame(parent, text="性能数据")
        data_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 创建左右分隔的Frame
        split_frame = ttk.Frame(data_frame)
        split_frame.pack(fill=tk.BOTH, expand=True)
        
        # 左侧性能数据
        left_frame = ttk.Frame(split_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.perf_text = ScrolledText(left_frame)
        self.perf_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 右侧抓包数据
        right_frame = ttk.Frame(split_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # 创建抓包显示区域
        self.packet_tree = ttk.Treeview(right_frame, columns=("时间", "源地址", "目标地址", "标志", "大小"))
        self.packet_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 设置列
        self.packet_tree.column("#0", width=0, stretch=tk.NO)
        self.packet_tree.column("时间", width=80)
        self.packet_tree.column("源地址", width=150)
        self.packet_tree.column("目标地址", width=150)
        self.packet_tree.column("标志", width=80)
        self.packet_tree.column("大小", width=80)
        
        # 设置表头
        self.packet_tree.heading("时间", text="时间")
        self.packet_tree.heading("源地址", text="源地址")
        self.packet_tree.heading("目标地址", text="目标地址")
        self.packet_tree.heading("标志", text="标志")
        self.packet_tree.heading("大小", text="大小(字节)")
        
        # 添加滚动条
        packet_scroll = ttk.Scrollbar(right_frame, orient="vertical", command=self.packet_tree.yview)
        packet_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_tree.configure(yscrollcommand=packet_scroll.set)
        
    def _init_log_page(self, parent):
        """初始化日志监控页"""
        # 创建顶部控制区域
        control_frame = ttk.LabelFrame(parent, text="日志控制")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 创建左侧按钮区域
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(side=tk.LEFT, fill=tk.X, padx=5, pady=5)
        
        self.start_log_btn = ttk.Button(btn_frame, text="开始记录", command=self.toggle_log_monitoring)
        self.start_log_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="清除日志", command=self.clear_log).pack(side=tk.LEFT, padx=5)
        
        # 创建右侧过滤和导出区域
        filter_frame = ttk.Frame(control_frame)
        filter_frame.pack(side=tk.RIGHT, fill=tk.X, padx=5, pady=5)
        
        # 过滤输入框
        ttk.Label(filter_frame, text="过滤关键词:").pack(side=tk.LEFT, padx=5)
        self.filter_entry = ttk.Entry(filter_frame, width=20)
        self.filter_entry.pack(side=tk.LEFT, padx=5)
        self.filter_entry.bind('<KeyRelease>', self.apply_log_filter)
        
        ttk.Button(filter_frame, text="清除过滤", command=self.clear_log_filter).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="导出日志", command=self.export_log).pack(side=tk.LEFT, padx=5)
        
        # 创建日志显示区域
        log_frame = ttk.LabelFrame(parent, text="日志输出")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = ScrolledText(log_frame)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 配置高亮标签
        self.log_text.tag_configure("highlight", background="yellow", foreground="red")
        
        # 保存原始日志内容
        self.original_logs = []
        
    def apply_log_filter(self, event=None):
        """应用日志过滤
        Args:
            event: 键盘事件对象
        """
        try:
            # 获取过滤关键词
            filter_text = self.filter_entry.get().strip().lower()
            
            # 清空当前显示
            self.log_text.delete('1.0', tk.END)
            
            # 如果没有过滤关键词，显示所有日志
            if not filter_text:
                for log in self.original_logs:
                    self.log_text.insert(tk.END, log + '\n')
            else:
                # 显示匹配的日志并高亮关键词
                for log in self.original_logs:
                    if filter_text in log.lower():
                        # 插入日志行
                        line_start = self.log_text.index("end-1c")
                        self.log_text.insert(tk.END, log + '\n')
                        
                        # 查找并高亮所有匹配的关键词
                        line_end = self.log_text.index("end-1c")
                        self.highlight_text(line_start, line_end, filter_text)
            
            # 滚动到最新的日志
            self.log_text.see(tk.END)
            
        except Exception as e:
            self.status_bar['text'] = f"过滤日志出错: {str(e)}"
            
    def highlight_text(self, start, end, keyword):
        """高亮显示文本中的关键词
        Args:
            start: 起始位置
            end: 结束位置
            keyword: 要高亮的关键词
        """
        try:
            # 获取文本内容
            text = self.log_text.get(start, end).lower()
            keyword = keyword.lower()
            
            # 查找所有匹配位置
            idx = 0
            while True:
                idx = text.find(keyword, idx)
                if idx == -1:
                    break
                    
                # 计算实际位置
                line_start = int(float(start))
                match_start = f"{line_start}.{idx}"
                match_end = f"{line_start}.{idx + len(keyword)}"
                
                # 添加高亮标签
                self.log_text.tag_add("highlight", match_start, match_end)
                
                idx += len(keyword)
                
        except Exception as e:
            logger.error(f"高亮文本失败: {str(e)}")
            
    def update_log(self, log_line):
        """更新日志显示
        Args:
            log_line: 新的日志行
        """
        try:
            # 保存到原始日志列表
            self.original_logs.append(log_line)
            
            # 获取当前过滤关键词
            filter_text = self.filter_entry.get().strip().lower()
            
            # 如果没有过滤关键词或日志匹配过滤条件，则显示
            if not filter_text or filter_text in log_line.lower():
                # 获取插入位置
                line_start = self.log_text.index("end-1c")
                
                # 插入新日志
                self.log_text.insert(tk.END, log_line + '\n')
                
                # 如果有过滤关键词且匹配，添加高亮
                if filter_text and filter_text in log_line.lower():
                    line_end = self.log_text.index("end-1c")
                    self.highlight_text(line_start, line_end, filter_text)
                
                # 自动滚动到最新的日志
                self.log_text.see(tk.END)
            
            # 如果日志太长，删除旧的内容
            if len(self.original_logs) > 1000:
                self.original_logs = self.original_logs[-1000:]
                
        except Exception as e:
            self.status_bar['text'] = f"更新日志出错: {str(e)}"
            
    def clear_log_filter(self):
        """清除日志过滤"""
        try:
            # 清空过滤输入框
            self.filter_entry.delete(0, tk.END)
            
            # 显示所有日志
            self.log_text.delete('1.0', tk.END)
            for log in self.original_logs:
                self.log_text.insert(tk.END, log + '\n')
                
            self.status_bar['text'] = "已清除日志过滤"
            
        except Exception as e:
            self.status_bar['text'] = f"清除过滤出错: {str(e)}"
            
    def export_log(self):
        """导出日志"""
        try:
            # 获取当前时间作为默认文件名
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"android_debug_log_{timestamp}.txt"
            
            # 打开文件选择对话框
            filename = filedialog.asksaveasfilename(
                title="导出日志",
                defaultextension=".txt",
                initialfile=default_filename,
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if filename:
                # 获取当前显示的日志内容
                current_logs = self.log_text.get('1.0', tk.END).strip()
                
                # 写入文件
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(current_logs)
                    
                self.status_bar['text'] = f"日志已导出到: {filename}"
            
        except Exception as e:
            self.status_bar['text'] = f"导出日志出错: {str(e)}"
            messagebox.showerror("错误", f"导出日志失败: {str(e)}")
            
    def _init_file_page(self, parent):
        """初始化文件管理页"""
        # 创建左侧文件操作区域
        left_frame = ttk.LabelFrame(parent, text="文件操作")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 文件路径输入
        path_frame = ttk.Frame(left_frame)
        path_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(path_frame, text="路径:").pack(side=tk.LEFT)
        self.path_entry = ttk.Entry(path_frame)
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.path_entry.insert(0, "/sdcard")  # 修改默认路径为可写的/sdcard
        
        # 文件操作按钮
        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 添加返回上一级按钮
        ttk.Button(btn_frame, text="返回上一级", command=self.go_parent_dir).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="列出文件", command=self.list_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="上传文件", command=self.upload_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="下载文件", command=self.download_file).pack(side=tk.LEFT, padx=5)
        
        # 创建文件列表显示区域
        list_frame = ttk.Frame(left_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 创建Treeview组件
        self.file_tree = ttk.Treeview(list_frame, columns=("权限", "用户", "组", "大小", "修改时间", "文件名"))
        self.file_tree.pack(fill=tk.BOTH, expand=True)
        
        # 设置列宽和列标题
        self.file_tree.column("#0", width=0, stretch=tk.NO)  # 隐藏第一列
        self.file_tree.column("权限", width=100)
        self.file_tree.column("用户", width=80)
        self.file_tree.column("组", width=80)
        self.file_tree.column("大小", width=80)
        self.file_tree.column("修改时间", width=150)
        self.file_tree.column("文件名", width=200)
        
        # 设置表头
        self.file_tree.heading("权限", text="权限")
        self.file_tree.heading("用户", text="用户")
        self.file_tree.heading("组", text="组")
        self.file_tree.heading("大小", text="大小")
        self.file_tree.heading("修改时间", text="修改时间")
        self.file_tree.heading("文件名", text="文件名")
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.file_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_tree.configure(yscrollcommand=scrollbar.set)
        
        # 绑定双击事件
        self.file_tree.bind('<Double-1>', self._on_file_double_click)
        
        # 创建右键菜单
        self.file_menu = tk.Menu(self.file_tree, tearoff=0)
        self.file_menu.add_command(label="打开/查看", command=self._open_file)
        self.file_menu.add_command(label="下载", command=self.download_file)
        self.file_menu.add_command(label="复制路径", command=self._copy_file_path)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="重命名", command=self._rename_file)
        self.file_menu.add_command(label="删除", command=self._delete_file)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="属性", command=self._show_file_properties)
        
        # 绑定右键菜单
        self.file_tree.bind('<Button-3>', self._show_file_menu)
        
        # 创建右侧应用管理区域
        right_frame = ttk.LabelFrame(parent, text="应用管理")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 应用包名输入
        pkg_frame = ttk.Frame(right_frame)
        pkg_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(pkg_frame, text="包名:").pack(side=tk.LEFT)
        self.package_entry = ttk.Entry(pkg_frame)
        self.package_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # 应用操作按钮
        app_btn_frame = ttk.Frame(right_frame)
        app_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(app_btn_frame, text="安装APK", command=self.install_apk).pack(side=tk.LEFT, padx=5)
        ttk.Button(app_btn_frame, text="卸载应用", command=self.uninstall_app).pack(side=tk.LEFT, padx=5)
        ttk.Button(app_btn_frame, text="启动应用", command=self.start_app).pack(side=tk.LEFT, padx=5)
        ttk.Button(app_btn_frame, text="停止应用", command=self.stop_app).pack(side=tk.LEFT, padx=5)
        
        # 应用列表显示区域
        list_frame = ttk.Frame(right_frame)
        list_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(list_frame, text="系统应用", command=lambda: self.list_packages("-s")).pack(side=tk.LEFT, padx=5)
        ttk.Button(list_frame, text="第三方应用", command=lambda: self.list_packages("-3")).pack(side=tk.LEFT, padx=5)
        ttk.Button(list_frame, text="所有应用", command=lambda: self.list_packages()).pack(side=tk.LEFT, padx=5)
        
        # 应用信息显示
        self.app_list = ScrolledText(right_frame)
        self.app_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _init_debug_page(self, parent):
        """初始化调试命令页"""
        # 创建左右分隔Frame
        paned = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 左侧命令列表区域
        left_frame = ttk.LabelFrame(paned, text="命令列表")
        paned.add(left_frame)
        
        # 创建Notebook用于分类显示命令
        cmd_notebook = ttk.Notebook(left_frame)
        cmd_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 基础命令页
        basic_frame = ttk.Frame(cmd_notebook)
        cmd_notebook.add(basic_frame, text="基础命令")
        self._init_command_group(basic_frame, [
            ("启动ADB服务", "adb start-server"),
            ("终止ADB服务", "adb kill-server"),
            ("查看ADB版本", "adb version"),
            ("查看设备列表", "adb devices"),
            ("重启设备", "adb reboot"),
            ("进入Shell", "adb shell"),
            ("当前活动界面", "adb shell dumpsys activity top")
        ])

        # 设备信息命令页
        device_frame = ttk.Frame(cmd_notebook)
        cmd_notebook.add(device_frame, text="设备信息")
        self._init_command_group(device_frame, [
            ("设备型号", "adb shell getprop ro.product.model"),
            ("Android版本", "adb shell getprop ro.build.version.release"),
            ("系统版本号", "adb shell getprop ro.build.display.id"),
            ("系统API级别", "adb shell getprop ro.build.version.sdk"),
            ("CPU架构", "adb shell getprop ro.product.cpu.abi"),
            ("设备序列号", "adb shell getprop ro.serialno"),
            ("IMEI号", "adb shell service call iphonesubinfo 1"),
            ("Android ID", "adb shell settings get secure android_id"),
            ("MAC地址", "adb shell cat /sys/class/net/wlan0/address"),
            ("电池信息", "adb shell dumpsys battery"),
            ("分辨率", "adb shell wm size"),
            ("屏幕密度", "adb shell wm density")
        ])

        # 应用管理命令页
        app_frame = ttk.Frame(cmd_notebook)
        cmd_notebook.add(app_frame, text="应用管理")
        self._init_command_group(app_frame, [
            ("安装应用", "adb install "),
            ("卸载应用", "adb uninstall "),
            ("清除应用数据", "adb shell pm clear "),
            ("启动应用", "adb shell monkey -p {package} -c android.intent.category.LAUNCHER 1"),
            ("停止应用", "adb shell am force-stop "),
            ("查看前台应用", "adb shell dumpsys window | grep mCurrentFocus"),
            ("系统应用列表", "adb shell pm list packages -s"),
            ("第三方应用列表", "adb shell pm list packages -3"),
            ("禁用应用", "adb shell pm disable-user "),
            ("启用应用", "adb shell pm enable ")
        ])

        # 文件管理命令页
        file_frame = ttk.Frame(cmd_notebook)
        cmd_notebook.add(file_frame, text="文件管理")
        self._init_command_group(file_frame, [
            ("推送文件", "adb push "),
            ("拉取文件", "adb pull "),
            ("列出目录", "adb shell ls "),
            ("创建目录", "adb shell mkdir "),
            ("删除文件", "adb shell rm "),
            ("删除目录", "adb shell rm -r "),
            ("复制文件", "adb shell cp "),
            ("移动文件", "adb shell mv "),
            ("查看文件内容", "adb shell cat "),
            ("修改权限", "adb shell chmod ")
        ])

        # 网络命令页
        network_frame = ttk.Frame(cmd_notebook)
        cmd_notebook.add(network_frame, text="网络管理")
        self._init_command_group(network_frame, [
            ("IP地址", "adb shell ip addr show wlan0"),
            ("网络统计", "adb shell dumpsys netstats"),
            ("DNS信息", "adb shell getprop net.dns1"),
            ("TCP连接", "adb shell netstat"),
            ("Ping测试", "adb shell ping -c 4 www.baidu.com"),
            ("WiFi信息", "adb shell dumpsys wifi"),
            ("开启WiFi", "adb shell svc wifi enable"),
            ("关闭WiFi", "adb shell svc wifi disable"),
            ("无线调试连接", "adb connect "),
            ("断开无线连接", "adb disconnect ")
        ])

        # 性能监控命令页
        perf_frame = ttk.Frame(cmd_notebook)
        cmd_notebook.add(perf_frame, text="性能监控")
        self._init_command_group(perf_frame, [
            ("CPU信息", "adb shell cat /proc/cpuinfo"),
            ("内存信息", "adb shell cat /proc/meminfo"),
            ("CPU使用率", "adb shell top -n 1"),
            ("内存使用情况", "adb shell dumpsys meminfo"),
            ("进程列表", "adb shell ps"),
            ("GPU信息", "adb shell dumpsys gfxinfo"),
            ("系统负载", "adb shell cat /proc/loadavg"),
            ("电池状态", "adb shell dumpsys battery"),
            ("温度信息", "adb shell cat /sys/class/thermal/thermal_zone*/temp"),
            ("帧率信息", "adb shell dumpsys SurfaceFlinger")
        ])

        # 调试命令页
        debug_frame = ttk.Frame(cmd_notebook)
        cmd_notebook.add(debug_frame, text="调试工具")
        self._init_command_group(debug_frame, [
            ("查看日志", "adb logcat"),
            ("清除日志", "adb logcat -c"),
            ("ANR信息", "adb pull /data/anr/traces.txt ./"),
            ("抓取屏幕", "adb shell screencap -p /sdcard/screen.png"),
            ("录制屏幕", "adb shell screenrecord /sdcard/video.mp4"),
            ("输入文本", "adb shell input text "),
            ("模拟按键", "adb shell input keyevent "),
            ("模拟点击", "adb shell input tap "),
            ("模拟滑动", "adb shell input swipe "),
            ("查看事件", "adb shell getevent")
        ])

        # 系统设置命令页
        settings_frame = ttk.Frame(cmd_notebook)
        cmd_notebook.add(settings_frame, text="系统设置")
        self._init_command_group(settings_frame, [
            ("修改系统时间", "adb shell date -s "),
            ("设置系统属性", "adb shell setprop "),
            ("查看系统属性", "adb shell getprop "),
            ("调整亮度", "adb shell settings put system screen_brightness "),
            ("设置休眠时间", "adb shell settings put system screen_off_timeout "),
            ("设置铃声音量", "adb shell media volume --stream 2 --set "),
            ("设置媒体音量", "adb shell media volume --stream 3 --set "),
            ("设置通知音量", "adb shell media volume --stream 5 --set "),
            ("设置时区", "adb shell setprop persist.sys.timezone "),
            ("设置语言", "adb shell setprop persist.sys.language ")
        ])

        # 右侧执行结果区域
        right_frame = ttk.LabelFrame(paned, text="执行结果")
        paned.add(right_frame)
        
        # 创建结果显示文本框
        self.result_text = ScrolledText(right_frame)
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 配置文本显示样式
        self.result_text.tag_configure('command', foreground='blue', font=('Courier', 10, 'bold'))
        self.result_text.tag_configure('separator', foreground='gray')
        self.result_text.tag_configure('title', foreground='green', font=('Courier', 10, 'bold'))
        self.result_text.tag_configure('result', font=('Courier', 10))
        self.result_text.tag_configure('success', foreground='green')
        self.result_text.tag_configure('error', foreground='red')

    def select_apk_file(self):
        """选择APK文件"""
        try:
            file_path = filedialog.askopenfilename(
                title='选择APK文件',
                filetypes=[('APK文件', '*.apk'), ('所有文件', '*.*')]
            )
            if file_path:
                self.apk_path_var.set(file_path)
                self.analyze_apk('basic')  # 自动执行基本信息分析
        except Exception as e:
            logger.error(f'选择APK文件时发生错误: {str(e)}')
            messagebox.showerror('错误', f'选择APK文件时发生错误:\n{str(e)}')
            
    def analyze_apk(self, analysis_type):
        """分析APK文件"""
        if not APKUTILS_AVAILABLE:
            messagebox.showerror("错误", "未安装apkutils2库，无法进行APK分析")
            return
            
        apk_path = self.apk_path_var.get()
        if not apk_path:
            messagebox.showerror("错误", "请先选择APK文件")
            return
            
        try:
            success, message, result = None, None, None
            if analysis_type == "basic":
                success, message, result = APKAnalyzer.analyze_basic_info(apk_path)
                if success:
                    self._display_dict_result("APK基本信息", result)
                else:
                    messagebox.showerror("错误", f"分析APK基本信息失败: {message}")
            elif analysis_type == "permissions":
                success, message, result = APKAnalyzer.analyze_permissions(apk_path)
                if success:
                    self._display_list_result("APK权限信息", result)
                else:
                    messagebox.showerror("错误", f"分析APK权限信息失败: {message}")
            elif analysis_type == "signature":
                success, message, result = APKAnalyzer.analyze_signature(apk_path)
                if success:
                    self._display_signature_result("APK签名信息", result)
                else:
                    messagebox.showerror("错误", f"分析APK签名信息失败: {message}")
            elif analysis_type == "components":
                success, message, result = APKAnalyzer.analyze_components(apk_path)
                if success:
                    self._display_components_result("APK组件信息", result)
                else:
                    messagebox.showerror("错误", f"分析APK组件信息失败: {message}")
            elif analysis_type == "resources":
                success, message, result = APKAnalyzer.analyze_resources(apk_path)
                if success:
                    self._display_resources_result("APK资源信息", result)
                else:
                    messagebox.showerror("错误", f"分析APK资源信息失败: {message}")
        except Exception as e:
            logger.error(f"APK分析失败: {str(e)}")
            messagebox.showerror("错误", f"APK分析失败: {str(e)}")
            
    def _display_dict_result(self, title, data):
        """显示字典类型的分析结果"""
        if not data or not isinstance(data, dict):
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "无有效数据")
            return
            
        result_text = f"=== {title} ===\n\n"
        for key, value in data.items():
            result_text += f"{key}: {value}\n"
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, result_text)
        
    def _display_list_result(self, title, data):
        """显示列表类型的分析结果"""
        if not data or not isinstance(data, list):
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "无有效数据")
            return
            
        result_text = f"=== {title} ===\n\n"
        for item in data:
            result_text += f"- {item}\n"
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, result_text)
        
    def _display_signature_result(self, title, data):
        """显示签名分析结果"""
        if not data or not isinstance(data, str):
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "无有效的签名数据")
            return
            
        result_text = f"=== {title} ===\n\n{data}"
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, result_text)
        
    def _display_components_result(self, title, data):
        """显示组件分析结果"""
        if not data or not isinstance(data, dict):
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "无有效的组件数据")
            return
            
        result_text = f"=== {title} ===\n\n"
        for component_type, components in data.items():
            if components:
                result_text += f"{component_type}:\n"
                for component in components:
                    result_text += f"- {component}\n"
                result_text += "\n"
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, result_text)
        
    def _display_resources_result(self, title, data):
        """显示资源分析结果"""
        if not data or not isinstance(data, dict):
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "无有效的资源数据")
            return
            
        result_text = f"=== {title} ===\n\n"
        
        # 显示动态库
        if data.get('dynamic_libraries'):
            result_text += "动态库:\n"
            for lib in data['dynamic_libraries']:
                result_text += f"- {lib}\n"
            result_text += "\n"
        
        # 显示DEX文件
        if data.get('dex_files'):
            result_text += "DEX文件:\n"
            for dex in data['dex_files']:
                result_text += f"- {dex}\n"
            result_text += "\n"
        
        # 显示资源文件
        if data.get('resource_files'):
            result_text += "资源文件 (前20个):\n"
            for res in data['resource_files'][:20]:
                result_text += f"- {res}\n"
            if len(data['resource_files']) > 20:
                result_text += f"... 还有 {len(data['resource_files']) - 20} 个资源文件\n"
            result_text += "\n"
        
        # 显示assets文件
        if data.get('assets'):
            result_text += "Assets文件 (前20个):\n"
            for asset in data['assets'][:20]:
                result_text += f"- {asset}\n"
            if len(data['assets']) > 20:
                result_text += f"... 还有 {len(data['assets']) - 20} 个assets文件\n"
            result_text += "\n"
        
        # 显示其他文件
        if data.get('others'):
            result_text += "其他文件 (前20个):\n"
            for other in data['others'][:20]:
                result_text += f"- {other}\n"
            if len(data['others']) > 20:
                result_text += f"... 还有 {len(data['others']) - 20} 个其他文件\n"
            
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, result_text)

    def _init_command_group(self, parent, commands):
        """初始化命令组
        Args:
            parent: 父容器
            commands: 命令列表，每项为(显示名称, 命令)的元组
        """
        for name, cmd in commands:
            frame = ttk.Frame(parent)
            frame.pack(fill=tk.X, padx=5, pady=2)
            
            # 命令按钮
            btn = ttk.Button(frame, text=name, 
                           command=lambda c=cmd: self._execute_command(c))
            btn.pack(side=tk.LEFT, padx=(0, 5))
            
            # 命令文本框（用于可能需要修改的命令）
            entry = ttk.Entry(frame)
            entry.insert(0, cmd)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
            
            # 执行按钮
            exec_btn = ttk.Button(frame, text="执行",
                                command=lambda e=entry: self._execute_command(e.get()))
            exec_btn.pack(side=tk.RIGHT, padx=(5, 0))

    def _execute_command(self, command):
        """执行ADB命令
        Args:
            command: 要执行的命令
        """
        try:
            # 清空之前的结果
            self.result_text.delete('1.0', tk.END)
            
            # 显示正在执行的命令
            self.result_text.insert('1.0', f"正在执行命令: {command}\n", 'command')
            self.result_text.insert(tk.END, "-" * 50 + "\n\n", 'separator')
            
            # 检查命令是否需要包名
            if "{package}" in command:
                package = simpledialog.askstring("输入包名", 
                    "请输入应用包名:",
                    parent=self)
                if not package:
                    self.result_text.insert(tk.END, "已取消执行\n", 'error')
                    return
                command = command.format(package=package)
            
            # 检查命令是否需要补充参数
            if command.strip().endswith((" ", "connect", "disconnect", "install", "uninstall", "push", "pull")):
                param = simpledialog.askstring("输入参数", 
                    "请输入命令参数:",
                    parent=self)
                if not param:
                    self.result_text.insert(tk.END, "已取消执行\n", 'error')
                    return
                command = command.strip() + " " + param
            
            # 执行命令
            self.result_text.insert(tk.END, "执行结果:\n", 'title')
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            output = result.decode('utf-8', errors='ignore')
            
            # 显示结果
            if output.strip():
                self.result_text.insert(tk.END, output + "\n", 'result')
            else:
                self.result_text.insert(tk.END, "命令执行成功,无输出结果\n", 'success')
            
            self.status_bar['text'] = "命令执行成功"
            
        except subprocess.CalledProcessError as e:
            error_msg = f"命令执行失败: {str(e)}\n{e.output.decode('utf-8', errors='ignore')}"
            self.result_text.insert(tk.END, error_msg + "\n", 'error')
            self.status_bar['text'] = "命令执行失败"
            
        except Exception as e:
            error_msg = f"执行出错: {str(e)}"
            self.result_text.insert(tk.END, error_msg + "\n", 'error')
            self.status_bar['text'] = "命令执行出错"
            
        # 自动滚动到底部
        self.result_text.see(tk.END)

    # 功能实现方法
    def refresh_devices(self):
        """刷新设备列表"""
        devices = ADBCommand.get_devices()
        self.device_combo['values'] = devices
        self.status_bar['text'] = '设备列表已更新'
    
    def connect_device(self):
        """连接设备"""
        selected_device = self.device_combo.get()
        if selected_device:
            result = ADBCommand.connect_wireless(selected_device)
            self.status_bar['text'] = result
    
    def disconnect_device(self):
        """断开设备"""
        selected_device = self.device_combo.get()
        if selected_device:
            result = ADBCommand.disconnect_wireless(selected_device)
            self.status_bar['text'] = result
    
    def install_apk(self):
        """安装APK"""
        if not self.current_device:
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        file_path = filedialog.askopenfilename(title='选择APK文件', filetypes=[("APK files", "*.apk")])
        if file_path:
            try:
                result = ADBCommand.execute_command(f"install {file_path}")
                self.app_list.delete('1.0', tk.END)
                self.app_list.insert('1.0', result)
                self.status_bar['text'] = "APK安装完成"
            except Exception as e:
                messagebox.showerror("错误", f"安装失败: {str(e)}")
    
    def uninstall_app(self):
        """卸载应用"""
        if not self.current_device:
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        package_name = self.package_entry.get().strip()
        if not package_name:
            messagebox.showwarning("警告", "请输入应用包名")
            return
            
        if messagebox.askyesno("确认", f"确定要卸载应用 {package_name} 吗？"):
            try:
                result = ADBCommand.execute_command(f"uninstall {package_name}")
                self.app_list.delete('1.0', tk.END)
                self.app_list.insert('1.0', result)
                self.status_bar['text'] = "应用卸载完成"
            except Exception as e:
                messagebox.showerror("错误", f"卸载失败: {str(e)}")
    
    def start_app(self):
        """启动应用"""
        if not self.current_device:
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        package_name = self.package_entry.get().strip()
        if not package_name:
            messagebox.showwarning("警告", "请输入应用包名")
            return
            
        try:
            result = ADBCommand.execute_command(f"shell monkey -p {package_name} -c android.intent.category.LAUNCHER 1")
            self.status_bar['text'] = "应用已启动"
        except Exception as e:
            messagebox.showerror("错误", f"启动失败: {str(e)}")
    
    def stop_app(self):
        """停止应用"""
        if not self.current_device:
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        package_name = self.package_entry.get().strip()
        if not package_name:
            messagebox.showwarning("警告", "请输入应用包名")
            return
            
        try:
            result = ADBCommand.execute_command(f"shell am force-stop {package_name}")
            self.status_bar['text'] = "应用已停止"
        except Exception as e:
            messagebox.showerror("错误", f"停止失败: {str(e)}")
    
    def list_packages(self, option=None):
        """列出应用包
        Args:
            option: 可选参数，如 -s (系统应用)，-3 (第三方应用)
        """
        if not self.current_device:
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        try:
            cmd = "shell pm list packages"
            if option:
                cmd += f" {option}"
            result = ADBCommand.execute_command(cmd)
            
            # 清空并显示结果
            self.app_list.delete('1.0', tk.END)
            self.app_list.insert('1.0', result)
            
            # 更新状态栏
            status = "系统应用" if option == "-s" else "第三方应用" if option == "-3" else "所有应用"
            self.status_bar['text'] = f"已列出{status}"
        except Exception as e:
            messagebox.showerror("错误", f"获取应用列表失败: {str(e)}")
            
    def get_app_info(self):
        """获取应用详细信息"""
        if not self.current_device:
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        package_name = self.package_entry.get().strip()
        if not package_name:
            messagebox.showwarning("警告", "请输入应用包名")
            return
            
        try:
            result = ADBCommand.execute_command(f"shell dumpsys package {package_name}")
            self.app_list.delete('1.0', tk.END)
            self.app_list.insert('1.0', result)
            self.status_bar['text'] = "已获取应用信息"
        except Exception as e:
            messagebox.showerror("错误", f"获取应用信息失败: {str(e)}")
    
    def show_system_info(self):
        """显示系统信息"""
        info = ADBCommand.get_device_info()
        self.system_info.setText(info)
        self.statusBar().showMessage('系统信息已更新')
    
    def take_screenshot(self):
        """截图"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"screenshot_{timestamp}.png"
        ADBCommand.execute_command(f"shell screencap -p /sdcard/{filename}")
        ADBCommand.execute_command(f"pull /sdcard/{filename} .")
        ADBCommand.execute_command(f"shell rm /sdcard/{filename}")
        self.statusBar().showMessage(f'截图已保存: {filename}')
    
    def start_screenrecord(self):
        """开始录屏"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"screenrecord_{timestamp}.mp4"
        ADBCommand.execute_command(f"shell screenrecord /sdcard/{filename}")
        self.statusBar().showMessage('录屏已开始')
    
    def start_monitoring(self):
        """启动性能监控"""
        if not self.monitor_thread or not self.monitor_thread.is_alive():
            self.monitor_thread = MonitorThread(self.update_performance_data)
            self.monitor_thread.start()
            self.start_monitor_btn['text'] = "停止监控"
            self.status_bar['text'] = "性能监控已启动"
            
    def stop_monitoring(self):
        """停止性能监控"""
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.stop()
            self.monitor_thread.join()
            self.monitor_thread = None
            self.start_monitor_btn['text'] = "开始监控"
            self.status_bar['text'] = "性能监控已停止"
            
    def update_performance_data(self, data):
        """更新性能数据显示
        Args:
            data: 包含性能数据的字典
        """
        try:
            # 清空当前显示
            self.perf_text.delete('1.0', tk.END)
            
            # 格式化并显示性能数据
            info = [
                f"CPU使用率: {data.get('cpu_usage', 'N/A')}%",
                f"内存使用: {data.get('memory_usage', 'N/A')}MB",
                f"电池电量: {data.get('battery_level', 'N/A')}%",
                f"电池温度: {data.get('battery_temp', 'N/A')}°C",
                f"WiFi状态: {data.get('wifi_state', 'N/A')}",
                f"网络流量: ↑{data.get('network_tx', 'N/A')}MB ↓{data.get('network_rx', 'N/A')}MB",
                f"进程数量: {data.get('process_count', 'N/A')}"
            ]
            
            self.perf_text.insert('1.0', '\n'.join(info))
        except Exception as e:
            self.status_bar.config(text=f"更新性能数据出错: {str(e)}")
            
    def toggle_performance_monitoring(self):
        """切换性能监控状态"""
        if not self.monitor_thread or not self.monitor_thread.is_alive():
            self.start_monitoring()
        else:
            self.stop_monitoring()
            
    def view_system_file(self):
        """查看系统文件"""
        file_path = self.path_entry.get()
        if file_path:
            content = ADBCommand.get_system_file_content(file_path)
            self.file_content.setText(content)
            self.file_content.setReadOnly(True)
            self.statusBar().showMessage('文件内容已加载')
    
    def edit_system_file(self):
        """编辑系统文件"""
        file_path = self.path_entry.get()
        if file_path:
            # 首先获取文件内容
            content = ADBCommand.get_system_file_content(file_path)
            self.file_content.setText(content)
            self.file_content.setReadOnly(False)
            
            # 添加保存按钮
            save_btn = ttk.Button(self, text='保存修改', command=lambda: self.save_system_file(file_path))
            self.statusBar().addWidget(save_btn)
    
    def save_system_file(self, file_path):
        """保存系统文件修改"""
        content = self.file_content.toPlainText()
        result = ADBCommand.write_system_file(file_path, content)
        if "错误" not in result:
            self.statusBar().showMessage('文件保存成功')
        else:
            self.statusBar().showMessage(f'保存失败: {result}')
    
    def upload_file(self):
        """上传文件到设备"""
        if not self.current_device:
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        local_file = filedialog.askopenfilename()
        if not local_file:
            return
            
        remote_path = self.path_entry.get().strip()
        if not remote_path:
            messagebox.showwarning("警告", "请输入目标路径")
            return
            
        try:
            ADBCommand.push_file(local_file, remote_path)
            self.status_bar['text'] = "文件上传成功"
            self.list_files()  # 刷新文件列表
        except Exception as e:
            messagebox.showerror("错误", f"文件上传失败: {str(e)}")
            
    def download_file(self):
        """从设备下载文件"""
        if not self.current_device:
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        try:
            # 获取选中的项目
            selected_item = self.file_tree.selection()
            if not selected_item:
                messagebox.showwarning("警告", "请先选择要下载的文件")
                return
                
            # 获取文件信息
            file_info = self.file_tree.item(selected_item[0])
            if not file_info['values']:
                messagebox.showwarning("警告", "无效的文件信息")
                return
                
            # 获取权限和文件名
            perms = file_info['values'][0]
            file_name = file_info['values'][5]
            
            # 检查是否是目录
            if perms.startswith('d'):
                messagebox.showwarning("警告", "不能下载目录，请选择文件")
                return
                
            # 检查文件是否可读
            if 'r' not in perms:
                messagebox.showwarning("警告", "该文件没有读取权限")
                return
                
            # 构建完整路径（确保使用正斜杠）
            current_path = self.path_entry.get().strip().replace('\\', '/')
            remote_path = f"{current_path}/{file_name}"
            
            # 选择保存位置
            save_path = filedialog.asksaveasfilename(
                title='选择保存位置',
                initialfile=file_name,
                defaultextension=".*"
            )
            if not save_path:
                return
                
            # 执行下载
            logger.info(f"开始下载文件: {remote_path} -> {save_path}")
            result = ADBCommand.pull_file(remote_path, save_path)
            
            if "error" in result.lower() or "failed" in result.lower():
                error_msg = f"文件下载失败: {result}"
                logger.error(error_msg)
                messagebox.showerror("错误", error_msg)
            else:
                success_msg = f"文件 {file_name} 下载成功"
                logger.info(success_msg)
                self.status_bar['text'] = success_msg
                
        except Exception as e:
            error_msg = f"文件下载失败: {str(e)}"
            logger.error(error_msg)
            messagebox.showerror("错误", error_msg)
            
    def browse_files(self):
        """浏览设备文件"""
        result = ADBCommand.execute_command("shell ls -l /sdcard/")
        self.file_content.setText(result)
        self.statusBar().showMessage('文件列表已更新')
    
    # 调试命令相关方法
    def get_current_activity(self):
        """获取当前活动"""
        result = ADBCommand.get_current_activity()
        self.debug_output.setText(result)
        self.statusBar().showMessage('已获取当前活动信息')
    
    def get_focused_window(self):
        """获取焦点窗口"""
        result = ADBCommand.get_focused_window()
        self.debug_output.setText(result)
        self.statusBar().showMessage('已获取焦点窗口信息')
    
    def get_cpu_info(self):
        """获取CPU信息"""
        result = ADBCommand.get_cpu_info()
        self.debug_output.setText(result)
        self.statusBar().showMessage('已获取CPU信息')
    
    def get_memory_info(self):
        """获取内存信息"""
        result = ADBCommand.get_memory_info()
        self.debug_output.setText(result)
        self.statusBar().showMessage('已获取内存信息')
    
    def get_display_info(self):
        """获取显示信息"""
        result = ADBCommand.get_display_info()
        self.debug_output.setText(result)
        self.statusBar().showMessage('已获取显示信息')
    
    def get_network_stats(self):
        """获取网络统计"""
        result = ADBCommand.get_network_stats()
        self.debug_output.setText(result)
        self.statusBar().showMessage('已获取网络统计信息')
    
    def get_wifi_info(self):
        """获取WiFi信息"""
        result = ADBCommand.get_wifi_info()
        self.debug_output.setText(result)
        self.statusBar().showMessage('已获取WiFi信息')
    
    def get_ip_address(self):
        """获取IP地址"""
        result = ADBCommand.get_ip_address()
        self.debug_output.setText(result)
        self.statusBar().showMessage('已获取IP地址')
    
    def view_logcat(self):
        """查看日志"""
        result = ADBCommand.get_logcat()
        self.debug_output.setText(result)
        self.statusBar().showMessage('已获取日志信息')
    
    def clear_logcat(self):
        """清除日志"""
        result = ADBCommand.clear_logcat()
        self.debug_output.setText("日志已清除")
        self.statusBar().showMessage('已清除日志')
    
    def get_anr_traces(self):
        """获取ANR信息"""
        result = ADBCommand.get_anr_traces()
        self.debug_output.setText(result)
        self.statusBar().showMessage('已获取ANR信息')
    
    def input_text(self):
        """输入文本"""
        text = simpledialog.askstring("输入文本", "请输入要模拟输入的文本：")
        if text:
            result = ADBCommand.input_text(text)
            self.debug_output.setText(f"文本输入完成: {text}")
            self.statusBar().showMessage('已完成文本输入')
    
    def input_keyevent(self):
        """模拟按键"""
        keycode = simpledialog.askinteger("模拟按键", "请输入按键代码：", minvalue=0)
        if keycode:
            result = ADBCommand.input_keyevent(keycode)
            self.debug_output.setText(f"按键事件已发送: {keycode}")
            self.statusBar().showMessage('已发送按键事件')
    
    def input_tap(self):
        """模拟点击"""
        x = simpledialog.askinteger("模拟点击", "请输入X坐标：", minvalue=0)
        if x:
            y = simpledialog.askinteger("模拟点击", "请输入Y坐标：", minvalue=0)
            if y:
                result = ADBCommand.input_tap(x, y)
                self.debug_output.setText(f"点击事件已发送: ({x}, {y})")
                self.statusBar().showMessage('已发送点击事件')
    
    def get_imei(self):
        """获取IMEI号"""
        result = ADBCommand.get_imei()
        self.debug_output.setText(result)
        self.statusBar().showMessage('已获取IMEI号')
    
    def get_android_id(self):
        """获取Android ID"""
        result = ADBCommand.get_android_id()
        self.debug_output.setText(result)
        self.statusBar().showMessage('已获取Android ID')
    
    def reboot_device(self):
        """重启设备"""
        if not self.current_device:
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        if messagebox.askyesno("确认", "确定要重启设备吗？"):
            ADBCommand.reboot_device()
            self.status_bar['text'] = "设备正在重启..."
            
    def toggle_log_monitoring(self):
        """切换日志监控状态"""
        if not self.log_thread or not self.log_thread.is_alive():
            self.start_log_monitoring()
        else:
            self.stop_log_monitoring()
            
    def start_log_monitoring(self):
        """启动日志监控"""
        if not self.log_thread or not self.log_thread.is_alive():
            self.log_thread = LogMonitorThread(self.update_log)
            self.log_thread.start()
            self.start_log_btn['text'] = "停止日志"
            self.status_bar['text'] = "日志监控已启动"
            
    def stop_log_monitoring(self):
        """停止日志监控"""
        if self.log_thread and self.log_thread.is_alive():
            self.log_thread.stop()
            self.log_thread.join()
            self.log_thread = None
            self.start_log_btn['text'] = "开始日志"
            self.status_bar['text'] = "日志监控已停止"
            
    def clear_log(self):
        """清除日志"""
        self.log_text.delete('1.0', tk.END)
        ADBCommand.clear_logcat()
        self.status_bar['text'] = "日志已清除"
        
    def list_files(self):
        """列出文件"""
        path = self.path_entry.get().strip()
        if not path:
            messagebox.showwarning("警告", "请输入文件路径")
            return
            
        try:
            # 清空现有项目
            for item in self.file_tree.get_children():
                self.file_tree.delete(item)
                
            # 获取文件列表
            result = ADBCommand.execute_command(f"shell ls -l {path}")
            if "错误" in result:
                messagebox.showerror("错误", result)
                return
                
            # 解析并显示文件信息
            lines = result.strip().split('\n')
            for line in lines:
                if line.startswith('total') or not line.strip():  # 跳过总计行和空行
                    continue
                    
                try:
                    # 使用更健壮的分割方法
                    parts = line.split(None, 8)  # 最多分割8次，保持文件名完整
                    if len(parts) >= 8:
                        perms = parts[0]
                        user = parts[2]
                        group = parts[3]
                        
                        # 处理文件大小
                        try:
                            size_str = parts[4]
                            size = int(size_str)  # 尝试转换为整数
                            size = self._format_size(size)  # 格式化显示
                        except ValueError:
                            size = size_str  # 如果转换失败，直接使用原始字符串
                        
                        # 处理日期和时间
                        date = f"{parts[5]} {parts[6]}"
                        
                        # 获取文件名
                        name = parts[-1]
                        
                        # 添加到树形视图
                        self.file_tree.insert("", "end", values=(perms, user, group, size, date, name))
                except Exception as e:
                    logger.error(f"解析文件行失败: {line} - {str(e)}")
                    continue
            
            self.status_bar['text'] = f"已列出 {path} 的文件"
            
        except Exception as e:
            error_msg = f"获取文件列表失败: {str(e)}"
            logger.error(error_msg)
            messagebox.showerror("错误", error_msg)
            
    def _format_size(self, size):
        """格式化文件大小显示
        Args:
            size: 文件大小(字节)
        Returns:
            格式化后的大小字符串
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
            
    def _show_file_menu(self, event):
        """显示文件右键菜单"""
        try:
            # 获取点击位置对应的项目
            item = self.file_tree.identify_row(event.y)
            if item:
                # 选中该项目
                self.file_tree.selection_set(item)
                # 显示菜单
                self.file_menu.post(event.x_root, event.y_root)
        except Exception as e:
            logger.error(f"显示文件菜单失败: {str(e)}")
            
    def _copy_file_path(self):
        """复制文件路径"""
        try:
            selected_item = self.file_tree.selection()
            if selected_item:
                file_info = self.file_tree.item(selected_item[0])
                if file_info['values']:
                    file_name = file_info['values'][5]
                    full_path = os.path.join(self.path_entry.get().strip(), file_name)
                    self.clipboard_clear()
                    self.clipboard_append(full_path)
                    self.status_bar['text'] = "文件路径已复制到剪贴板"
        except Exception as e:
            logger.error(f"复制文件路径失败: {str(e)}")
            
    def _delete_file(self):
        """删除文件"""
        try:
            selected_item = self.file_tree.selection()
            if selected_item:
                file_info = self.file_tree.item(selected_item[0])
                if file_info['values']:
                    file_name = file_info['values'][5]
                    full_path = os.path.join(self.path_entry.get().strip(), file_name)
                    
                    if messagebox.askyesno("确认", f"确定要删除文件 {file_name} 吗？"):
                        result = ADBCommand.execute_command(f"shell rm {full_path}")
                        if "错误" not in result:
                            self.status_bar['text'] = "文件已删除"
                            self.list_files()  # 刷新文件列表
                        else:
                            messagebox.showerror("错误", f"删除文件失败: {result}")
        except Exception as e:
            logger.error(f"删除文件失败: {str(e)}")
    
    def on_device_selected(self, event):
        """设备选择事件处理"""
        selected_device = self.device_combo.get()
        if selected_device:
            self.current_device = selected_device
            self.refresh_device_info()
            self.status_bar['text'] = f'已选择设备: {selected_device}'
    
    def refresh_device_info(self):
        """刷新设备信息"""
        if not self.current_device:
            return
            
        info = []
        info.append(f"设备ID: {self.current_device}")
        info.append(f"Android版本: {ADBCommand.get_android_version()}")
        info.append(f"系统架构: {ADBCommand.get_abi()}")
        info.append(f"电池信息: {ADBCommand.get_battery_info()}")
        info.append(f"分辨率: {ADBCommand.get_display_info()}")
        info.append(f"IP地址: {ADBCommand.get_ip_address()}")
        
        self.device_info_text.delete('1.0', tk.END)
        self.device_info_text.insert('1.0', '\n'.join(info))

    def on_closing(self):
        """窗口关闭时的清理工作"""
        # 停止所有监控线程
        self.stop_monitoring()
        self.stop_log_monitoring()
        # 销毁窗口
        self.destroy()

    def _on_file_click(self, event):
        """处理文件点击事件"""
        try:
            # 获取点击位置对应的行
            index = self.file_tree.index("@%d,%d" % (event.x, event.y))
            # 设置当前行
            self.file_tree.mark_set("insert", index)
            # 清除之前的选择
            self.file_tree.tag_remove("sel", "1.0", "end")
            # 选择当前行
            self.file_tree.tag_add("sel", index + " linestart", index + " lineend")
        except Exception as e:
            logger.error(f"处理文件点击事件失败: {str(e)}")

    def toggle_packet_capture(self):
        """切换抓包状态"""
        if not self.capture_thread or not self.capture_thread.is_alive():
            self.start_packet_capture()
        else:
            self.stop_packet_capture()
            
    def start_packet_capture(self):
        """开始抓包"""
        if not self.capture_thread or not self.capture_thread.is_alive():
            self.capture_thread = PacketCaptureThread(self.update_packet_data)
            self.capture_thread.start()
            self.start_capture_btn['text'] = "停止抓包"
            self.save_capture_btn['state'] = 'normal'
            self.status_bar['text'] = "TCP抓包已启动"
            
    def stop_packet_capture(self):
        """停止抓包"""
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.stop()
            self.capture_thread.join()
            self.capture_thread = None
            self.start_capture_btn['text'] = "开始抓包"
            self.status_bar['text'] = "TCP抓包已停止"
            
    def update_packet_data(self, packet_info):
        """更新抓包数据显示
        Args:
            packet_info: 包含包信息的字典
        """
        try:
            self.packet_tree.insert("", 0, values=(
                packet_info['time'],
                packet_info['src'],
                packet_info['dst'],
                packet_info['flags'],
                packet_info['size']
            ))
        except Exception as e:
            logger.error(f"更新抓包数据失败: {str(e)}")
            
    def save_packet_capture(self):
        """保存抓包数据"""
        if not self.capture_thread:
            messagebox.showwarning("警告", "没有可保存的抓包数据")
            return
            
        try:
            filename = filedialog.asksaveasfilename(
                title="保存抓包数据",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if filename and self.capture_thread.save_packets(filename):
                self.status_bar['text'] = f"抓包数据已保存到: {filename}"
            else:
                self.status_bar['text'] = "保存抓包数据失败"
                
        except Exception as e:
            logger.error(f"保存抓包数据失败: {str(e)}")
            messagebox.showerror("错误", f"保存抓包数据失败: {str(e)}")

    def _on_file_double_click(self, event):
        """处理文件双击事件"""
        self._open_file()
        
    def _open_file(self):
        """打开/查看文件"""
        try:
            selected_item = self.file_tree.selection()
            if not selected_item:
                return
                
            file_info = self.file_tree.item(selected_item[0])
            if not file_info['values']:
                return
                
            perms = file_info['values'][0]
            file_name = file_info['values'][5]
            current_path = self.path_entry.get().strip().replace('\\', '/')
            remote_path = f"{current_path}/{file_name}"
            
            # 如果是目录
            if perms.startswith('d'):
                self.path_entry.delete(0, tk.END)
                self.path_entry.insert(0, remote_path)
                self.list_files()
                return
                
            # 如果是文件，先下载到临时目录
            temp_dir = os.path.join(os.environ.get('TEMP', '.'), 'android_debug_helper')
            os.makedirs(temp_dir, exist_ok=True)
            local_path = os.path.join(temp_dir, file_name)
            
            # 下载文件
            result = ADBCommand.pull_file(remote_path, local_path)
            if "error" in result.lower():
                raise Exception(result)
                
            # 使用系统默认程序打开文件
            os.startfile(local_path)
            
        except Exception as e:
            messagebox.showerror("错误", f"打开文件失败: {str(e)}")
            
    def _rename_file(self):
        """重命名文件"""
        try:
            selected_item = self.file_tree.selection()
            if not selected_item:
                return
                
            file_info = self.file_tree.item(selected_item[0])
            if not file_info['values']:
                return
                
            old_name = file_info['values'][5]
            current_path = self.path_entry.get().strip().replace('\\', '/')
            
            # 获取新文件名
            new_name = simpledialog.askstring(
                "重命名",
                "请输入新的文件名:",
                initialvalue=old_name
            )
            
            if not new_name or new_name == old_name:
                return
                
            # 执行重命名
            old_path = f"{current_path}/{old_name}"
            new_path = f"{current_path}/{new_name}"
            result = ADBCommand.execute_command(f'shell mv "{old_path}" "{new_path}"')
            
            if result and "error" not in result.lower():
                self.list_files()  # 刷新文件列表
                self.status_bar['text'] = "文件重命名成功"
            else:
                raise Exception(result)
                
        except Exception as e:
            messagebox.showerror("错误", f"重命名失败: {str(e)}")
            
    def _show_file_properties(self):
        """显示文件属性"""
        try:
            selected_item = self.file_tree.selection()
            if not selected_item:
                return
                
            file_info = self.file_tree.item(selected_item[0])
            if not file_info['values']:
                return
                
            # 获取文件信息
            perms, user, group, size, mod_time, name = file_info['values']
            current_path = self.path_entry.get().strip().replace('\\', '/')
            full_path = f"{current_path}/{name}"
            
            # 获取详细信息
            result = ADBCommand.execute_command(f'shell ls -l "{full_path}"')
            file_type = "目录" if perms.startswith('d') else "文件"
            
            # 创建属性对话框
            props_dialog = tk.Toplevel(self)
            props_dialog.title("文件属性")
            props_dialog.geometry("400x300")
            props_dialog.resizable(False, False)
            
            # 添加属性信息
            ttk.Label(props_dialog, text=f"名称: {name}").pack(anchor=tk.W, padx=10, pady=5)
            ttk.Label(props_dialog, text=f"类型: {file_type}").pack(anchor=tk.W, padx=10, pady=5)
            ttk.Label(props_dialog, text=f"位置: {current_path}").pack(anchor=tk.W, padx=10, pady=5)
            ttk.Label(props_dialog, text=f"大小: {size}").pack(anchor=tk.W, padx=10, pady=5)
            ttk.Label(props_dialog, text=f"修改时间: {mod_time}").pack(anchor=tk.W, padx=10, pady=5)
            ttk.Label(props_dialog, text=f"权限: {perms}").pack(anchor=tk.W, padx=10, pady=5)
            ttk.Label(props_dialog, text=f"所有者: {user}").pack(anchor=tk.W, padx=10, pady=5)
            ttk.Label(props_dialog, text=f"用户组: {group}").pack(anchor=tk.W, padx=10, pady=5)
            
            # 添加确定按钮
            ttk.Button(props_dialog, text="确定", command=props_dialog.destroy).pack(pady=10)
            
            # 设置模态对话框
            props_dialog.transient(self)
            props_dialog.grab_set()
            
        except Exception as e:
            messagebox.showerror("错误", f"获取文件属性失败: {str(e)}")

    def go_parent_dir(self):
        """返回上一级目录"""
        try:
            current_path = self.path_entry.get().strip().replace('\\', '/')
            
            # 如果已经是根目录，则不操作
            if current_path == "/" or current_path == "/sdcard":
                self.status_bar['text'] = "已经是根目录"
                return
                
            # 获取父目录路径
            parent_path = os.path.dirname(current_path)
            
            # 更新路径输入框
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, parent_path)
            
            # 刷新文件列表
            self.list_files()
            
            self.status_bar['text'] = f"已进入上级目录: {parent_path}"
            
        except Exception as e:
            logger.error(f"返回上级目录失败: {str(e)}")
            messagebox.showerror("错误", f"返回上级目录失败: {str(e)}")

    def _init_apk_page(self):
        """
        初始化APK分析页面
        """
        if not APKUTILS_AVAILABLE:
            logger.warning("apkutils2库未正确加载，APK分析功能将不可用")
            
        # 创建主框架
        main_frame = ttk.Frame(self.notebook)
        self.notebook.add(main_frame, text="APK分析")
        
        # 文件选择区域
        file_frame = ttk.LabelFrame(main_frame, text="APK文件选择", padding=5)
        file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 文件路径输入框和选择按钮
        path_frame = ttk.Frame(file_frame)
        path_frame.pack(fill=tk.X, expand=True)
        
        self.apk_path_entry = ttk.Entry(path_frame)
        self.apk_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        select_btn = ttk.Button(path_frame, text="选择APK", command=self.select_apk_file)
        select_btn.pack(side=tk.RIGHT)
        
        # 分析按钮区域
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 创建分析按钮
        ttk.Button(button_frame, text="基本信息", 
                   command=lambda: self.analyze_apk("basic")).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="权限列表", 
                   command=lambda: self.analyze_apk("permissions")).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="签名信息", 
                   command=lambda: self.analyze_apk("signature")).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="组件信息", 
                   command=lambda: self.analyze_apk("components")).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="资源列表", 
                   command=lambda: self.analyze_apk("resources")).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="清空结果", 
                   command=self.clear_apk_analysis).pack(side=tk.RIGHT)
        
        # 结果显示区域
        result_frame = ttk.LabelFrame(main_frame, text="分析结果", padding=5)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 创建文本显示区域和滚动条
        self.result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, 
                                                   width=80, height=20)
        self.result_text.pack(fill=tk.BOTH, expand=True)
        
        # 初始化变量
        self.apk_path = ""
        
    def clear_apk_analysis(self):
        """
        清空APK分析结果
        """
        try:
            self.result_text.delete(1.0, tk.END)
            self.status_bar.config(text="已清空分析结果")
        except Exception as e:
            error_msg = f"清空结果时发生错误: {str(e)}"
            logger.error(error_msg)
            messagebox.showerror("错误", error_msg)

class APKAnalyzer:
    """APK分析类"""
    
    @staticmethod
    def analyze_basic_info(apk_path):
        """分析APK基本信息"""
        try:
            apk = APK(apk_path)
            manifest = apk.get_manifest()
            info = {
                "包名": manifest.get("@package"),
                "版本名": manifest.get("@android:versionName"),
                "版本号": manifest.get("@android:versionCode"),
                "最小SDK版本": manifest.get("@android:minSdkVersion"),
                "目标SDK版本": manifest.get("@android:targetSdkVersion"),
                "应用名称": manifest.get("application", {}).get("@android:label")
            }
            return True, "基本信息分析成功", info
        except Exception as e:
            logger.error(f"分析APK基本信息失败: {str(e)}")
            return False, f"分析失败: {str(e)}", None

    @staticmethod
    def analyze_permissions(apk_path):
        """分析APK权限"""
        try:
            apk = APK(apk_path)
            manifest = apk.get_manifest()
            permissions = []
            if "uses-permission" in manifest:
                perms = manifest["uses-permission"]
                if isinstance(perms, list):
                    for perm in perms:
                        if isinstance(perm, dict) and "@android:name" in perm:
                            permissions.append(perm["@android:name"])
                elif isinstance(perms, dict) and "@android:name" in perms:
                    permissions.append(perms["@android:name"])
            return True, "权限分析成功", permissions
        except Exception as e:
            logger.error(f"分析APK权限失败: {str(e)}")
            return False, f"分析失败: {str(e)}", None

    @staticmethod
    def analyze_signature(apk_path):
        """分析APK签名信息"""
        try:
            apk = APK(apk_path)
            cert_data = apk.get_certs()
            if not cert_data:
                return False, "未找到签名信息", None
            
            cert_info = []
            for cert in cert_data:
                info = {
                    "序列号": cert.get("serial_number", "未知"),
                    "签发者": cert.get("issuer", {}).get("CN", "未知"),
                    "主题": cert.get("subject", {}).get("CN", "未知"),
                    "有效期开始": cert.get("not_before", "未知"),
                    "有效期结束": cert.get("not_after", "未知"),
                    "签名算法": cert.get("signature_algorithm", "未知")
                }
                cert_info.append(info)
            
            return True, "签名分析成功", cert_info
        except Exception as e:
            logger.error(f"分析APK签名失败: {str(e)}")
            return False, f"分析失败: {str(e)}", None

    @staticmethod
    def analyze_components(apk_path):
        """分析APK组件"""
        try:
            apk = APK(apk_path)
            manifest = apk.get_manifest()
            app_node = manifest.get("application", {})
            
            components = {
                "activities": [],
                "services": [],
                "receivers": [],
                "providers": []
            }
            
            # 解析Activities
            if "activity" in app_node:
                activities = app_node["activity"]
                if isinstance(activities, list):
                    for activity in activities:
                        if isinstance(activity, dict) and "@android:name" in activity:
                            components["activities"].append(activity["@android:name"])
                elif isinstance(activities, dict) and "@android:name" in activities:
                    components["activities"].append(activities["@android:name"])
            
            # 解析Services
            if "service" in app_node:
                services = app_node["service"]
                if isinstance(services, list):
                    for service in services:
                        if isinstance(service, dict) and "@android:name" in service:
                            components["services"].append(service["@android:name"])
                elif isinstance(services, dict) and "@android:name" in services:
                    components["services"].append(services["@android:name"])
            
            # 解析Receivers
            if "receiver" in app_node:
                receivers = app_node["receiver"]
                if isinstance(receivers, list):
                    for receiver in receivers:
                        if isinstance(receiver, dict) and "@android:name" in receiver:
                            components["receivers"].append(receiver["@android:name"])
                elif isinstance(receivers, dict) and "@android:name" in receivers:
                    components["receivers"].append(receivers["@android:name"])
            
            # 解析Providers
            if "provider" in app_node:
                providers = app_node["provider"]
                if isinstance(providers, list):
                    for provider in providers:
                        if isinstance(provider, dict) and "@android:name" in provider:
                            components["providers"].append(provider["@android:name"])
                elif isinstance(providers, dict) and "@android:name" in providers:
                    components["providers"].append(providers["@android:name"])
            
            return True, "组件分析成功", components
        except Exception as e:
            logger.error(f"分析APK组件失败: {str(e)}")
            return False, f"分析失败: {str(e)}", None

    @staticmethod
    def analyze_resources(apk_path):
        """分析APK资源"""
        try:
            apk = APK(apk_path)
            resources = {
                "文件列表": [],
                "资源统计": {}
            }
            
            # 获取APK中的所有文件
            with zipfile.ZipFile(apk_path, 'r') as z:
                for file_info in z.filelist:
                    resources["文件列表"].append({
                        "文件名": file_info.filename,
                        "大小": file_info.file_size,
                        "压缩大小": file_info.compress_size,
                        "修改时间": datetime.fromtimestamp(time.mktime(file_info.date_time + (0, 0, -1))).strftime("%Y-%m-%d %H:%M:%S")
                    })
                    
                    # 统计不同类型的资源数量
                    ext = os.path.splitext(file_info.filename)[1].lower()
                    if ext:
                        resources["资源统计"][ext] = resources["资源统计"].get(ext, 0) + 1
            
            return True, "资源分析成功", resources
        except Exception as e:
            logger.error(f"分析APK资源失败: {str(e)}")
            return False, f"分析失败: {str(e)}", None

def main():
    """主函数"""
    window = MainWindow()
    window.mainloop()

if __name__ == '__main__':
    main() 