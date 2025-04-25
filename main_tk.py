#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Android调试工具GUI实现
使用tkinter构建图形界面,提供设备管理、应用管理、性能监控等功能
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import time
import json
import os
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from scapy.all import *
from loguru import logger
import subprocess

class ADBCommand:
    """ADB命令执行类"""
    
    def __init__(self):
        """初始化ADB命令执行环境"""
        self.adb_path = "adb"
        
    def execute_command(self, command):
        """
        执行ADB命令
        :param command: ADB命令
        :return: 命令执行结果
        """
        try:
            result = subprocess.check_output(f"{self.adb_path} {command}", shell=True)
            return result.decode('utf-8').strip()
        except subprocess.CalledProcessError as e:
            logger.error(f"执行ADB命令失败: {e}")
            return None
            
    def connect_device(self, address):
        """
        连接设备
        :param address: 设备地址(ip:port)
        :return: 连接结果
        """
        result = self.execute_command(f"connect {address}")
        return result and "connected" in result.lower()
        
    def disconnect_device(self, address=None):
        """
        断开设备连接
        :param address: 设备地址,为None时断开所有设备
        :return: 断开结果
        """
        if address:
            result = self.execute_command(f"disconnect {address}")
        else:
            result = self.execute_command("disconnect")
        return result is not None
        
    def get_device_state(self, device_id):
        """
        获取设备状态
        :param device_id: 设备ID
        :return: 设备状态
        """
        result = self.execute_command("devices -l")
        if result:
            for line in result.split('\n'):
                if device_id in line:
                    if "offline" in line:
                        return "离线"
                    elif "device" in line:
                        return "在线"
                    elif "unauthorized" in line:
                        return "未授权"
        return "未连接"
        
    def get_device_list(self):
        """
        获取已连接设备列表
        :return: 设备列表
        """
        devices = []
        result = self.execute_command("devices")
        if result:
            lines = result.split('\n')[1:]
            for line in lines:
                if line.strip():
                    device_id = line.split('\t')[0]
                    devices.append(device_id)
        return devices
        
    def get_device_info(self, device_id):
        """
        获取设备详细信息
        :param device_id: 设备ID
        :return: 设备信息字典
        """
        info = {}
        try:
            # 获取设备型号
            model = self.execute_command(f"-s {device_id} shell getprop ro.product.model")
            info['model'] = model if model else "未知"
            
            # 获取Android版本
            android_ver = self.execute_command(f"-s {device_id} shell getprop ro.build.version.release")
            info['android_version'] = android_ver if android_ver else "未知"
            
            # 获取系统版本号
            build_num = self.execute_command(f"-s {device_id} shell getprop ro.build.display.id")
            info['build_number'] = build_num if build_num else "未知"
            
            # 获取设备序列号
            serial = self.execute_command(f"-s {device_id} shell getprop ro.serialno")
            info['serial'] = serial if serial else "未知"
            
            # 获取CPU信息
            cpu_info = self.execute_command(f"-s {device_id} shell cat /proc/cpuinfo")
            info['cpu_info'] = cpu_info if cpu_info else "未知"
            
            # 获取内存信息
            mem_info = self.execute_command(f"-s {device_id} shell cat /proc/meminfo")
            info['mem_info'] = mem_info if mem_info else "未知"
            
        except Exception as e:
            logger.error(f"获取设备信息失败: {e}")
            
        return info
        
    def get_installed_packages(self, device_id):
        """
        获取已安装应用列表
        :param device_id: 设备ID
        :return: 应用包名列表
        """
        packages = []
        result = self.execute_command(f"-s {device_id} shell pm list packages")
        if result:
            for line in result.split('\n'):
                if line.startswith('package:'):
                    packages.append(line.split('package:')[1].strip())
        return packages
        
    def install_apk(self, device_id, apk_path):
        """
        安装APK
        :param device_id: 设备ID
        :param apk_path: APK文件路径
        :return: 安装结果
        """
        return self.execute_command(f"-s {device_id} install {apk_path}")
        
    def uninstall_package(self, device_id, package_name):
        """
        卸载应用
        :param device_id: 设备ID
        :param package_name: 应用包名
        :return: 卸载结果
        """
        return self.execute_command(f"-s {device_id} uninstall {package_name}")
        
    def start_app(self, device_id, package_name):
        """
        启动应用
        :param device_id: 设备ID
        :param package_name: 应用包名
        :return: 启动结果
        """
        return self.execute_command(f"-s {device_id} shell monkey -p {package_name} -c android.intent.category.LAUNCHER 1")
        
    def stop_app(self, device_id, package_name):
        """
        停止应用
        :param device_id: 设备ID
        :param package_name: 应用包名
        :return: 停止结果
        """
        return self.execute_command(f"-s {device_id} shell am force-stop {package_name}")
        
    def clear_app_data(self, device_id, package_name):
        """
        清除应用数据
        :param device_id: 设备ID
        :param package_name: 应用包名
        :return: 清除结果
        """
        return self.execute_command(f"-s {device_id} shell pm clear {package_name}")
        
    def pull_file(self, device_id, remote_path, local_path):
        """
        从设备拉取文件
        :param device_id: 设备ID
        :param remote_path: 设备上的文件路径
        :param local_path: 本地保存路径
        :return: 拉取结果
        """
        return self.execute_command(f"-s {device_id} pull {remote_path} {local_path}")
        
    def push_file(self, device_id, local_path, remote_path):
        """
        推送文件到设备
        :param device_id: 设备ID
        :param local_path: 本地文件路径
        :param remote_path: 设备上的保存路径
        :return: 推送结果
        """
        return self.execute_command(f"-s {device_id} push {local_path} {remote_path}")
        
    def list_files(self, device_id, remote_path):
        """
        列出设备上的文件
        :param device_id: 设备ID
        :param remote_path: 设备上的目录路径
        :return: 文件列表
        """
        return self.execute_command(f"-s {device_id} shell ls -l {remote_path}")
        
    def reboot_device(self, device_id):
        """
        重启设备
        :param device_id: 设备ID
        :return: 重启结果
        """
        return self.execute_command(f"-s {device_id} reboot")
        
    def get_device_ip(self, device_id):
        """
        获取设备IP地址
        :param device_id: 设备ID
        :return: IP地址
        """
        result = self.execute_command(f"-s {device_id} shell ip route")
        if result:
            for line in result.split('\n'):
                if 'wlan0' in line and 'src' in line:
                    return line.split('src')[1].strip()
        return None
        
    def get_screen_resolution(self, device_id):
        """
        获取屏幕分辨率
        :param device_id: 设备ID
        :return: 分辨率信息
        """
        result = self.execute_command(f"-s {device_id} shell wm size")
        if result:
            return result.split('Physical size:')[1].strip()
        return None
        
    def get_device_logs(self, device_id):
        """
        获取设备日志
        :param device_id: 设备ID
        :return: 日志内容
        """
        return self.execute_command(f"-s {device_id} logcat -d")
        
    def clear_device_logs(self, device_id):
        """
        清除设备日志
        :param device_id: 设备ID
        :return: 清除结果
        """
        return self.execute_command(f"-s {device_id} logcat -c")

class PacketCaptureThread(threading.Thread):
    """数据包捕获线程类"""
    
    def __init__(self, callback, filter_str=""):
        """
        初始化数据包捕获线程
        :param callback: 数据包处理回调函数
        :param filter_str: 数据包过滤规则
        """
        super().__init__()
        self.callback = callback
        self.filter_str = filter_str
        self.running = False
        
    def run(self):
        """运行数据包捕获"""
        self.running = True
        try:
            sniff(filter=self.filter_str, prn=self.callback, store=0, stop_filter=lambda _: not self.running)
        except Exception as e:
            logger.error(f"数据包捕获失败: {e}")
            
    def stop(self):
        """停止数据包捕获"""
        self.running = False

class PerformanceMonitor:
    """性能监控类"""
    
    def __init__(self, device_id):
        """
        初始化性能监控
        :param device_id: 设备ID
        """
        self.device_id = device_id
        self.adb = ADBCommand()
        self.running = False
        
    def get_cpu_usage(self):
        """获取CPU使用率"""
        result = self.adb.execute_command(f"-s {self.device_id} shell top -n 1")
        # 解析CPU使用率
        return result
        
    def get_memory_info(self):
        """获取内存使用情况"""
        result = self.adb.execute_command(f"-s {self.device_id} shell dumpsys meminfo")
        # 解析内存信息
        return result
        
    def get_battery_info(self):
        """获取电池信息"""
        result = self.adb.execute_command(f"-s {self.device_id} shell dumpsys battery")
        # 解析电池信息
        return result

class AndroidDebuggerGUI:
    """Android调试工具GUI类"""
    
    def __init__(self):
        """初始化GUI"""
        self.root = tk.Tk()
        self.root.title("Android调试工具")
        self.root.geometry("800x600")
        
        # 创建标签页
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both')
        
        # 设备管理页
        self.device_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.device_frame, text='设备管理')
        self.init_device_frame()
        
        # 应用管理页
        self.app_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.app_frame, text='应用管理')
        self.init_app_frame()
        
        # 性能监控页
        self.perf_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.perf_frame, text='性能监控')
        self.init_perf_frame()
        
        # 文件管理页
        self.file_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.file_frame, text='文件管理')
        self.init_file_frame()
        
        # 抓包分析页
        self.packet_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.packet_frame, text='抓包分析')
        self.init_packet_frame()
        
        # 初始化ADB命令执行器
        self.adb = ADBCommand()
        
        # 初始化性能监控器
        self.perf_monitor = None
        
        # 初始化数据包捕获线程
        self.packet_capture = None
        
    def init_device_frame(self):
        """初始化设备管理页面"""
        # 左侧设备列表面板
        left_panel = ttk.Frame(self.device_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 设备列表
        list_frame = ttk.LabelFrame(left_panel, text="设备列表")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 设备列表(使用Treeview替换Listbox以显示更多信息)
        self.device_list = ttk.Treeview(list_frame, columns=("device", "status"), show="headings")
        self.device_list.heading("device", text="设备ID")
        self.device_list.heading("status", text="状态")
        self.device_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.device_list.bind('<<TreeviewSelect>>', self.on_device_selected)
        
        # 滚动条
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.device_list.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.device_list.yview)
        
        # 连接控制面板
        conn_frame = ttk.LabelFrame(left_panel, text="连接控制")
        conn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # IP地址输入框
        ip_frame = ttk.Frame(conn_frame)
        ip_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(ip_frame, text="IP地址:").pack(side=tk.LEFT)
        self.ip_entry = ttk.Entry(ip_frame)
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        ttk.Label(ip_frame, text="端口:").pack(side=tk.LEFT)
        self.port_entry = ttk.Entry(ip_frame, width=8)
        self.port_entry.insert(0, "5555")  # 默认端口
        self.port_entry.pack(side=tk.LEFT, padx=5)
        
        # 连接按钮
        btn_frame = ttk.Frame(conn_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        connect_btn = ttk.Button(btn_frame, text="连接设备",
                               command=self.connect_device)
        connect_btn.pack(side=tk.LEFT, padx=5)
        
        disconnect_btn = ttk.Button(btn_frame, text="断开设备",
                                  command=self.disconnect_device)
        disconnect_btn.pack(side=tk.LEFT, padx=5)
        
        refresh_btn = ttk.Button(btn_frame, text="刷新设备列表", 
                               command=self.refresh_device_list)
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
        # 状态栏
        self.status_label = ttk.Label(left_panel, text="就绪", relief=tk.SUNKEN)
        self.status_label.pack(fill=tk.X, padx=5, pady=5)
        
        # 右侧设备信息面板
        right_panel = ttk.Frame(self.device_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # 设备信息显示
        info_frame = ttk.LabelFrame(right_panel, text="设备信息")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.device_info = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD)
        self.device_info.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 日志操作区域
        log_frame = ttk.LabelFrame(right_panel, text="设备日志")
        log_frame.pack(fill=tk.X, padx=5, pady=5)
        
        get_log_btn = ttk.Button(log_frame, text="获取日志",
                               command=self.get_device_logs)
        get_log_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        clear_log_btn = ttk.Button(log_frame, text="清除日志",
                                command=self.clear_device_logs)
        clear_log_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        # 启动设备状态监控
        self.start_device_monitor()
        
    def init_app_frame(self):
        """初始化应用管理页面"""
        # 左侧应用列表面板
        left_panel = ttk.Frame(self.app_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 应用列表
        list_frame = ttk.LabelFrame(left_panel, text="已安装应用")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.app_list = ttk.Treeview(list_frame, columns=("package",), show="headings")
        self.app_list.heading("package", text="包名")
        self.app_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 滚动条
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.app_list.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.app_list.yview)
        
        # 右侧操作面板
        right_panel = ttk.Frame(self.app_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 应用操作区域
        op_frame = ttk.LabelFrame(right_panel, text="应用操作")
        op_frame.pack(fill=tk.X, padx=5, pady=5)
        
        install_btn = ttk.Button(op_frame, text="安装应用", 
                               command=self.install_app)
        install_btn.pack(fill=tk.X, padx=5, pady=5)
        
        uninstall_btn = ttk.Button(op_frame, text="卸载应用",
                                 command=self.uninstall_app)
        uninstall_btn.pack(fill=tk.X, padx=5, pady=5)
        
        start_btn = ttk.Button(op_frame, text="启动应用",
                             command=self.start_app)
        start_btn.pack(fill=tk.X, padx=5, pady=5)
        
        stop_btn = ttk.Button(op_frame, text="停止应用",
                            command=self.stop_app)
        stop_btn.pack(fill=tk.X, padx=5, pady=5)
        
        clear_btn = ttk.Button(op_frame, text="清除数据",
                             command=self.clear_app_data)
        clear_btn.pack(fill=tk.X, padx=5, pady=5)
        
        # 刷新按钮
        refresh_btn = ttk.Button(right_panel, text="刷新应用列表",
                               command=self.refresh_app_list)
        refresh_btn.pack(fill=tk.X, padx=5, pady=5)
        
    def init_perf_frame(self):
        """初始化性能监控页面"""
        # 性能图表区域
        self.fig = plt.Figure(figsize=(6, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.perf_frame)
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        
        # 控制按钮
        btn_frame = ttk.Frame(self.perf_frame)
        btn_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        start_btn = ttk.Button(btn_frame, text="开始监控",
                             command=self.start_monitoring)
        start_btn.pack(side=tk.LEFT, padx=5)
        
        stop_btn = ttk.Button(btn_frame, text="停止监控",
                            command=self.stop_monitoring)
        stop_btn.pack(side=tk.LEFT, padx=5)
        
    def init_file_frame(self):
        """初始化文件管理页面"""
        # 文件列表
        self.file_list = tk.Listbox(self.file_frame)
        self.file_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 按钮区域
        btn_frame = ttk.Frame(self.file_frame)
        btn_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        pull_btn = ttk.Button(btn_frame, text="拉取文件",
                            command=self.pull_file)
        pull_btn.pack(side=tk.TOP, pady=5)
        
        push_btn = ttk.Button(btn_frame, text="推送文件",
                            command=self.push_file)
        push_btn.pack(side=tk.TOP, pady=5)
        
    def init_packet_frame(self):
        """初始化抓包分析页面"""
        # 数据包列表
        self.packet_list = tk.Listbox(self.packet_frame)
        self.packet_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 控制区域
        ctrl_frame = ttk.Frame(self.packet_frame)
        ctrl_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 过滤规则输入
        filter_label = ttk.Label(ctrl_frame, text="过滤规则:")
        filter_label.pack(side=tk.TOP, pady=5)
        
        self.filter_entry = ttk.Entry(ctrl_frame)
        self.filter_entry.pack(side=tk.TOP, pady=5)
        
        # 控制按钮
        start_btn = ttk.Button(ctrl_frame, text="开始捕获",
                             command=self.start_capture)
        start_btn.pack(side=tk.TOP, pady=5)
        
        stop_btn = ttk.Button(ctrl_frame, text="停止捕获",
                            command=self.stop_capture)
        stop_btn.pack(side=tk.TOP, pady=5)
        
    def connect_device(self):
        """连接设备"""
        ip = self.ip_entry.get().strip()
        port = self.port_entry.get().strip()
        
        if not ip:
            messagebox.showwarning("警告", "请输入IP地址")
            return
            
        if not port:
            port = "5555"
            
        address = f"{ip}:{port}"
        self.status_label.config(text=f"正在连接设备 {address}...")
        
        if self.adb.connect_device(address):
            self.status_label.config(text=f"设备 {address} 连接成功")
            self.refresh_device_list()
        else:
            self.status_label.config(text=f"设备 {address} 连接失败")
            messagebox.showerror("错误", f"无法连接到设备 {address}")
            
    def disconnect_device(self):
        """断开设备连接"""
        selection = self.device_list.selection()
        if not selection:
            # 断开所有设备
            if messagebox.askyesno("确认", "确定要断开所有设备吗?"):
                if self.adb.disconnect_device():
                    self.status_label.config(text="已断开所有设备")
                    self.refresh_device_list()
                else:
                    self.status_label.config(text="断开设备失败")
        else:
            # 断开选中的设备
            device_id = self.device_list.item(selection[0])["values"][0]
            if messagebox.askyesno("确认", f"确定要断开设备 {device_id} 吗?"):
                if self.adb.disconnect_device(device_id):
                    self.status_label.config(text=f"已断开设备 {device_id}")
                    self.refresh_device_list()
                else:
                    self.status_label.config(text=f"断开设备 {device_id} 失败")
                    
    def refresh_device_list(self):
        """刷新设备列表"""
        # 清空列表
        for item in self.device_list.get_children():
            self.device_list.delete(item)
            
        # 获取并显示设备列表
        devices = self.adb.get_device_list()
        for device in devices:
            state = self.adb.get_device_state(device)
            self.device_list.insert("", tk.END, values=(device, state))
            
        self.status_label.config(text=f"找到 {len(devices)} 个设备")
        
    def start_device_monitor(self):
        """启动设备状态监控"""
        def monitor_thread():
            while True:
                # 获取当前显示的设备列表
                current_devices = {}
                for item in self.device_list.get_children():
                    values = self.device_list.item(item)["values"]
                    current_devices[values[0]] = values[1]
                    
                # 获取最新的设备列表
                devices = self.adb.get_device_list()
                device_states = {device: self.adb.get_device_state(device) for device in devices}
                
                # 检查设备状态变化
                need_refresh = False
                for device, state in device_states.items():
                    if device not in current_devices:
                        # 新设备连接
                        need_refresh = True
                        break
                    if current_devices[device] != state:
                        # 设备状态改变
                        need_refresh = True
                        break
                        
                for device in current_devices:
                    if device not in device_states:
                        # 设备断开
                        need_refresh = True
                        break
                        
                # 如果有变化则刷新列表
                if need_refresh:
                    self.root.after(0, self.refresh_device_list)
                    
                time.sleep(2)  # 每2秒检查一次
                
        # 启动监控线程
        threading.Thread(target=monitor_thread, daemon=True).start()
        
    def refresh_app_list(self):
        """刷新应用列表"""
        selection = self.device_list.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        device_id = self.device_list.item(selection[0])["values"][0]
        
        # 清空列表
        for item in self.app_list.get_children():
            self.app_list.delete(item)
            
        # 获取并显示应用列表
        packages = self.adb.get_installed_packages(device_id)
        for package in packages:
            self.app_list.insert("", tk.END, values=(package,))
            
    def install_app(self):
        """安装应用"""
        if not self.device_list.curselection():
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        device_id = self.device_list.get(self.device_list.curselection())
        
        # 选择APK文件
        apk_path = filedialog.askopenfilename(
            title="选择APK文件",
            filetypes=[("APK文件", "*.apk")]
        )
        
        if not apk_path:
            return
            
        # 显示进度窗口
        progress_window = tk.Toplevel(self.root)
        progress_window.title("安装进度")
        progress_window.geometry("300x100")
        
        label = ttk.Label(progress_window, text="正在安装应用...")
        label.pack(pady=10)
        
        progress = ttk.Progressbar(progress_window, mode='indeterminate')
        progress.pack(fill=tk.X, padx=20)
        progress.start()
        
        def install_thread():
            result = self.adb.install_apk(device_id, apk_path)
            progress_window.destroy()
            
            if result and "Success" in result:
                messagebox.showinfo("成功", "应用安装成功")
                self.refresh_app_list()
            else:
                messagebox.showerror("错误", f"应用安装失败: {result}")
                
        threading.Thread(target=install_thread).start()
        
    def uninstall_app(self):
        """卸载应用"""
        if not self.device_list.curselection():
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        selection = self.app_list.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择要卸载的应用")
            return
            
        device_id = self.device_list.get(self.device_list.curselection())
        package = self.app_list.item(selection[0])["values"][0]
        
        if messagebox.askyesno("确认", f"确定要卸载应用 {package} 吗?"):
            result = self.adb.uninstall_package(device_id, package)
            if result and "Success" in result:
                messagebox.showinfo("成功", "应用卸载成功")
                self.refresh_app_list()
            else:
                messagebox.showerror("错误", f"应用卸载失败: {result}")
                
    def start_app(self):
        """启动应用"""
        if not self.device_list.curselection():
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        selection = self.app_list.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择要启动的应用")
            return
            
        device_id = self.device_list.get(self.device_list.curselection())
        package = self.app_list.item(selection[0])["values"][0]
        
        result = self.adb.start_app(device_id, package)
        if result is None:
            messagebox.showerror("错误", "应用启动失败")
        else:
            messagebox.showinfo("成功", "应用已启动")
            
    def stop_app(self):
        """停止应用"""
        if not self.device_list.curselection():
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        selection = self.app_list.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择要停止的应用")
            return
            
        device_id = self.device_list.get(self.device_list.curselection())
        package = self.app_list.item(selection[0])["values"][0]
        
        result = self.adb.stop_app(device_id, package)
        if result is None:
            messagebox.showerror("错误", "应用停止失败")
        else:
            messagebox.showinfo("成功", "应用已停止")
            
    def clear_app_data(self):
        """清除应用数据"""
        if not self.device_list.curselection():
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        selection = self.app_list.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择要清除数据的应用")
            return
            
        device_id = self.device_list.get(self.device_list.curselection())
        package = self.app_list.item(selection[0])["values"][0]
        
        if messagebox.askyesno("确认", f"确定要清除应用 {package} 的数据吗?"):
            result = self.adb.clear_app_data(device_id, package)
            if result is None:
                messagebox.showerror("错误", "清除应用数据失败")
            else:
                messagebox.showinfo("成功", "应用数据已清除")
        
    def start_monitoring(self):
        """开始性能监控"""
        selection = self.device_list.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        device_id = self.device_list.item(selection[0])["values"][0]
        self.perf_monitor = PerformanceMonitor(device_id)
        # 启动性能监控线程
        
    def stop_monitoring(self):
        """停止性能监控"""
        if self.perf_monitor:
            # 停止性能监控线程
            self.perf_monitor = None
            
    def pull_file(self):
        """从设备拉取文件"""
        # 实现文件拉取逻辑
        pass
        
    def push_file(self):
        """向设备推送文件"""
        # 实现文件推送逻辑
        pass
        
    def start_capture(self):
        """开始数据包捕获"""
        filter_str = self.filter_entry.get()
        self.packet_capture = PacketCaptureThread(self.packet_callback, filter_str)
        self.packet_capture.start()
        
    def stop_capture(self):
        """停止数据包捕获"""
        if self.packet_capture:
            self.packet_capture.stop()
            self.packet_capture = None
            
    def packet_callback(self, packet):
        """
        数据包处理回调
        :param packet: 捕获的数据包
        """
        # 解析并显示数据包信息
        packet_info = packet.summary()
        self.packet_list.insert(tk.END, packet_info)
        
    def on_device_selected(self, event):
        """设备选择事件处理"""
        selection = self.device_list.selection()
        if not selection:
            return
            
        device_id = self.device_list.item(selection[0])["values"][0]
        self.show_device_info(device_id)
        
    def show_device_info(self, device_id):
        """显示设备信息"""
        info = self.adb.get_device_info(device_id)
        
        # 清空显示
        self.device_info.delete(1.0, tk.END)
        
        # 显示基本信息
        self.device_info.insert(tk.END, f"设备ID: {device_id}\n\n")
        self.device_info.insert(tk.END, f"型号: {info.get('model', '未知')}\n")
        self.device_info.insert(tk.END, f"Android版本: {info.get('android_version', '未知')}\n")
        self.device_info.insert(tk.END, f"系统版本: {info.get('build_number', '未知')}\n")
        self.device_info.insert(tk.END, f"序列号: {info.get('serial', '未知')}\n\n")
        
        # 显示IP地址
        ip = self.adb.get_device_ip(device_id)
        self.device_info.insert(tk.END, f"IP地址: {ip if ip else '未知'}\n")
        
        # 显示屏幕分辨率
        resolution = self.adb.get_screen_resolution(device_id)
        self.device_info.insert(tk.END, f"屏幕分辨率: {resolution if resolution else '未知'}\n\n")
        
        # 显示CPU信息
        self.device_info.insert(tk.END, "CPU信息:\n")
        self.device_info.insert(tk.END, f"{info.get('cpu_info', '未知')}\n\n")
        
        # 显示内存信息
        self.device_info.insert(tk.END, "内存信息:\n")
        self.device_info.insert(tk.END, f"{info.get('mem_info', '未知')}\n")
        
    def get_device_logs(self):
        """获取设备日志"""
        selection = self.device_list.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        device_id = self.device_list.item(selection[0])["values"][0]
        logs = self.adb.get_device_logs(device_id)
        
        # 创建新窗口显示日志
        log_window = tk.Toplevel(self.root)
        log_window.title("设备日志")
        log_window.geometry("800x600")
        
        # 日志文本框
        log_text = scrolledtext.ScrolledText(log_window, wrap=tk.WORD)
        log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 显示日志内容
        if logs:
            log_text.insert(tk.END, logs)
        else:
            log_text.insert(tk.END, "获取日志失败")
            
    def clear_device_logs(self):
        """清除设备日志"""
        selection = self.device_list.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择设备")
            return
            
        device_id = self.device_list.item(selection[0])["values"][0]
        result = self.adb.clear_device_logs(device_id)
        
        if result is None:
            messagebox.showerror("错误", "清除日志失败")
        else:
            messagebox.showinfo("成功", "设备日志已清除")
        
    def run(self):
        """运行GUI"""
        self.root.mainloop()

if __name__ == "__main__":
    # 配置日志
    logger.add("debug.log", rotation="500 MB")
    
    # 启动GUI
    app = AndroidDebuggerGUI()
    app.run() 