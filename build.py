#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
打包脚本
用于将Android调试助手打包成exe文件
"""

import os
import PyInstaller.__main__

# 定义图标文件路径
icon_path = os.path.join(os.path.dirname(__file__), 'app.ico')

# 定义打包参数
params = [
    'main.py',  # 主程序文件
    '--name=Android调试助手',  # 生成的exe名称
    '--windowed',  # 使用GUI模式
    '--onefile',  # 打包成单个文件
    f'--icon={icon_path}',  # 设置图标
    '--clean',  # 清理临时文件
    '--noconfirm',  # 不确认覆盖
    # 添加所需的依赖
    '--hidden-import=tkinter',
    '--hidden-import=adbutils',
    '--hidden-import=loguru',
    '--hidden-import=scapy',
]

# 执行打包
PyInstaller.__main__.run(params) 