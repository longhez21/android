#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
创建应用图标
"""

from PIL import Image, ImageDraw, ImageFont

def create_app_icon():
    # 创建一个256x256的图像，使用RGBA模式支持透明度
    size = 256
    image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    
    # 绘制圆形背景
    margin = 10
    draw.ellipse([margin, margin, size-margin, size-margin], 
                 fill='#4CAF50')  # 使用Material Design绿色
    
    # 绘制"ADB"文字
    try:
        # 尝试加载系统字体
        font = ImageFont.truetype("arial.ttf", 80)
    except:
        # 如果找不到指定字体，使用默认字体
        font = ImageFont.load_default()
        
    text = "ADB"
    # 获取文字大小
    text_bbox = draw.textbbox((0, 0), text, font=font)
    text_width = text_bbox[2] - text_bbox[0]
    text_height = text_bbox[3] - text_bbox[1]
    
    # 计算文字位置，使其居中
    x = (size - text_width) // 2
    y = (size - text_height) // 2
    
    # 绘制文字
    draw.text((x, y), text, fill='white', font=font)
    
    # 保存为ICO文件
    image.save('app.ico', format='ICO', sizes=[(256, 256)])

if __name__ == '__main__':
    create_app_icon() 