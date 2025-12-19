#!/usr/bin/env python3
"""
NGE2 汉化工具 GUI 启动脚本
直接运行此文件即可启动图形界面
"""

import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.gui.main import main

if __name__ == "__main__":
    main()
