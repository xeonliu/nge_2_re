"""
简化的工作流程
将常见的多步操作封装成单一函数，减少用户交互次数
"""

import os
from pathlib import Path
from typing import Optional, Callable
from app.cli.main import App
from scripts.paratranz.download import download_function, merge_function


class Workflows:
    """简化的工作流程集合"""
    
    # 预定义的路径常量
    TEMP_DIR = Path("temp")
    DOWNLOAD_DIR = TEMP_DIR / "downloads"
    BUILD_DIR = Path("build")
    EXPORT_GAME_DIR = BUILD_DIR / "ULJS00064" / "PSP_GAME"
    EXPORT_USRDIR = EXPORT_GAME_DIR / "USRDIR"
    PSP_GAME_DIR = TEMP_DIR / "ULJS00064" / "PSP_GAME"
    USRDIR = PSP_GAME_DIR / "USRDIR"
    
    # HGAR 目录列表
    HGAR_DIRS = ['btdemo', 'btface', 'btl', 'chara', 'event', 'face', 'free', 'game', 'im', 'map']
    
    def __init__(self, logger: Optional[Callable] = None):
        """
        初始化工作流
        
        Args:
            logger: 日志函数，用于输出进度信息
        """
        self.logger = logger or print
    
    def log(self, message: str):
        """输出日志"""
        self.logger(message)
    
    def download_translations(self, token: str):
        """
        从 Paratranz 下载并预处理翻译文件
        
        Args:
            token: Paratranz API Token
        """
        self.log("=" * 60 + "\n")
        self.log("开始下载翻译文件...\n")
        self.log("=" * 60 + "\n")
        
        # 确保下载目录存在
        self.DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
        
        # 下载文件
        self.log("\n【1/2】从 Paratranz 下载文件...\n")
        download_function(token, str(self.DOWNLOAD_DIR))
        
        # 合并处理
        self.log("\n【2/2】合并和预处理翻译文件...\n")
        merge_function(str(self.DOWNLOAD_DIR))
        
        self.log("\n" + "=" * 60 + "\n")
        self.log(f"✓ 翻译文件已下载到: {self.DOWNLOAD_DIR}\n")
        self.log("=" * 60 + "\n")
    
    def import_all_from_game(self):
        """
        从游戏文件导入所有资源
        前提：游戏ISO已经解压到 temp/ULJS00064 目录
        """
        self.log("=" * 60 + "\n")
        self.log("开始导入所有游戏资源...\n")
        self.log("=" * 60 + "\n")
        
        # 检查游戏目录是否存在
        if not self.USRDIR.exists():
            raise FileNotFoundError(
                f"游戏目录不存在: {self.USRDIR}\n"
                f"请先将游戏ISO解压到 {self.PSP_GAME_DIR.parent} 目录"
            )
        
        # 1. 导入所有 HGAR 目录
        self.log("\n【1/4】导入 HGAR 文件...\n")
        for i, dir_name in enumerate(self.HGAR_DIRS, 1):
            hgar_path = self.USRDIR / dir_name
            if hgar_path.exists():
                self.log(f"  [{i}/{len(self.HGAR_DIRS)}] 导入 {dir_name}...\n")
                App.import_har(str(hgar_path))
            else:
                self.log(f"  [{i}/{len(self.HGAR_DIRS)}] 跳过 {dir_name} (目录不存在)\n")
        
        # 2. 导入 TEXT 文件
        self.log("\n【2/4】导入 TEXT 文件...\n")
        text_files = [
            self.USRDIR / 'free' / 'f2info.bin',
            self.USRDIR / 'free' / 'f2tuto.bin'
        ]
        for i, text_file in enumerate(text_files, 1):
            if text_file.exists():
                self.log(f"  [{i}/{len(text_files)}] 导入 {text_file.name}...\n")
                App.import_text(str(text_file))
            else:
                self.log(f"  [{i}/{len(text_files)}] 跳过 {text_file.name} (文件不存在)\n")
        
        # 3. 导入 BIND 文件
        self.log("\n【3/4】导入 BIND 文件...\n")
        bind_files = [
            self.USRDIR / 'btl' / 'btimtext.bin',
            self.USRDIR / 'game' / 'imtext.bin'
        ]
        for i, bind_file in enumerate(bind_files, 1):
            if bind_file.exists():
                self.log(f"  [{i}/{len(bind_files)}] 导入 {bind_file.name}...\n")
                App.import_bind(str(bind_file))
            else:
                self.log(f"  [{i}/{len(bind_files)}] 跳过 {bind_file.name} (文件不存在)\n")
        
        # 4. 导入翻译图像（如果存在）
        self.log("\n【4/4】导入翻译图像...\n")
        trans_pic_dir = Path('resources/trans_pic/trans')
        if trans_pic_dir.exists():
            self.log(f"  从 {trans_pic_dir} 导入图像...\n")
            App.import_images(str(trans_pic_dir))
        else:
            self.log(f"  跳过图像导入 (目录不存在: {trans_pic_dir})\n")
        
        self.log("\n" + "=" * 60 + "\n")
        self.log("✓ 所有游戏资源导入完成！\n")
        self.log("=" * 60 + "\n")
    
    def import_all_translations(self):
        """
        导入所有翻译文件
        前提：翻译文件已下载到 temp/downloads 目录
        """
        self.log("=" * 60 + "\n")
        self.log("开始导入所有翻译...\n")
        self.log("=" * 60 + "\n")
        
        # 检查下载目录是否存在
        if not self.DOWNLOAD_DIR.exists():
            raise FileNotFoundError(
                f"翻译下载目录不存在: {self.DOWNLOAD_DIR}\n"
                f"请先下载翻译文件"
            )
        
        # 翻译文件列表
        translation_files = [
            self.DOWNLOAD_DIR / 'evs_trans.json',
            self.DOWNLOAD_DIR / 'utf8' / 'free' / 'info.json',
            self.DOWNLOAD_DIR / 'utf8' / 'free' / 'tuto.json',
            self.DOWNLOAD_DIR / 'utf8' / 'game' / 'btimtext.json',
            self.DOWNLOAD_DIR / 'utf8' / 'game' / 'imtext.json',
        ]
        
        total = len(translation_files)
        for i, trans_file in enumerate(translation_files, 1):
            if trans_file.exists():
                self.log(f"[{i}/{total}] 导入 {trans_file.relative_to(self.DOWNLOAD_DIR)}...\n")
                App.import_translation(str(trans_file))
            else:
                self.log(f"[{i}/{total}] 跳过 {trans_file.name} (文件不存在)\n")
        
        self.log("\n" + "=" * 60 + "\n")
        self.log("✓ 所有翻译导入完成！\n")
        self.log("=" * 60 + "\n")
    
    def export_all_to_build(self):
        """
        导出所有文件到构建目录
        输出目录：build/ULJS00064/PSP_GAME/USRDIR
        """
        self.log("=" * 60 + "\n")
        self.log("开始导出所有文件...\n")
        self.log("=" * 60 + "\n")
        
        # 确保输出目录存在
        self.EXPORT_USRDIR.mkdir(parents=True, exist_ok=True)
        
        # 1. 导出 TEXT 文件
        self.log("\n【1/4】导出 TEXT 文件...\n")
        text_exports = [
            ('free', 'f2info.bin'),
            ('free', 'f2tuto.bin')
        ]
        for i, (subdir, filename) in enumerate(text_exports, 1):
            output_dir = self.EXPORT_USRDIR / subdir
            output_dir.mkdir(parents=True, exist_ok=True)
            self.log(f"  [{i}/{len(text_exports)}] 导出 {filename}...\n")
            App.export_text(str(output_dir), filename)
        
        # 2. 导出 BIND 文件
        self.log("\n【2/4】导出 BIND 文件...\n")
        bind_exports = [
            ('btl', 'btimtext.bin'),
            ('game', 'imtext.bin')
        ]
        for i, (subdir, filename) in enumerate(bind_exports, 1):
            output_dir = self.EXPORT_USRDIR / subdir
            output_dir.mkdir(parents=True, exist_ok=True)
            self.log(f"  [{i}/{len(bind_exports)}] 导出 {filename}...\n")
            App.export_bind(str(output_dir), filename)
        
        # 3. 导出 HGAR 文件
        self.log("\n【3/4】导出 HGAR 文件...\n")
        self.log(f"  导出到 {self.EXPORT_USRDIR}...\n")
        App.output_hgar(str(self.EXPORT_USRDIR), None)
        
        # 4. 导出 EBOOT 翻译
        self.log("\n【4/4】导出 EBOOT 翻译...\n")
        eboot_trans = self.DOWNLOAD_DIR / 'eboot_trans.json'
        if eboot_trans.exists():
            export_bin_dir = self.BUILD_DIR / 'bin'
            export_bin_dir.mkdir(parents=True, exist_ok=True)
            output_path = export_bin_dir / 'EBTRANS.BIN'
            self.log(f"  生成 {output_path}...\n")
            App.export_eboot_trans(str(eboot_trans), str(output_path))
        else:
            self.log(f"  跳过 EBOOT 翻译 (文件不存在: {eboot_trans})\n")
        
        self.log("\n" + "=" * 60 + "\n")
        self.log(f"✓ 所有文件已导出到: {self.EXPORT_USRDIR}\n")
        self.log("=" * 60 + "\n")
    
    def quick_workflow(self, token: Optional[str] = None):
        """
        快速工作流：从游戏导入 -> 导入翻译 -> 导出构建
        一键完成所有常规操作
        
        Args:
            token: 如果提供，会先下载最新翻译
        """
        self.log("\n" + "=" * 60 + "\n")
        self.log("开始快速工作流...\n")
        self.log("=" * 60 + "\n\n")
        
        try:
            # 步骤 0: 下载翻译（可选）
            if token:
                self.download_translations(token)
                self.log("\n")
            
            # 步骤 1: 导入游戏资源
            self.import_all_from_game()
            self.log("\n")
            
            # 步骤 2: 导入翻译
            self.import_all_translations()
            self.log("\n")
            
            # 步骤 3: 导出到构建目录
            self.export_all_to_build()
            
            self.log("\n" + "=" * 60 + "\n")
            self.log("✓ 快速工作流完成！\n")
            self.log("=" * 60 + "\n")
            
        except Exception as e:
            self.log("\n" + "=" * 60 + "\n")
            self.log(f"✗ 工作流失败: {str(e)}\n")
            self.log("=" * 60 + "\n")
            raise
    
    def full_auto_workflow(self, token: str):
        """
        全自动工作流：下载 -> 导入游戏 -> 导入翻译 -> 导出构建
        完全自动化，只需要提供Token
        
        Args:
            token: Paratranz API Token
        """
        self.log("\n" + "=" * 60 + "\n")
        self.log("开始全自动工作流...\n")
        self.log("=" * 60 + "\n\n")
        
        try:
            # 步骤 1: 下载翻译
            self.download_translations(token)
            self.log("\n")
            
            # 步骤 2: 导入游戏资源
            self.import_all_from_game()
            self.log("\n")
            
            # 步骤 3: 导入翻译
            self.import_all_translations()
            self.log("\n")
            
            # 步骤 4: 导出到构建目录
            self.export_all_to_build()
            
            self.log("\n" + "=" * 60 + "\n")
            self.log("🎉 全自动工作流完成！\n")
            self.log("=" * 60 + "\n")
            
        except Exception as e:
            self.log("\n" + "=" * 60 + "\n")
            self.log(f"✗ 工作流失败: {str(e)}\n")
            self.log("=" * 60 + "\n")
            raise
