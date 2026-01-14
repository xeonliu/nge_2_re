"""
NGE2 汉化工具图形界面
使用 tkinter 构建，适合打包给非编程用户使用
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
from pathlib import Path
import json

# 导入 CLI 主程序的功能
from app.cli.main import App
from app.gui.workflows import Workflows
from scripts.paratranz.download import download_function, merge_function

# 重定向 print 输出到 GUI
class TextRedirector:
    """将标准输出重定向到 GUI 文本区域"""
    def __init__(self, text_widget):
        self.text_widget = text_widget
        
    def write(self, message):
        self.text_widget.insert(tk.END, message)
        self.text_widget.see(tk.END)
        
    def flush(self):
        pass


class NGE2TranslationGUI:
    """NGE2 汉化工具主窗口"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("NGE2 汉化工具")
        self.root.geometry("900x700")
        
        # 设置文件路径
        self.settings_file = Path("settings.json")
        self.token = self.load_token()
        
        # 设置窗口图标（如果有的话）
        try:
            # 可以在这里设置图标
            pass
        except:
            pass
        
        # 创建菜单栏
        self.create_menu()
        
        # 创建主框架
        self.create_widgets()
        
        # 初始化数据库
        self.init_database()
        
    def init_database(self):
        """初始化数据库"""
        try:
            App()
            self.log("数据库初始化成功！\n")
        except Exception as e:
            self.log(f"数据库初始化失败: {str(e)}\n")
            messagebox.showerror("错误", f"数据库初始化失败:\n{str(e)}")
    
    def load_token(self):
        """从设置文件加载Token"""
        try:
            if self.settings_file.exists():
                with open(self.settings_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data.get('token', '')
        except Exception as e:
            self.log(f"加载Token失败: {str(e)}\n")
        return ''
    
    def save_token(self, token):
        """保存Token到设置文件"""
        try:
            self.settings_file.parent.mkdir(parents=True, exist_ok=True)
            data = {'token': token}
            with open(self.settings_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.token = token
            self.update_token_status()
            self.log("Token已保存！\n")
            messagebox.showinfo("成功", "Token已保存并持久化到 settings.json")
        except Exception as e:
            self.log(f"保存Token失败: {str(e)}\n")
            messagebox.showerror("错误", f"保存Token失败:\n{str(e)}")
    
    def update_token_status(self):
        """更新Token状态显示"""
        if hasattr(self, 'token_status_label'):
            if self.token:
                # 显示Token的前4位和后4位
                masked = f"{self.token[:4]}...{self.token[-4:]}" if len(self.token) > 8 else "****"
                self.token_status_label.config(
                    text=f"✓ Token: {masked}",
                    foreground="green"
                )
            else:
                self.token_status_label.config(
                    text="❌ 未设置 Token",
                    foreground="red"
                )
    
    def create_menu(self):
        """创建菜单栏"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # 设置菜单
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="设置", menu=settings_menu)
        settings_menu.add_command(label="设置Token", command=self.on_settings_token)
    
    def on_settings_token(self):
        """设置Token对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title("设置 Paratranz Token")
        dialog.geometry("500x220")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # 居中显示对话框
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # 说明文本
        info_label = ttk.Label(
            dialog,
            text="请输入您的 Paratranz API Token\n用于下载翻译文件（Token将保存到 settings.json）",
            justify=tk.CENTER,
            foreground="gray"
        )
        info_label.pack(pady=10)
        
        ttk.Label(dialog, text="Token:", font=("Arial", 10, "bold")).pack(pady=(5, 0))
        
        # 输入框
        entry_frame = ttk.Frame(dialog)
        entry_frame.pack(pady=5, padx=20, fill=tk.X)
        
        entry = ttk.Entry(entry_frame, show="*", font=("Arial", 10))
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        entry.insert(0, self.token)  # 预填当前Token
        entry.focus()
        
        # 显示/隐藏按钮
        show_var = tk.BooleanVar(value=False)
        
        def toggle_show():
            if show_var.get():
                entry.config(show="")
                show_btn.config(text="🙈 隐藏")
            else:
                entry.config(show="*")
                show_btn.config(text="👁 显示")
        
        show_btn = ttk.Button(
            entry_frame,
            text="👁 显示",
            command=lambda: (show_var.set(not show_var.get()), toggle_show()),
            width=8
        )
        show_btn.pack(side=tk.LEFT)
        
        def save():
            token = entry.get().strip()
            if token:
                self.save_token(token)
                dialog.destroy()
            else:
                messagebox.showwarning("警告", "Token 不能为空")
        
        def cancel():
            dialog.destroy()
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=15)
        ttk.Button(button_frame, text="💾 保存", command=save, width=12).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="❌ 取消", command=cancel, width=12).pack(side=tk.LEFT, padx=5)
        
        entry.bind('<Return>', lambda e: save())
    
    def create_widgets(self):
        """创建界面组件"""
        # 创建主容器
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置网格权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # 标题
        title_label = ttk.Label(
            main_frame, 
            text="《新世纪福音战士 2》汉化工具",
            font=("Arial", 16, "bold")
        )
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # 创建左侧可滚动按钮区域
        left_container = ttk.Frame(main_frame)
        left_container.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        left_container.columnconfigure(0, weight=1)
        left_container.rowconfigure(0, weight=1)
        
        # 创建 Canvas 和 Scrollbar
        canvas = tk.Canvas(left_container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(left_container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        # 配置滚动区域
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        # 在 Canvas 中创建窗口
        canvas_frame = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        
        # 配置 Canvas 和 Scrollbar
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # 使 Canvas 宽度自适应
        def configure_canvas_width(event):
            canvas_width = event.width
            canvas.itemconfig(canvas_frame, width=canvas_width)
        
        canvas.bind('<Configure>', configure_canvas_width)
        
        # 绑定鼠标滚轮事件
        def on_mousewheel(event):
            # Windows 和 macOS
            if event.delta:
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        
        def on_scroll_up(event):
            canvas.yview_scroll(-1, "units")
        
        def on_scroll_down(event):
            canvas.yview_scroll(1, "units")
        
        # Windows 和 macOS
        canvas.bind("<MouseWheel>", on_mousewheel)
        # Linux 系统使用 Button-4 和 Button-5
        canvas.bind("<Button-4>", on_scroll_up)
        canvas.bind("<Button-5>", on_scroll_down)
        
        # 同时绑定到 scrollable_frame，这样在按钮上滚动也能工作
        scrollable_frame.bind("<MouseWheel>", on_mousewheel)
        scrollable_frame.bind("<Button-4>", on_scroll_up)
        scrollable_frame.bind("<Button-5>", on_scroll_down)
        
        # 创建右侧日志区域
        log_frame = ttk.LabelFrame(main_frame, text="操作日志", padding="5")
        log_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame, 
            width=50, 
            height=30,
            wrap=tk.WORD,
            font=("Consolas", 9)
        )
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 重定向标准输出
        sys.stdout = TextRedirector(self.log_text)
        
        # 创建按钮组（使用 scrollable_frame 作为父容器）
        self.create_button_groups(scrollable_frame)
        
    def create_button_groups(self, parent):
        """创建功能按钮组"""
        
        # ===== 快速工作流区域 =====
        workflow_frame = ttk.LabelFrame(parent, text="⚡ 快速工作流", padding="10")
        workflow_frame.pack(fill=tk.X, pady=5)
        
        # Token 设置区域
        token_frame = ttk.Frame(workflow_frame)
        token_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Token 状态标签
        self.token_status_label = ttk.Label(
            token_frame,
            text="❌ 未设置 Token",
            foreground="red",
            font=("Arial", 9, "bold")
        )
        self.token_status_label.pack(side=tk.LEFT, padx=(0, 10))
        
        # 更新Token状态显示
        self.update_token_status()
        
        ttk.Button(
            token_frame,
            text="🔑 设置 Token",
            command=self.on_settings_token,
            width=15
        ).pack(side=tk.LEFT)
        
        ttk.Separator(workflow_frame, orient='horizontal').pack(fill=tk.X, pady=5)
        
        ttk.Button(
            workflow_frame, 
            text="🎉 全自动流程（下载+导入+导出）", 
            command=self.on_full_auto_workflow
        ).pack(fill=tk.X, pady=2)
        
        ttk.Separator(workflow_frame, orient='horizontal').pack(fill=tk.X, pady=5)
        
        ttk.Button(
            workflow_frame, 
            text="📥 下载翻译文件", 
            command=self.on_download_translations_workflow
        ).pack(fill=tk.X, pady=2)
        
        ttk.Button(
            workflow_frame, 
            text="🚀 一键完整流程（不含下载）", 
            command=self.on_quick_workflow
        ).pack(fill=tk.X, pady=2)
        
        ttk.Separator(workflow_frame, orient='horizontal').pack(fill=tk.X, pady=5)
        
        ttk.Button(
            workflow_frame, 
            text="📥 导入所有游戏资源", 
            command=self.on_import_all_from_game
        ).pack(fill=tk.X, pady=2)
        
        ttk.Button(
            workflow_frame, 
            text="📝 导入所有翻译", 
            command=self.on_import_all_translations
        ).pack(fill=tk.X, pady=2)
        
        ttk.Button(
            workflow_frame, 
            text="📤 导出到构建目录", 
            command=self.on_export_all_to_build
        ).pack(fill=tk.X, pady=2)
        
        # 添加说明标签
        info_label = ttk.Label(
            workflow_frame,
            text="💡 游戏ISO请解压到 temp/ULJS00064",
            font=("Arial", 8),
            foreground="gray"
        )
        info_label.pack(fill=tk.X, pady=(5, 0))
        
        # 数据库操作
        db_frame = ttk.LabelFrame(parent, text="数据库操作", padding="10")
        db_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            db_frame, 
            text="初始化数据库", 
            command=self.on_init_db
        ).pack(fill=tk.X, pady=2)
        
        
        # EBOOT 翻译操作
        eboot_frame = ttk.LabelFrame(parent, text="EBOOT 翻译", padding="10")
        eboot_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            eboot_frame, 
            text="生成 EBTRANS.BIN", 
            command=self.on_export_eboot_trans
        ).pack(fill=tk.X, pady=2)
        
    def log(self, message):
        """添加日志消息"""
        self.log_text.insert(tk.END, message)
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def run_in_thread(self, func, *args, **kwargs):
        """在后台线程中运行函数，避免界面冻结"""
        def wrapper():
            try:
                func(*args, **kwargs)
                self.log("操作完成！\n\n")
            except Exception as e:
                error_msg = f"错误: {str(e)}\n"
                self.log(error_msg)
                messagebox.showerror("错误", f"操作失败:\n{str(e)}")
        
        thread = threading.Thread(target=wrapper, daemon=True)
        thread.start()
    
    def run_terminal_command(self, command):
        """运行终端命令"""
        # 这里我们需要导入run_in_terminal，但它是工具，不是模块。
        # 实际上，我们不能直接调用run_in_terminal，因为它是工具。
        # 我们需要使用subprocess或os.system。
        import subprocess
        import sys
        try:
            result = subprocess.run(command, shell=True, cwd=str(Path(__file__).parent.parent.parent), capture_output=True, text=True)
            if result.stdout:
                self.log(result.stdout)
            if result.stderr:
                self.log(result.stderr)
        except Exception as e:
            self.log(f"命令执行失败: {str(e)}\n")
    
    def ask_prefix(self, title="输入前缀"):
        """询问用户输入前缀"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("300x120")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # 居中显示对话框
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        result = [None]
        cancelled = [False]
        
        ttk.Label(dialog, text="请输入前缀（留空表示全部）:").pack(pady=10)
        entry = ttk.Entry(dialog, width=30)
        entry.pack(pady=5)
        entry.focus()
        
        def ok():
            result[0] = entry.get().strip() if entry.get().strip() else None
            dialog.destroy()
        
        def cancel():
            cancelled[0] = True
            dialog.destroy()
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="确定", command=ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="取消", command=cancel).pack(side=tk.LEFT, padx=5)
        
        entry.bind('<Return>', lambda e: ok())
        dialog.bind('<Escape>', lambda e: cancel())
        
        dialog.wait_window()
        # 返回 False 表示用户取消，None 表示全部，字符串表示具体前缀
        if cancelled[0]:
            return False
        return result[0]
    
    def ask_filename(self, title="输入文件名"):
        """询问用户输入文件名"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("300x120")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # 居中显示对话框
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        result = [None]
        cancelled = [False]
        
        ttk.Label(dialog, text="请输入文件名（留空表示全部）:").pack(pady=10)
        entry = ttk.Entry(dialog, width=30)
        entry.pack(pady=5)
        entry.focus()
        
        def ok():
            result[0] = entry.get().strip() if entry.get().strip() else None
            dialog.destroy()
        
        def cancel():
            cancelled[0] = True
            dialog.destroy()
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="确定", command=ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="取消", command=cancel).pack(side=tk.LEFT, padx=5)
        
        entry.bind('<Return>', lambda e: ok())
        dialog.bind('<Escape>', lambda e: cancel())
        
        dialog.wait_window()
        # 返回 False 表示用户取消，None 表示全部，字符串表示具体前缀
        if cancelled[0]:
            return False
        return result[0]
    
    def ask_token(self, title="输入 Token"):
        """询问用户输入 Token"""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x140")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # 居中显示对话框
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        result = [None]
        cancelled = [False]
        
        ttk.Label(dialog, text="请输入 Paratranz Token:").pack(pady=10)
        entry = ttk.Entry(dialog, width=50, show="*")  # 隐藏输入
        entry.pack(pady=5)
        entry.focus()
        
        def ok():
            token = entry.get().strip()
            if token:
                result[0] = token
                dialog.destroy()
            else:
                messagebox.showwarning("警告", "Token 不能为空")
        
        def cancel():
            cancelled[0] = True
            dialog.destroy()
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="确定", command=ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="取消", command=cancel).pack(side=tk.LEFT, padx=5)
        
        entry.bind('<Return>', lambda e: ok())
        dialog.bind('<Escape>', lambda e: cancel())
        
        dialog.wait_window()
        if cancelled[0]:
            return False
        return result[0]
    
    # 事件处理函数
    def on_init_db(self):
        """初始化数据库"""
        self.run_in_thread(lambda: App())
        self.log("正在初始化数据库...\n")
    
    def on_import_har(self):
        """导入 HAR 文件"""
        dir_path = filedialog.askdirectory(title="选择包含 HAR 文件的目录")
        if dir_path:
            self.log(f"正在导入 HAR 文件: {dir_path}\n")
            self.run_in_thread(App.import_har, dir_path)
    
    def on_export_hgar(self):
        """导出 HAR 文件"""
        output_dir = filedialog.askdirectory(title="选择输出目录")
        if output_dir:
            prefix = self.ask_prefix("导出 HAR 文件")
            if prefix is not False:  # False 表示用户取消
                self.log(f"正在导出 HAR 文件到: {output_dir}\n")
                if prefix:
                    self.log(f"前缀过滤: {prefix}\n")
                self.run_in_thread(App.output_hgar, output_dir, prefix)
    
    def on_export_evs(self):
        """导出 EVS 原文"""
        output_dir = filedialog.askdirectory(title="选择输出目录")
        if output_dir:
            prefix = self.ask_prefix("导出 EVS 原文")
            if prefix is not False:  # False 表示用户取消
                self.log(f"正在导出 EVS 原文到: {output_dir}\n")
                if prefix:
                    self.log(f"前缀过滤: {prefix}\n")
                self.run_in_thread(App.output_evs, output_dir, prefix)
    
    def on_import_translation(self):
        """导入翻译"""
        file_path = filedialog.askopenfilename(
            title="选择翻译 JSON 文件",
            filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")]
        )
        if file_path:
            self.log(f"正在导入翻译: {file_path}\n")
            self.run_in_thread(App.import_translation, file_path)
    
    def on_export_translation(self):
        """导出翻译"""
        output_dir = filedialog.askdirectory(title="选择输出目录")
        if output_dir:
            prefix = self.ask_prefix("导出翻译")
            if prefix is not False:  # False 表示用户取消
                self.log(f"正在导出翻译到: {output_dir}\n")
                if prefix:
                    self.log(f"前缀过滤: {prefix}\n")
                self.run_in_thread(App.output_translation, output_dir, prefix)
    
    def on_export_images(self):
        """导出图像"""
        output_dir = filedialog.askdirectory(title="选择输出目录")
        if output_dir:
            self.log(f"正在导出图像到: {output_dir}\n")
            self.run_in_thread(App.output_images, output_dir)
    
    def on_import_images(self):
        """导入翻译后的图像"""
        dir_path = filedialog.askdirectory(title="选择包含翻译后图像的目录")
        if dir_path:
            self.log(f"正在导入图像: {dir_path}\n")
            self.run_in_thread(App.import_images, dir_path)
    
    def on_import_text(self):
        """导入 TEXT 文件"""
        file_path = filedialog.askopenfilename(
            title="选择 TEXT 文件",
            filetypes=[("BIN 文件", "*.bin"), ("所有文件", "*.*")]
        )
        if file_path:
            self.log(f"正在导入 TEXT 文件: {file_path}\n")
            self.run_in_thread(App.import_text, file_path)
    
    def on_export_text(self):
        """导出 TEXT 文件"""
        output_dir = filedialog.askdirectory(title="选择输出目录")
        if output_dir:
            filename = self.ask_filename("导出 TEXT 文件")
            if filename is not False:  # False 表示用户取消
                self.log(f"正在导出 TEXT 文件到: {output_dir}\n")
                if filename:
                    self.log(f"文件名过滤: {filename}\n")
                self.run_in_thread(App.export_text, output_dir, filename)
    
    def on_export_text_json(self):
        """导出 TEXT 为 JSON"""
        output_dir = filedialog.askdirectory(title="选择输出目录")
        if output_dir:
            filename = self.ask_filename("导出 TEXT 为 JSON")
            if filename is not False:  # False 表示用户取消
                self.log(f"正在导出 TEXT JSON 到: {output_dir}\n")
                if filename:
                    self.log(f"文件名过滤: {filename}\n")
                self.run_in_thread(App.export_text_json, output_dir, filename)
    
    def on_import_bind(self):
        """导入 BIND 文件"""
        file_path = filedialog.askopenfilename(
            title="选择 BIND 文件",
            filetypes=[("BIN 文件", "*.bin"), ("所有文件", "*.*")]
        )
        if file_path:
            self.log(f"正在导入 BIND 文件: {file_path}\n")
            self.run_in_thread(App.import_bind, file_path)
    
    def on_export_bind(self):
        """导出 BIND 文件"""
        output_dir = filedialog.askdirectory(title="选择输出目录")
        if output_dir:
            filename = self.ask_filename("导出 BIND 文件")
            if filename is not False:  # False 表示用户取消
                self.log(f"正在导出 BIND 文件到: {output_dir}\n")
                if filename:
                    self.log(f"文件名过滤: {filename}\n")
                self.run_in_thread(App.export_bind, output_dir, filename)
    
    def on_export_bind_json(self):
        """导出 BIND 为 JSON"""
        output_dir = filedialog.askdirectory(title="选择输出目录")
        if output_dir:
            filename = self.ask_filename("导出 BIND 为 JSON")
            if filename is not False:  # False 表示用户取消
                self.log(f"正在导出 BIND JSON 到: {output_dir}\n")
                if filename:
                    self.log(f"文件名过滤: {filename}\n")
                self.run_in_thread(App.export_bind_json, output_dir, filename)
    
    def on_export_eboot_trans(self):
        """生成 EBTRANS.BIN 文件"""
        # 首先选择翻译文件或目录
        translation_path = filedialog.askopenfilename(
            title="选择翻译 JSON 文件（或取消后选择目录）",
            filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")]
        )
        
        # 如果用户取消文件选择，尝试选择目录
        if not translation_path:
            translation_path = filedialog.askdirectory(title="选择包含 chunk_*.json 的目录")
        
        if translation_path:
            # 选择输出文件路径
            output_path = filedialog.asksaveasfilename(
                title="保存 EBTRANS.BIN 文件",
                defaultextension=".BIN",
                filetypes=[("BIN 文件", "*.BIN"), ("所有文件", "*.*")],
                initialfile="EBTRANS.BIN"
            )
            
            if output_path:
                self.log(f"正在生成 EBTRANS.BIN...\n")
                self.log(f"翻译文件路径: {translation_path}\n")
                self.log(f"输出文件路径: {output_path}\n")
                self.run_in_thread(App.export_eboot_trans, translation_path, output_path)
    
    def on_download_translation(self):
        """下载翻译"""
        token = self.token if self.token else self.ask_token("输入 Paratranz Token")
        if token:  # token 不为空
            self.log("正在下载翻译...\n")
            # 先下载文件
            self.run_in_thread(self.download_and_merge, token)
            # 如果是从ask_token得到的，保存它
            if not self.token:
                self.save_token(token)
    
    def download_and_merge(self, token):
        """下载并合并翻译文件"""
        try:
            # 下载文件
            download_function(token, "temp/downloads")
            # 合并文件
            merge_function("temp/downloads")
            self.log("翻译下载和处理完成！\n")
        except Exception as e:
            self.log(f"下载或处理失败: {str(e)}\n")
            raise
    
    # ===== 快速工作流事件处理 =====
    
    def on_download_translations_workflow(self):
        """下载翻译文件"""
        # 检查token是否已设置
        if not self.token:
            messagebox.showwarning(
                "需要设置 Token",
                "请先点击 '🔑 设置 Token' 按钮设置您的 Paratranz Token！\n\n"
                "Token 将被安全保存到 settings.json 文件中。"
            )
            self.on_settings_token()  # 直接打开设置对话框
            if not self.token:  # 如果用户取消了设置
                return
        
        result = messagebox.askyesno(
            "确认", 
            "这将从 Paratranz 下载最新翻译到 temp/downloads\n\n"
            "确定要继续吗？"
        )
        if result:
            workflows = Workflows(logger=self.log)
            self.run_in_thread(workflows.download_translations, self.token)
    
    def on_full_auto_workflow(self):
        """全自动工作流：下载+导入+导出"""
        # 检查token是否已设置
        if not self.token:
            messagebox.showwarning(
                "需要设置 Token",
                "请先点击 '🔑 设置 Token' 按钮设置您的 Paratranz Token！\n\n"
                "Token 将被安全保存到 settings.json 文件中，\n"
                "之后您就不需要每次都输入了。"
            )
            self.on_settings_token()  # 直接打开设置对话框
            if not self.token:  # 如果用户取消了设置
                return
        
        result = messagebox.askyesno(
            "确认", 
            "这将执行以下操作：\n"
            "1. 从 Paratranz 下载最新翻译\n"
            "2. 从 temp/ULJS00064 导入所有游戏资源\n"
            "3. 导入所有翻译文件\n"
            "4. 导出到 build/ULJS00064\n\n"
            "🎉 这是最简单的方式，只需要确保游戏ISO已解压!\n\n"
            "确定要继续吗？"
        )
        if result:
            workflows = Workflows(logger=self.log)
            self.run_in_thread(workflows.full_auto_workflow, self.token)
    
    def on_quick_workflow(self):
        """快速工作流：一键完成所有操作"""
        result = messagebox.askyesno(
            "确认", 
            "这将执行以下操作：\n"
            "1. 从 temp/ULJS00064 导入所有游戏资源\n"
            "2. 从 temp/downloads 导入所有翻译\n"
            "3. 导出到 build/ULJS00064\n\n"
            "确定要继续吗？"
        )
        if result:
            self.log("=" * 60 + "\n")
            self.log("启动快速工作流...\n")
            self.log("=" * 60 + "\n")
            workflows = Workflows(logger=self.log)
            self.run_in_thread(workflows.quick_workflow)
    
    def on_import_all_from_game(self):
        """从游戏导入所有资源"""
        result = messagebox.askyesno(
            "确认", 
            "这将从 temp/ULJS00064 导入：\n"
            "• 所有 HGAR 目录\n"
            "• TEXT 文件 (info, tuto)\n"
            "• BIND 文件 (btimtext, imtext)\n"
            "• 翻译图像\n\n"
            "确定要继续吗？"
        )
        if result:
            workflows = Workflows(logger=self.log)
            self.run_in_thread(workflows.import_all_from_game)
    
    def on_import_all_translations(self):
        """导入所有翻译"""
        result = messagebox.askyesno(
            "确认", 
            "这将从 temp/downloads 导入所有翻译文件。\n\n"
            "确定要继续吗？"
        )
        if result:
            workflows = Workflows(logger=self.log)
            self.run_in_thread(workflows.import_all_translations)
    
    def on_export_all_to_build(self):
        """导出所有文件到构建目录"""
        result = messagebox.askyesno(
            "确认", 
            "这将导出所有文件到 build/ULJS00064/PSP_GAME/USRDIR。\n\n"
            "确定要继续吗？"
        )
        if result:
            workflows = Workflows(logger=self.log)
            self.run_in_thread(workflows.export_all_to_build)


def main():
    """启动 GUI 应用"""
    root = tk.Tk()
    app = NGE2TranslationGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

