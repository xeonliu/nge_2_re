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

# 导入 CLI 主程序的功能
from app.cli.main import App

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
        
        # 设置窗口图标（如果有的话）
        try:
            # 可以在这里设置图标
            pass
        except:
            pass
        
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
        # 数据库操作
        db_frame = ttk.LabelFrame(parent, text="数据库操作", padding="10")
        db_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            db_frame, 
            text="初始化数据库", 
            command=self.on_init_db
        ).pack(fill=tk.X, pady=2)
        
        # HAR 文件操作
        har_frame = ttk.LabelFrame(parent, text="HAR 文件操作", padding="10")
        har_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            har_frame, 
            text="导入 HAR 文件（目录）", 
            command=self.on_import_har
        ).pack(fill=tk.X, pady=2)
        
        ttk.Button(
            har_frame, 
            text="导出 HAR 文件", 
            command=self.on_export_hgar
        ).pack(fill=tk.X, pady=2)
        
        # EVS 和翻译操作
        evs_frame = ttk.LabelFrame(parent, text="EVS 和翻译", padding="10")
        evs_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            evs_frame, 
            text="导出 EVS 原文（JSON）", 
            command=self.on_export_evs
        ).pack(fill=tk.X, pady=2)
        
        ttk.Button(
            evs_frame, 
            text="导入翻译（JSON）", 
            command=self.on_import_translation
        ).pack(fill=tk.X, pady=2)
        
        ttk.Button(
            evs_frame, 
            text="导出翻译（JSON）", 
            command=self.on_export_translation
        ).pack(fill=tk.X, pady=2)
        
        # 图像操作
        image_frame = ttk.LabelFrame(parent, text="图像操作", padding="10")
        image_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            image_frame, 
            text="导出图像（PNG）", 
            command=self.on_export_images
        ).pack(fill=tk.X, pady=2)
        
        ttk.Button(
            image_frame, 
            text="导入翻译后的图像", 
            command=self.on_import_images
        ).pack(fill=tk.X, pady=2)
        
        # TEXT 文件操作
        text_frame = ttk.LabelFrame(parent, text="TEXT 文件操作", padding="10")
        text_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            text_frame, 
            text="导入 TEXT 文件", 
            command=self.on_import_text
        ).pack(fill=tk.X, pady=2)
        
        ttk.Button(
            text_frame, 
            text="导出 TEXT 文件", 
            command=self.on_export_text
        ).pack(fill=tk.X, pady=2)
        
        ttk.Button(
            text_frame, 
            text="导出 TEXT 为 JSON", 
            command=self.on_export_text_json
        ).pack(fill=tk.X, pady=2)
        
        # BIND 文件操作
        bind_frame = ttk.LabelFrame(parent, text="BIND 文件操作", padding="10")
        bind_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            bind_frame, 
            text="导入 BIND 文件", 
            command=self.on_import_bind
        ).pack(fill=tk.X, pady=2)
        
        ttk.Button(
            bind_frame, 
            text="导出 BIND 文件", 
            command=self.on_export_bind
        ).pack(fill=tk.X, pady=2)
        
        ttk.Button(
            bind_frame, 
            text="导出 BIND 为 JSON", 
            command=self.on_export_bind_json
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


def main():
    """启动 GUI 应用"""
    root = tk.Tk()
    app = NGE2TranslationGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

