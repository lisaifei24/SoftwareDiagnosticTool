import sys
import subprocess
import os
import platform
import ctypes
import winreg
import json
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget, 
                             QLabel, QLineEdit, QPushButton, QTextEdit, 
                             QFileDialog, QMessageBox, QTabWidget, QProgressBar,
                             QHBoxLayout, QGroupBox, QCheckBox)
from PyQt5.QtCore import QProcess, QThread, pyqtSignal
from PyQt5.QtGui import QTextCursor
import requests
from zipfile import ZipFile
from io import BytesIO

class DownloadThread(QThread):
    update_progress = pyqtSignal(int)
    download_complete = pyqtSignal(bool, str)

    def __init__(self, url, save_path):
        super().__init__()
        self.url = url
        self.save_path = save_path

    def run(self):
        try:
            response = requests.get(self.url, stream=True)
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(self.save_path, 'wb') as f:
                for data in response.iter_content(chunk_size=4096):
                    f.write(data)
                    downloaded += len(data)
                    progress = int((downloaded / total_size) * 100) if total_size > 0 else 0
                    self.update_progress.emit(progress)
            
            self.download_complete.emit(True, self.save_path)
        except Exception as e:
            self.download_complete.emit(False, str(e))

class SystemInfoCollector:
    @staticmethod
    def collect():
        info = {
            "timestamp": datetime.now().isoformat(),
            "system": {
                "platform": platform.platform(),
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor()
            },
            "windows": {
                "product_name": SystemInfoCollector.get_windows_product_name(),
                "build_number": SystemInfoCollector.get_windows_build_number(),
                "is_admin": SystemInfoCollector.is_admin()
            },
            "memory": {
                "total": round(psutil.virtual_memory().total / (1024**3), 2),
                "available": round(psutil.virtual_memory().available / (1024**3), 2)
            },
            "disks": SystemInfoCollector.get_disk_info(),
            "environment": dict(os.environ)
        }
        return info

    @staticmethod
    def get_windows_product_name():
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            product_name, _ = winreg.QueryValueEx(key, "ProductName")
            winreg.CloseKey(key)
            return product_name
        except:
            return "Unknown"

    @staticmethod
    def get_windows_build_number():
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            build_number, _ = winreg.QueryValueEx(key, "CurrentBuildNumber")
            winreg.CloseKey(key)
            return build_number
        except:
            return "Unknown"

    @staticmethod
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    @staticmethod
    def get_disk_info():
        disks = []
        for part in psutil.disk_partitions(all=False):
            usage = psutil.disk_usage(part.mountpoint)
            disks.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "total_gb": round(usage.total / (1024**3), 2),
                "used_gb": round(usage.used / (1024**3), 2),
                "free_gb": round(usage.free / (1024**3), 2),
                "percent": usage.percent
            })
        return disks

class SoftwareDiagnosticTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("增强版软件运行诊断助手")
        self.setGeometry(100, 100, 800, 600)
        
        # 初始化关键属性
        self.log_dir = os.path.join(os.getenv('APPDATA'), "SoftwareDiagnosticTool")
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            
        self.diagnosis_history = []
        self.system_info = None
        self.download_thread = None
        
        # 初始化UI
        self.init_ui()
        
        # 初始化进程相关
        self.process = QProcess()
        self.process.readyReadStandardOutput.connect(self.handle_output)
        self.process.readyReadStandardError.connect(self.handle_error)
        self.process.finished.connect(self.process_finished)
        
    def init_ui(self):
        # 主窗口部件
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        
        # 创建标签页
        self.tabs = QTabWidget()
        
        # 诊断标签页
        self.diagnosis_tab = QWidget()
        self.init_diagnosis_tab()
        self.tabs.addTab(self.diagnosis_tab, "诊断")
        
        # 系统信息标签页
        self.system_info_tab = QWidget()
        self.init_system_info_tab()
        self.tabs.addTab(self.system_info_tab, "系统信息")
        
        # 历史记录标签页
        self.history_tab = QWidget()
        self.init_history_tab()
        self.tabs.addTab(self.history_tab, "历史记录")
        
        # 添加到主布局
        main_layout.addWidget(self.tabs)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
    
    def init_diagnosis_tab(self):
        layout = QVBoxLayout()
        
        # 软件路径选择
        path_group = QGroupBox("软件诊断设置")
        path_layout = QVBoxLayout()
        
        self.path_label = QLabel("软件路径:")
        self.path_input = QLineEdit()
        self.browse_button = QPushButton("浏览...")
        self.browse_button.clicked.connect(self.browse_software)
        
        # 诊断选项
        self.collect_sysinfo_check = QCheckBox("收集系统信息")
        self.collect_sysinfo_check.setChecked(True)
        self.auto_repair_check = QCheckBox("尝试自动修复")
        self.auto_repair_check.setChecked(True)
        
        path_layout.addWidget(self.path_label)
        path_layout.addWidget(self.path_input)
        path_layout.addWidget(self.browse_button)
        path_layout.addWidget(self.collect_sysinfo_check)
        path_layout.addWidget(self.auto_repair_check)
        path_group.setLayout(path_layout)
        
        # 运行按钮
        self.run_button = QPushButton("运行诊断")
        self.run_button.clicked.connect(self.run_diagnosis)
        
        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        # 输出区域
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        
        # 诊断结果区域
        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)
        self.result_area.setPlaceholderText("诊断结果将显示在这里...")
        
        # 添加到布局
        layout.addWidget(path_group)
        layout.addWidget(self.run_button)
        layout.addWidget(self.progress_bar)
        layout.addWidget(QLabel("运行输出:"))
        layout.addWidget(self.output_area)
        layout.addWidget(QLabel("诊断结果:"))
        layout.addWidget(self.result_area)
        
        self.diagnosis_tab.setLayout(layout)
    
    def init_system_info_tab(self):
        layout = QVBoxLayout()
        
        self.sysinfo_refresh_button = QPushButton("刷新系统信息")
        self.sysinfo_refresh_button.clicked.connect(self.refresh_system_info)
        
        self.sysinfo_text = QTextEdit()
        self.sysinfo_text.setReadOnly(True)
        
        layout.addWidget(self.sysinfo_refresh_button)
        layout.addWidget(self.sysinfo_text)
        
        self.system_info_tab.setLayout(layout)
        self.refresh_system_info()
    
    def init_history_tab(self):
        layout = QVBoxLayout()
        
        self.history_list = QTextEdit()
        self.history_list.setReadOnly(True)
        
        self.clear_history_button = QPushButton("清除历史记录")
        self.clear_history_button.clicked.connect(self.clear_history)
        
        self.export_history_button = QPushButton("导出历史记录")
        self.export_history_button.clicked.connect(self.export_history)
        
        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self.clear_history_button)
        buttons_layout.addWidget(self.export_history_button)
        
        layout.addWidget(QLabel("诊断历史记录:"))
        layout.addWidget(self.history_list)
        layout.addLayout(buttons_layout)
        
        self.history_tab.setLayout(layout)
        self.load_history()
    
    def browse_software(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择要诊断的软件", "", 
            "可执行文件 (*.exe *.bat *.cmd);;所有文件 (*.*)"
        )
        if file_path:
            self.path_input.setText(file_path)
    
    def run_diagnosis(self):
        software_path = self.path_input.text()
        if not software_path:
            QMessageBox.warning(self, "警告", "请先选择要诊断的软件路径")
            return
        
        if not os.path.exists(software_path):
            QMessageBox.critical(self, "错误", "指定的软件路径不存在")
            return
        
        # 准备诊断
        self.output_area.clear()
        self.result_area.clear()
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.run_button.setEnabled(False)
        
        # 收集系统信息
        if self.collect_sysinfo_check.isChecked():
            self.append_output("正在收集系统信息...")
            self.system_info = SystemInfoCollector.collect()
            self.append_output("系统信息收集完成")
        
        # 获取软件所在目录
        working_dir = os.path.dirname(software_path)
        
        # 设置工作目录
        self.process.setWorkingDirectory(working_dir)
        
        # 启动程序
        try:
            self.append_output(f"正在启动程序: {software_path}")
            self.process.start(software_path)
        except Exception as e:
            self.append_output(f"启动失败: {str(e)}")
            self.analyze_error(str(e))
            self.finish_diagnosis()
    
    def handle_output(self):
        output = self.process.readAllStandardOutput().data().decode('utf-8', errors='ignore')
        if output:
            self.append_output(output)
    
    def handle_error(self):
        error = self.process.readAllStandardError().data().decode('utf-8', errors='ignore')
        if error:
            self.append_output(f"错误: {error}")
            self.analyze_error(error)
    
    def process_finished(self, exit_code, exit_status):
        if exit_code != 0:
            self.append_result(f"\n程序异常退出，退出代码: {exit_code}")
            self.analyze_exit_code(exit_code)
        else:
            self.append_result("\n程序正常退出，未检测到明显问题")
        
        self.finish_diagnosis()
    
    def analyze_error(self, error_msg):
        error_msg = error_msg.lower()
        solutions = []
        auto_repair_possible = False
        auto_repair_action = None
        
        # 常见错误模式分析
        if "dll" in error_msg and ("not found" in error_msg or "missing" in error_msg):
            missing_dll = self.extract_missing_file(error_msg)
            self.append_result(f"\n诊断结果: 缺少必要的DLL文件 - {missing_dll}")
            solutions = [
                "1. 重新安装该软件",
                "2. 从官方来源下载并安装缺少的DLL文件",
                "3. 安装对应的运行时库(如Visual C++ Redistributable)",
                "4. 运行系统文件检查器 (在命令提示符中输入: sfc /scannow)"
            ]
            
            if self.auto_repair_check.isChecked():
                auto_repair_possible = True
                auto_repair_action = lambda: self.download_and_install_dll(missing_dll)
        
        elif "access denied" in error_msg or "permission" in error_msg:
            self.append_result("\n诊断结果: 权限不足")
            solutions = [
                "1. 以管理员身份运行该程序",
                "2. 检查程序所在目录的权限设置",
                "3. 检查杀毒软件是否阻止了程序运行"
            ]
        
        elif "not a valid win32 application" in error_msg:
            self.append_result("\n诊断结果: 程序不兼容或已损坏")
            solutions = [
                "1. 重新下载并安装该软件",
                "2. 检查是否下载了适合您系统版本(32位/64位)的软件",
                "3. 尝试在兼容模式下运行(右键程序->属性->兼容性)"
            ]
        
        elif "corrupt" in error_msg or "damaged" in error_msg:
            self.append_result("\n诊断结果: 程序文件可能已损坏")
            solutions = [
                "1. 重新安装该软件",
                "2. 检查磁盘错误(在命令提示符中输入: chkdsk /f)"
            ]
        
        elif "memory" in error_msg or "out of memory" in error_msg:
            self.append_result("\n诊断结果: 内存不足")
            solutions = [
                "1. 关闭其他程序释放内存",
                "2. 增加虚拟内存设置",
                "3. 考虑升级您的硬件内存"
            ]
        
        else:
            self.append_result("\n诊断结果: 未知错误")
            self.append_result("错误信息:")
            self.append_result(error_msg)
            solutions = [
                "1. 检查软件的系统要求是否满足",
                "2. 更新您的操作系统和驱动程序",
                "3. 查看软件的官方文档或支持论坛"
            ]
        
        # 显示解决方案
        if solutions:
            self.append_result("\n可能的解决方案:")
            for solution in solutions:
                self.append_result(solution)
        
        # 自动修复
        if auto_repair_possible and self.auto_repair_check.isChecked():
            self.append_result("\n尝试自动修复...")
            auto_repair_action()
    
    def analyze_exit_code(self, exit_code):
        # 常见退出代码分析
        specific_errors = []
        
        if exit_code == 0xC0000135:  # STATUS_DLL_NOT_FOUND
            specific_errors.append("特定错误: 程序启动时缺少必要的DLL文件")
        elif exit_code == 0xC0000005:  # STATUS_ACCESS_VIOLATION
            specific_errors.append("特定错误: 内存访问冲突(可能是程序bug或硬件问题)")
        elif exit_code == 0xC0000409:  # STATUS_STACK_BUFFER_OVERRUN
            specific_errors.append("特定错误: 堆栈缓冲区溢出(安全保护机制触发)")
        elif exit_code == 0x80000003:  # STATUS_BREAKPOINT
            specific_errors.append("特定错误: 调试断点(可能是程序调试版本)")
        
        if specific_errors:
            self.append_result("\n" + "\n".join(specific_errors))
        
        self.append_result("\n建议操作:")
        self.append_result("1. 检查Windows事件查看器获取更多详细信息")
        self.append_result("2. 更新软件到最新版本")
        self.append_result("3. 联系软件开发商并提供错误代码")
    
    def extract_missing_file(self, error_msg):
        # 从错误消息中提取缺失的文件名
        patterns = ["'", "\"", ":", " "]
        for pattern in patterns:
            start = error_msg.find(pattern) + 1
            end = error_msg.find(pattern, start)
            if start > 0 and end > start:
                return error_msg[start:end]
        
        # 如果没找到明确的文件名，尝试其他方法
        parts = error_msg.split()
        for part in parts:
            if part.endswith(".dll"):
                return part
        
        return "未知文件"
    
    def download_and_install_dll(self, dll_name):
        # 这里应该使用可靠的DLL源，实际应用中应该更谨慎
        # 注意: 从互联网下载DLL文件有安全风险，这里仅为演示
        
        self.append_result(f"\n尝试下载并安装 {dll_name}...")
        
        # 创建系统目录路径
        system_dir = os.path.join(os.environ['SystemRoot'], 'System32')
        if platform.architecture()[0] == '64bit':
            system_dir = os.path.join(os.environ['SystemRoot'], 'SysWOW64')
        
        save_path = os.path.join(system_dir, dll_name)
        
        # 检查是否已经有这个DLL
        if os.path.exists(save_path):
            self.append_result(f"{dll_name} 已存在于系统目录，跳过下载")
            return
        
        # 显示进度条
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # 启动下载线程 (注意: 这里使用了一个模拟URL，实际应用中应该使用可靠的源)
        url = f"https://example.com/dlls/{dll_name}.zip"  # 模拟URL
        temp_path = os.path.join(self.log_dir, f"{dll_name}.zip")
        
        self.download_thread = DownloadThread(url, temp_path)
        self.download_thread.update_progress.connect(self.progress_bar.setValue)
        self.download_thread.download_complete.connect(
            lambda success, msg: self.on_dll_download_complete(success, msg, dll_name, save_path, temp_path)
        )
        self.download_thread.start()
    
    def on_dll_download_complete(self, success, msg, dll_name, save_path, temp_path):
        if success:
            try:
                # 解压并安装DLL (这里简化了过程)
                with ZipFile(temp_path, 'r') as zip_ref:
                    zip_ref.extractall(os.path.dirname(save_path))
                
                self.append_result(f"{dll_name} 安装成功")
                # 注册DLL
                try:
                    subprocess.run(['regsvr32', '/s', save_path], check=True)
                    self.append_result(f"{dll_name} 注册成功")
                except subprocess.CalledProcessError:
                    self.append_result(f"警告: {dll_name} 注册失败，可能需要手动注册")
                
                # 建议重启
                self.append_result("\n某些更改可能需要重启系统才能生效")
            except Exception as e:
                self.append_result(f"安装失败: {str(e)}")
            finally:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
        else:
            self.append_result(f"下载失败: {msg}")
        
        self.progress_bar.setVisible(False)
    
    def append_output(self, text):
        self.output_area.append(text)
        self.output_area.moveCursor(QTextCursor.End)
    
    def append_result(self, text):
        self.result_area.append(text)
        self.result_area.moveCursor(QTextCursor.End)
    
    def finish_diagnosis(self):
        self.run_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        # 保存诊断结果到历史记录
        self.save_diagnosis_to_history()
    
    def save_diagnosis_to_history(self):
        diagnosis_entry = {
            "timestamp": datetime.now().isoformat(),
            "software_path": self.path_input.text(),
            "output": self.output_area.toPlainText(),
            "result": self.result_area.toPlainText(),
            "system_info": self.system_info if self.collect_sysinfo_check.isChecked() else None
        }
        
        self.diagnosis_history.append(diagnosis_entry)
        self.save_history()
        self.load_history()
    
    def load_history(self):
        history_file = os.path.join(self.log_dir, "diagnosis_history.json")
        if os.path.exists(history_file):
            try:
                with open(history_file, 'r', encoding='utf-8') as f:
                    self.diagnosis_history = json.load(f)
            except:
                self.diagnosis_history = []
        
        self.update_history_display()
    
    def save_history(self):
        history_file = os.path.join(self.log_dir, "diagnosis_history.json")
        with open(history_file, 'w', encoding='utf-8') as f:
            json.dump(self.diagnosis_history, f, ensure_ascii=False, indent=2)
    
    def update_history_display(self):
        self.history_list.clear()
        for entry in reversed(self.diagnosis_history[-20:]):  # 显示最近20条记录
            self.history_list.append(f"=== {entry['timestamp']} ===")
            self.history_list.append(f"软件: {entry['software_path']}")
            self.history_list.append(f"结果: {entry['result'].splitlines()[0] if entry['result'] else '无'}")
            self.history_list.append("")
    
    def clear_history(self):
        reply = QMessageBox.question(
            self, '确认', '确定要清除所有诊断历史记录吗?', 
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.diagnosis_history = []
            self.save_history()
            self.history_list.clear()
    
    def export_history(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出历史记录", "", 
            "JSON 文件 (*.json);;文本文件 (*.txt);;所有文件 (*.*)"
        )
        
        if file_path:
            try:
                if file_path.endswith('.json'):
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(self.diagnosis_history, f, ensure_ascii=False, indent=2)
                else:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        for entry in self.diagnosis_history:
                            f.write(f"=== {entry['timestamp']} ===\n")
                            f.write(f"软件: {entry['software_path']}\n")
                            f.write("输出:\n")
                            f.write(entry['output'] + "\n")
                            f.write("结果:\n")
                            f.write(entry['result'] + "\n\n")
                
                QMessageBox.information(self, "成功", "历史记录已成功导出")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出失败: {str(e)}")
    
    def refresh_system_info(self):
        self.system_info = SystemInfoCollector.collect()
        self.sysinfo_text.clear()
        self.sysinfo_text.append(json.dumps(self.system_info, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    try:
        import psutil
    except ImportError:
        print("正在安装所需依赖...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil", "pyqt5", "requests"])
        import psutil
    
    app = QApplication(sys.argv)
    window = SoftwareDiagnosticTool()
    window.show()
    sys.exit(app.exec_())