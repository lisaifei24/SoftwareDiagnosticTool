import sys
import subprocess
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget, 
                             QLabel, QLineEdit, QPushButton, QTextEdit, 
                             QFileDialog, QMessageBox)
from PyQt5.QtCore import QProcess

class SoftwareDiagnosticTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("软件运行诊断助手")
        self.setGeometry(100, 100, 600, 400)
        
        self.init_ui()
        self.process = QProcess()
        self.process.readyReadStandardOutput.connect(self.handle_output)
        self.process.readyReadStandardError.connect(self.handle_error)
        self.process.finished.connect(self.process_finished)
        
    def init_ui(self):
        # 主窗口部件
        main_widget = QWidget()
        layout = QVBoxLayout()
        
        # 软件路径选择
        self.path_label = QLabel("软件路径:")
        self.path_input = QLineEdit()
        self.browse_button = QPushButton("浏览...")
        self.browse_button.clicked.connect(self.browse_software)
        
        path_layout = QVBoxLayout()
        path_input_layout = QVBoxLayout()
        path_input_layout.addWidget(self.path_label)
        path_input_layout.addWidget(self.path_input)
        path_input_layout.addWidget(self.browse_button)
        
        # 运行按钮
        self.run_button = QPushButton("运行诊断")
        self.run_button.clicked.connect(self.run_diagnosis)
        
        # 输出区域
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        
        # 诊断结果区域
        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)
        self.result_area.setPlaceholderText("诊断结果将显示在这里...")
        
        # 添加到主布局
        layout.addLayout(path_input_layout)
        layout.addWidget(self.run_button)
        layout.addWidget(QLabel("运行输出:"))
        layout.addWidget(self.output_area)
        layout.addWidget(QLabel("诊断结果:"))
        layout.addWidget(self.result_area)
        
        main_widget.setLayout(layout)
        self.setCentralWidget(main_widget)
    
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
        
        self.output_area.clear()
        self.result_area.clear()
        
        # 获取软件所在目录
        working_dir = os.path.dirname(software_path)
        
        # 设置工作目录
        self.process.setWorkingDirectory(working_dir)
        
        # 启动程序
        try:
            self.process.start(software_path)
        except Exception as e:
            self.output_area.append(f"启动失败: {str(e)}")
            self.analyze_error(str(e))
    
    def handle_output(self):
        output = self.process.readAllStandardOutput().data().decode('utf-8', errors='ignore')
        if output:
            self.output_area.append(output)
    
    def handle_error(self):
        error = self.process.readAllStandardError().data().decode('utf-8', errors='ignore')
        if error:
            self.output_area.append(f"错误: {error}")
            self.analyze_error(error)
    
    def process_finished(self, exit_code, exit_status):
        if exit_code != 0:
            self.result_area.append(f"\n程序异常退出，退出代码: {exit_code}")
            self.analyze_exit_code(exit_code)
        else:
            self.result_area.append("\n程序正常退出，未检测到明显问题")
    
    def analyze_error(self, error_msg):
        error_msg = error_msg.lower()
        
        # 常见错误模式分析
        if "dll" in error_msg and ("not found" in error_msg or "missing" in error_msg):
            missing_dll = self.extract_missing_file(error_msg)
            self.result_area.append(f"\n诊断结果: 缺少必要的DLL文件 - {missing_dll}")
            self.result_area.append("可能的解决方案:")
            self.result_area.append("1. 重新安装该软件")
            self.result_area.append("2. 从官方来源下载并安装缺少的DLL文件")
            self.result_area.append("3. 安装对应的运行时库(如Visual C++ Redistributable)")
            self.result_area.append("4. 运行系统文件检查器 (在命令提示符中输入: sfc /scannow)")
        
        elif "access denied" in error_msg or "permission" in error_msg:
            self.result_area.append("\n诊断结果: 权限不足")
            self.result_area.append("可能的解决方案:")
            self.result_area.append("1. 以管理员身份运行该程序")
            self.result_area.append("2. 检查程序所在目录的权限设置")
            self.result_area.append("3. 检查杀毒软件是否阻止了程序运行")
        
        elif "not a valid win32 application" in error_msg:
            self.result_area.append("\n诊断结果: 程序不兼容或已损坏")
            self.result_area.append("可能的解决方案:")
            self.result_area.append("1. 重新下载并安装该软件")
            self.result_area.append("2. 检查是否下载了适合您系统版本(32位/64位)的软件")
            self.result_area.append("3. 尝试在兼容模式下运行(右键程序->属性->兼容性)")
        
        elif "corrupt" in error_msg or "damaged" in error_msg:
            self.result_area.append("\n诊断结果: 程序文件可能已损坏")
            self.result_area.append("可能的解决方案:")
            self.result_area.append("1. 重新安装该软件")
            self.result_area.append("2. 检查磁盘错误(在命令提示符中输入: chkdsk /f)")
        
        elif "memory" in error_msg or "out of memory" in error_msg:
            self.result_area.append("\n诊断结果: 内存不足")
            self.result_area.append("可能的解决方案:")
            self.result_area.append("1. 关闭其他程序释放内存")
            self.result_area.append("2. 增加虚拟内存设置")
            self.result_area.append("3. 考虑升级您的硬件内存")
        
        else:
            self.result_area.append("\n诊断结果: 未知错误")
            self.result_area.append("错误信息:")
            self.result_area.append(error_msg)
            self.result_area.append("\n建议:")
            self.result_area.append("1. 检查软件的系统要求是否满足")
            self.result_area.append("2. 更新您的操作系统和驱动程序")
            self.result_area.append("3. 查看软件的官方文档或支持论坛")
    
    def analyze_exit_code(self, exit_code):
        # 常见退出代码分析
        if exit_code == 0xC0000135:  # STATUS_DLL_NOT_FOUND
            self.result_area.append("特定错误: 程序启动时缺少必要的DLL文件")
        elif exit_code == 0xC0000005:  # STATUS_ACCESS_VIOLATION
            self.result_area.append("特定错误: 内存访问冲突(可能是程序bug或硬件问题)")
        elif exit_code == 0xC0000409:  # STATUS_STACK_BUFFER_OVERRUN
            self.result_area.append("特定错误: 堆栈缓冲区溢出(安全保护机制触发)")
        elif exit_code == 0x80000003:  # STATUS_BREAKPOINT
            self.result_area.append("特定错误: 调试断点(可能是程序调试版本)")
        
        self.result_area.append("\n建议操作:")
        self.result_area.append("1. 检查Windows事件查看器获取更多详细信息")
        self.result_area.append("2. 更新软件到最新版本")
        self.result_area.append("3. 联系软件开发商并提供错误代码")
    
    def extract_missing_file(self, error_msg):
        # 从错误消息中提取缺失的文件名
        start = error_msg.find("'") + 1
        end = error_msg.find("'", start)
        if start > 0 and end > start:
            return error_msg[start:end]
        return "未知文件"

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SoftwareDiagnosticTool()
    window.show()
    sys.exit(app.exec_())
