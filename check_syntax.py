#!/usr/bin/env python3
"""批量检查Python文件语法错误"""
import os
import sys
import py_compile

def check_python_file(filepath):
    """检查单个Python文件"""
    try:
        py_compile.compile(filepath, doraise=True)
        return True, None
    except py_compile.PyCompileError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)

def scan_directory(directory, exclude_dirs=None):
    """递归扫描目录下所有Python文件"""
    if exclude_dirs is None:
        exclude_dirs = {'__pycache__', '.git', 'venv', 'env', '.venv'}
    
    python_files = []
    for root, dirs, files in os.walk(directory):
        # 移除排除的目录
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))
    
    return python_files

def main():
    """主函数"""
    # 检查 xuanjian-security/backend 目录
    backend_dir = 'xuanjian-security/backend'
    
    if not os.path.exists(backend_dir):
        print(f"错误: 目录 {backend_dir} 不存在")
        sys.exit(1)
    
    print(f"开始检查目录: {backend_dir}")
    print("=" * 60)
    
    python_files = scan_directory(backend_dir)
    error_count = 0
    success_count = 0
    
    for filepath in sorted(python_files):
        success, error = check_python_file(filepath)
        if success:
            success_count += 1
            print(f"✓ {filepath}")
        else:
            error_count += 1
            print(f"✗ {filepath}")
            print(f"  错误: {error}")
            print()
    
    print("=" * 60)
    print(f"检查完成: 共检查 {len(python_files)} 个文件")
    print(f"成功: {success_count} 个")
    print(f"失败: {error_count} 个")
    
    if error_count > 0:
        sys.exit(1)

if __name__ == '__main__':
    main()
