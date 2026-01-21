#!/usr/bin/env python3
"""
cProfile 分析 export_hgar 的性能瓶颈
"""

import cProfile
import pstats
import sys
import os
from io import StringIO
from pathlib import Path

# Add the project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.cli.main import App


def profile_export_hgar(output_dir: str = None, prefix: str = None):
    """
    Profile export_hgar 操作
    
    Args:
        output_dir: 输出目录，默认为 ./output_profile
        prefix: 前缀过滤，默认为 None (导出所有)
    """
    if output_dir is None:
        output_dir = "./output_profile"
    
    # 确保输出目录存在
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    print(f"Profiling export_hgar:")
    print(f"  Output directory: {output_dir}")
    print(f"  Prefix: {prefix if prefix else '(all)'}")
    print("-" * 60)
    
    # 创建 profiler
    pr = cProfile.Profile()
    pr.enable()
    
    try:
        # 执行导出操作
        App.output_hgar(output_dir, prefix)
    finally:
        pr.disable()
    
    # 生成报告
    print("\n" + "=" * 60)
    print("CPROFILE STATISTICS")
    print("=" * 60 + "\n")
    
    # 按总时间排序
    print("Top 30 functions by cumulative time:")
    print("-" * 60)
    s = StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
    ps.print_stats(30)
    print(s.getvalue())
    
    # 按自身时间排序
    print("\n" + "=" * 60)
    print("Top 30 functions by own time:")
    print("-" * 60)
    s = StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats('time')
    ps.print_stats(30)
    print(s.getvalue())
    
    # 保存详细报告到文件
    report_file = os.path.join(output_dir, "profile_report.txt")
    with open(report_file, 'w') as f:
        ps = pstats.Stats(pr, stream=f).sort_stats('cumulative')
        f.write("=" * 60 + "\n")
        f.write("CPROFILE REPORT - Cumulative Time\n")
        f.write("=" * 60 + "\n\n")
        ps.print_stats()
        
        f.write("\n\n" + "=" * 60 + "\n")
        f.write("CPROFILE REPORT - Own Time\n")
        f.write("=" * 60 + "\n\n")
        ps = pstats.Stats(pr, stream=f).sort_stats('time')
        ps.print_stats()
    
    print(f"\nDetailed report saved to: {report_file}")


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Profile export_hgar operation using cProfile'
    )
    parser.add_argument(
        '-o', '--output',
        default='./output_profile',
        help='Output directory (default: ./output_profile)'
    )
    parser.add_argument(
        '-p', '--prefix',
        default=None,
        help='Prefix filter for HGAR names (e.g., "a", "cev")'
    )
    
    args = parser.parse_args()
    
    profile_export_hgar(args.output, args.prefix)
