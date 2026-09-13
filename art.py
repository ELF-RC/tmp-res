import multiprocessing
import sys
import threading
import traceback
import os

# Nuitka onefile / 精简环境 locale=C 导致 stdout/stderr 为 ASCII，
# 中文输出全部 UnicodeEncodeError。在最早期强制切 UTF-8。
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
if hasattr(sys.stdin, 'reconfigure'):
    try:
        sys.stdin.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


RED = '\x1b[91m'
YELLOW = '\x1b[93m'
BOLD = '\x1b[1m'
CYAN = '\x1b[36m'
CLOSE = '\x1b[0m'


def _render_crash_report(exception_type, exception, tb):
    """渲染崩溃报告（纯输出，不抛异常）。"""
    # 提取完整调用栈
    try:
        tb_lines = traceback.format_exception(exception_type, exception, tb)
    except Exception:
        tb_lines = [f'{exception_type.__name__}: {exception}\n']

    # 从调用栈中定位崩溃的子模块和函数
    crash_module = '未知'
    crash_function = '未知'
    crash_location = '未知'
    try:
        if tb is not None:
            frame = tb
            depth = 0
            while frame.tb_next is not None and depth < 200:
                frame = frame.tb_next
                depth += 1
            co = frame.tb_frame.f_code
            crash_file = co.co_filename
            crash_function = co.co_name
            crash_line = frame.tb_lineno
            try:
                rel_path = os.path.relpath(crash_file, os.path.dirname(os.path.abspath(__file__)))
            except (ValueError, OSError):
                rel_path = crash_file
            crash_location = f'{rel_path}:{crash_line}'
            basename = os.path.basename(crash_file)
            if basename.endswith('.py'):
                crash_module = basename[:-3]
    except Exception:
        pass

    # 清屏
    try:
        os.system('clear' if os.name != 'nt' else 'cls')
    except Exception:
        pass

    # 输出崩溃报告
    print(f"{RED}{BOLD}  ERROR!!!{CLOSE}")
    print(f"{YELLOW}崩溃模块:{CLOSE}  {CYAN}{crash_module}{CLOSE}")
    print(f"{YELLOW}崩溃函数:{CLOSE}  {CYAN}{crash_function}(){CLOSE}")
    print(f"{YELLOW}崩溃位置:{CLOSE}  {CYAN}{crash_location}{CLOSE}")
    print(f"{YELLOW}异常类型:{CLOSE}  {RED}{exception_type.__name__}{CLOSE}")
    print(f"{YELLOW}异常信息:{CLOSE}  {RED}{exception}{CLOSE}")
    print()
    print(f"{BOLD}LOG：{CLOSE}")
    print()
    for line in tb_lines:
        for subline in line.rstrip().split('\n'):
            print(f'  {subline}')
    print()


def _safe_input(prompt=''):
    """安全的 input，捕获 KeyboardInterrupt 和 EOFError 防止二次崩溃。"""
    try:
        input(prompt)
    except (KeyboardInterrupt, EOFError):
        pass
    except UnicodeEncodeError:
        # 非 UTF-8 终端（如 LANG=C）下中文 prompt 无法编码，降级为英文
        try:
            input('Press Enter to exit...')
        except (KeyboardInterrupt, EOFError, UnicodeEncodeError):
            pass


def exception_handler(exception_type, exception, tb):
    """全局异常处理器（主线程）。"""
    try:
        _render_crash_report(exception_type, exception, tb)
    except Exception as fallback:
        # handler 自身崩溃时的兜底：直接用 stderr 原始输出
        sys.stderr.write(f'\n=== CRASH (exception handler failed) ===\n')
        sys.stderr.write(f'Original: {exception_type.__name__}: {exception}\n')
        sys.stderr.write(f'Handler error: {type(fallback).__name__}: {fallback}\n')
        try:
            traceback.print_tb(tb, file=sys.stderr)
        except Exception:
            pass
        sys.stderr.write('=========================================\n')
    _safe_input(f'{YELLOW}按任意键退出...{CLOSE}')
    os._exit(1)


def _thread_exception_handler(args):
    """子线程异常处理 — threading.excepthook 回调。"""
    try:
        _render_crash_report(args.exc_type, args.exc_value, args.exc_traceback)
    except Exception:
        sys.stderr.write(f'\n=== THREAD CRASH ===\n')
        sys.stderr.write(f'{args.exc_type.__name__}: {args.exc_value}\n')
        traceback.print_tb(args.exc_traceback, file=sys.stderr)
        sys.stderr.write('====================\n')
    _safe_input(f'{YELLOW}按任意键退出...{CLOSE}')
    os._exit(1)


def _patch_subprocess_excepthook():
    """让 multiprocessing 子进程也能用崩溃处理。"""
    _original_init = multiprocessing.Process.__init__

    def _patched_init(self, *args, **kwargs):
        _original_init(self, *args, **kwargs)
        _original_run = self.run

        def _wrapped_run():
            sys.excepthook = exception_handler
            try:
                _original_run()
            except Exception:
                exception_handler(*sys.exc_info())

        self.run = _wrapped_run

    multiprocessing.Process.__init__ = _patched_init


def init():
    from scripts.utils import init_bin_path
    from scripts.config import check_permissions
    from scripts.menu import menu_once
    init_bin_path()
    check_permissions()
    menu_once()


if __name__ == '__main__':
    multiprocessing.freeze_support()
    sys.excepthook = exception_handler
    threading.excepthook = _thread_exception_handler
    _patch_subprocess_excepthook()
    init()
