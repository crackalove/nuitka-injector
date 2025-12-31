# 💉 Nuitka / PyInstaller Python Injector

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-win)
![Arch](https://img.shields.io/badge/Arch-x64%20%7C%20x86-orange)
![License](https://img.shields.io/badge/License-MIT-green)

A powerful **Reverse Engineering & Red Teaming framework** designed to inject arbitrary code into running Python processes.

It specifically targets compiled Python applications (Nuitka, PyInstaller, cx_Freeze) where the source code is hidden. The tool injects a DLL payload, initializes the Python API within the victim process, and grants full control over the runtime environment.


> **⚠️ DISCLAIMER**: This tool is for **educational purposes and authorized security testing only**. The author is not responsible for any misuse.


---

## ⌨️ Features

The framework includes **9 distinct payloads** for different phases of analysis:

1.  **Full Dumper**: Extracts all global variables from `__main__`. Useful for dumping hidden configs and database credentials loaded in memory.
2.  **Universal Inspector**: Reflective scanner that discovers **all custom classes** in the target process. Lists methods `[M]` and attributes `[V]` dynamically.
3.  **Signature Fuzzer**: Brute-forces method calls with empty arguments to trigger `TypeError` exceptions, leaking the exact function signature (argument names/types).
4.  **Payday (ACE)**: **Arbitrary Code Execution**. A template to inject and execute your own custom Python logic inside the target context.
5.  **Anti-Anti-Debug**: Patches `IsDebuggerPresent` in memory using `ctypes`, allowing you to attach debuggers (x64dbg, Cheat Engine) to protected processes.
6.  **Deep Memory Scan**: Triggers the Garbage Collector to iterate over the Heap. Searches for secrets (strings/bytes) like `password`, `auth`, `token` deep inside objects.
7.  **MITM Hook**: Installs a Python decorator on target functions to intercept arguments, modify return values, and log traffic in real-time.
8.  **HTTP Spy**: Hooks `requests.Session.request` to capture traffic **before** HTTPS encryption. Bypasses SSL Pinning and certificate checks.
9.  **Environment Dump**: Extracts `os.environ` variables to find Cloud Keys (AWS, Google), Connection Strings, and hidden flags.

---

## 🚀 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/crackalove/nuitka-injector
   cd nuitka-injector
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 💻 Usage
Note: You must run this tool as Administrator to acquire `SeDebugPrivilege` for memory injection.

1. Run the injector:
   ```bash
python injector.py
   ```

2. Select the **Target PID** from the list of detected Python processes.
The tool automatically detects architecture (x86/x64) and Python version.

3. Choose a Payload Mode (1-9) from the menu.

4. Check the output logs generated in the %TEMP% directory (or the script folder).
Select the Target PID from the list of detected Python processes.

The tool automatically detects architecture (x86/x64) and Python version.

Choose a **Payload Mode (1-9)** from the menu.

Check the output logs generated in the `%TEMP%` directory (or the script folder).

## ⚙️ Configuration (Advanced)
Modes **3 (Fuzzer), 4 (Payday),** and **7 (MITM)** act as templates. To target a specific logic in a specific application, you need to edit the injector.py file.
Look for the configuration blocks inside the payload strings:

Python

# =======================================================
# (!) CONFIGURATION: TARGET TO HOOK
# =======================================================

# Target Class Name (e.g., "PaymentProcessor")
TARGET_CLASS_NAME = "PaymentProcessor"  

# Target Method Name (e.g., "process_transaction")
TARGET_METHOD_NAME = "process_transaction"
Inspector, Deep Scan, HTTP Spy, and Dumpers are fully automatic and require no configuration.

🛠 Technology Stack
Python 3: Core logic.

Pymem: For reading/writing process memory and allocating shellcode.

Pefile: For static analysis of DLL exports (Cross-Arch resolution).

Native WinAPI: Direct usage of GetNativeSystemInfo, OpenProcess, and CreateRemoteThread.

Rich: For the professional CLI interface.

📜 License
This project is licensed under the MIT License - see the LICENSE file for details.
