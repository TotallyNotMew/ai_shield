import os, sys, time, threading, subprocess, shutil, queue, logging
import platform, math, hashlib, json, re
import urllib.request, urllib.error
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

if platform.system() != "Windows":
    print("AI Shield currently supports Windows only.")
    sys.exit(1)

import winreg

def _pip(pkg: str):
    print(f"  Installing {pkg} ...")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", pkg, "-q",
         "--disable-pip-version-check"],
        capture_output=True, check=False
    )

for _imp, _pkg in {
    "watchdog": "watchdog",
    "pystray":  "pystray",
    "PIL":      "Pillow",
}.items():
    try:    __import__(_imp)
    except ImportError: _pip(_pkg)

from watchdog.observers import Observer
from watchdog.events    import FileSystemEventHandler
import pystray
from PIL import Image, ImageDraw

APP_NAME    = "AI Shield"
APP_VERSION = "2.2"

UPDATE_SCRIPT_URL  = "https://raw.githubusercontent.com/TotallyNotMew/ai_shield/main/ai_shield.py"
UPDATE_VERSION_URL = "https://raw.githubusercontent.com/TotallyNotMew/ai_shield/main/version.txt"

ANTHROPIC_API_KEY = ""

AUTO_DELETE_CRITICAL  = False
CHECK_UPDATE_ON_START = True

FILE_SETTLE_DELAY = 3.0

MAX_SCAN_WORKERS = 3

MAX_WATCHER_FILE_SIZE = 20 * 1024 * 1024

DATA_DIR   = Path.home() / "AppData" / "Local" / "AIShield"
LOG_FILE   = DATA_DIR / "shield.log"
QUARANTINE = DATA_DIR / "Quarantine"
DATA_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE.mkdir(parents=True, exist_ok=True)

_h  = Path.home()
_ar = Path(os.environ.get("APPDATA",      str(_h / "AppData" / "Roaming")))
_al = Path(os.environ.get("LOCALAPPDATA", str(_h / "AppData" / "Local")))
_tp = Path(os.environ.get("TEMP", r"C:\Windows\Temp"))

MONITOR_FOLDERS: list[Path] = [
    _h  / "Downloads",
    _h  / "Desktop",
    _h  / "Documents",
    _tp,
    Path(os.environ.get("TMP", str(_tp))),
    _al / "Temp",
    _ar / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
]

DEEP_SCAN_EXTRAS: list[Path] = [
    _h  / "AppData",
    Path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"),
    Path(r"C:\Windows\System32\Tasks"),
    Path(r"C:\Users\Public"),
    Path(r"C:\ProgramData"),
]

TRUSTED_PATH_FRAGMENTS: list[str] = [
    r"\windows\system32",
    r"\windows\syswow64",
    r"\windows\winsxs",
    r"\windows\assembly",
    r"\microsoft.net",
    r"\windowsapps",

    r"\roblox",
    r"\steam",
    r"\steamapps",
    r"\epic games",
    r"\riot games",
    r"\valorant",
    r"\league of legends",
    r"\battle.net",
    r"\blizzard",
    r"\origin games",
    r"\ea games",
    r"\ea desktop",
    r"\ubisoft",
    r"\uplay",
    r"\gog galaxy",
    r"\bethesda",
    r"\rockstar games",
    r"\2k games",
    r"\activision",
    r"\minecraft",
    r"\mojang",
    r"\fortnite",
    r"\epic games\fortnite",
    r"\heroic",

    r"\google",
    r"\chrome",
    r"\mozilla",
    r"\firefox",
    r"\microsoft\edge",
    r"\microsoft office",
    r"\microsoft\teams",
    r"\microsoft\onedrive",
    r"\discord",
    r"\spotify",
    r"\zoom",
    r"\obs studio",
    r"\vlc",
    r"\7-zip",
    r"\winrar",
    r"\notepad++",
    r"\visual studio",
    r"\jetbrains",
    r"\nvidia",
    r"\amd",
    r"\intel",
    r"\realtek",
    r"\logitech",
    r"\razer",
    r"\corsair",
    r"\steelseries",

    r"\program files",
    r"\program files (x86)",
]

TRUSTED_FILENAMES: set[str] = {
    "robloxplayerlauncher.exe", "robloxplayerbeta.exe",
    "robloxstudiolauncher.exe", "robloxstudio.exe",

    "msiexec.exe", "wusa.exe", "wuauclt.exe",
    "dxsetup.exe", "vcredist_x64.exe", "vcredist_x86.exe",
    "vc_redist.x64.exe", "vc_redist.x86.exe",
    "windowsdesktop-runtime-installer.exe",
    "ndp48-x86-x64-allos-enu.exe",

    "uninst.exe", "uninstall.exe",
    "setup.exe", "install.exe",
    "update.exe", "updater.exe",
    "launcher.exe", "patcher.exe",
    "helper.exe",

    "easyanticheat.exe", "eac_setup.exe",
    "battleye.exe", "beeservice.exe",
    "faceit.exe", "vgc.exe", "vgtray.exe",

    "directx_jun2010_redist.exe",
    "oalinst.exe",
    "dotnetfx35.exe",
    "windowsxp-kb942288-v3-x86.exe",
}

TRUSTED_FILENAME_PREFIXES: tuple[str, ...] = (
    "setup_",
    "install_",
    "update_",
    "patch_",
    "redist",
    "vcredist",
    "directx",
    "dotnet",
    "npp.",
    "vlc-",
    "firefox setup",
    "chrome setup",
    "7z",
    "winrar",
)

DANGEROUS_EXTENSIONS: dict[str, str] = {
    ".exe": "Executable — runs code directly on your system",
    ".bat": "Batch script — can silently run system commands",
    ".cmd": "Command script — can silently run system commands",
    ".vbs": "Visual Basic Script — common in malware droppers",
    ".ps1": "PowerShell script — can modify system settings",
    ".scr": "Screen-saver format — often used to disguise malware",
    ".pif": "Legacy program-info file — treated as executable by Windows",
    ".com": "Old-style command format",
    ".jar": "Java archive — can execute arbitrary code via JVM",
    ".msi": "Windows installer — installs software system-wide",
    ".hta": "HTML Application — runs with full system privileges",
    ".wsf": "Windows Script File — can chain multiple scripts",
    ".reg": "Registry file — directly modifies the Windows Registry",
    ".cpl": "Control Panel extension — executed by Windows Explorer",
    ".lnk": "Windows shortcut — can silently run malicious programs",
    ".js":  "JavaScript file — can execute with system access via WScript",
    ".jse": "Encoded JScript — obfuscated JavaScript",
    ".vbe": "Encoded VBScript — obfuscated VBS",
    ".wsh": "Windows Script Host settings file",
    ".xll": "Excel add-in DLL — executes code inside Excel",
    ".cab": "Cabinet archive — used to deliver exploits historically",
    ".iso": "Disk image — can auto-run executables when mounted",
}

_HIGH_RISK_EXTS = {
    ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".scr",
    ".hta", ".pif", ".js", ".jse", ".vbe", ".com",
}

_LOW_CONTEXT_EXTS = {".lnk", ".msi", ".cab", ".iso", ".reg", ".jar"}

SUSPICIOUS_WORDS: list[str] = [
    "keygen", "hack", "cracker", "exploit", "payload", "trojan",
    "ransomware", "backdoor", "rootkit", "stealer", "miner",
    "worm", "botnet", "ratware", "logger", "spyware", "malware", "virus",
    "dropper", "dumper", "crypter",
    "packer", "binder", "clipper", "hvnc",
    "no_survey", "free_robux", "free_vbucks", "generator_v",
    "password_crack", "serial_crack",
]

_WEAK_SUSPICIOUS_WORDS: list[str] = [
    "crack", "patch", "serial", "license_bypass",
    "loader", "activator", "inject", "bypass", "cheat",
    "downloader", "grabber",
]

MAGIC_BYTES: list[tuple[bytes, str]] = [
    (b"\x4d\x5a",          "Windows PE executable (.exe/.dll/.scr)"),
    (b"\x50\x4b\x03\x04",  "ZIP archive"),
    (b"\x50\x4b\x05\x06",  "ZIP archive (empty)"),
    (b"\x25\x50\x44\x46",  "PDF document"),
    (b"\xff\xd8\xff",      "JPEG image"),
    (b"\x89\x50\x4e\x47",  "PNG image"),
    (b"\x47\x49\x46\x38",  "GIF image"),
    (b"\x52\x61\x72\x21",  "RAR archive"),
    (b"\x37\x7a\xbc\xaf",  "7-Zip archive"),
    (b"\x1f\x8b",          "GZIP archive"),
    (b"\xca\xfe\xba\xbe",  "Java class file"),
    (b"\xd0\xcf\x11\xe0",  "MS Office OLE document"),
]

_EXT_TO_MAGIC: dict[str, list[bytes]] = {
    ".exe":  [b"\x4d\x5a"],
    ".dll":  [b"\x4d\x5a"],
    ".scr":  [b"\x4d\x5a"],
    ".pdf":  [b"\x25\x50\x44\x46"],
    ".jpg":  [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".png":  [b"\x89\x50\x4e\x47"],
    ".gif":  [b"\x47\x49\x46\x38"],
    ".zip":  [b"\x50\x4b\x03\x04", b"\x50\x4b\x05\x06"],
    ".rar":  [b"\x52\x61\x72\x21"],
    ".7z":   [b"\x37\x7a\xbc\xaf"],
}

_BINARY_PATTERNS: list[bytes] = [
    b"GetAsyncKeyState",
    b"CreateRemoteThread",
    b"VirtualAllocEx",
    b"WriteProcessMemory",
    b"NtQueryInformationProcess",
    b"IsDebuggerPresent",
    b"cmd.exe /c",
    b"net user ",
    b"net localgroup",
    b"stratum+tcp",
    b"discord.com/api/webhooks",
    b"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    b"RegSetValueEx",
    b"VirtualProtect",
    b"ShellExecuteA",
]

_SCRIPT_PATTERNS: list[str] = [
    "downloadstring",
    "invoke-expression",
    "iex(",
    "frombase64string",
    "net user ",
    "net localgroup",
    "cmd.exe /c",
    "powershell -enc",
    "powershell -w hidden",
    "regsetvalueex",
    "createremotethread",
    "discord.com/api/webhooks",
    "stratum+tcp",
    "getvolumeinfo",
    "getasynckeystate",
    "writeprocessmemory",
]

RISK_COLORS: dict[str, str] = {
    "LOW":      "#d4a017",
    "MEDIUM":   "#cc5500",
    "HIGH":     "#c0392b",
    "CRITICAL": "#7b0000",
}

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)-8s]  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("AIShield")

_REG_RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"

def _startup_cmd() -> str:
    exe = sys.executable
    pw  = exe.replace("python.exe", "pythonw.exe")
    if os.path.isfile(pw):
        exe = pw
    script = os.path.abspath(sys.argv[0])
    return f'"{exe}" "{script}"'

def add_to_startup() -> bool:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_RUN, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, _startup_cmd())
        winreg.CloseKey(key)
        log.info("Registered in Windows startup registry.")
        return True
    except Exception as exc:
        log.error(f"Could not register startup: {exc}")
        return False

def remove_from_startup():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_RUN, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, APP_NAME)
        winreg.CloseKey(key)
        log.info("Removed from Windows startup registry.")
    except Exception:
        pass

def is_in_startup() -> bool:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_RUN, 0, winreg.KEY_READ)
        winreg.QueryValueEx(key, APP_NAME)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False

def _fetch_text(url: str, timeout: int = 10) -> str:
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": f"{APP_NAME}/{APP_VERSION}"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception:
        return ""

def check_for_update() -> tuple[bool, str]:
    if not UPDATE_VERSION_URL:
        return False, ""
    remote = _fetch_text(UPDATE_VERSION_URL).strip()
    if not remote:
        return False, ""
    try:
        rv = tuple(int(x) for x in remote.split("."))
        lv = tuple(int(x) for x in APP_VERSION.split("."))
        return rv > lv, remote
    except Exception:
        return False, ""

def perform_update(remote_version: str) -> bool:
    if not UPDATE_SCRIPT_URL:
        return False
    log.info(f"Downloading update v{remote_version} ...")
    new_code = _fetch_text(UPDATE_SCRIPT_URL, timeout=30)
    if not new_code or "def main(" not in new_code:
        log.error("Update download invalid or incomplete — aborting.")
        return False
    script_path = os.path.abspath(sys.argv[0])
    backup      = script_path + ".bak"
    try:
        shutil.copy2(script_path, backup)
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(new_code)
        log.info(f"Updated to v{remote_version}. Restarting ...")
        subprocess.Popen([sys.executable, script_path])
        sys.exit(0)
    except Exception as exc:
        log.error(f"Update write failed: {exc}")
        if os.path.isfile(backup):
            shutil.copy2(backup, script_path)
        return False

def _is_trusted_path(fp: str) -> bool:
    fp_lo = fp.lower().replace("/", "\\")
    return any(frag in fp_lo for frag in TRUSTED_PATH_FRAGMENTS)

def _is_trusted_filename(name: str) -> bool:
    name_lo = name.lower()
    if name_lo in TRUSTED_FILENAMES:
        return True
    if name_lo.endswith(".exe") and name_lo.startswith(TRUSTED_FILENAME_PREFIXES):
        return True
    return False

def _path_score_adjustment(fp: str) -> int:
    fp_lo = fp.lower()
    total = 0

    downloads_path = str(_h / "downloads").lower()
    if fp_lo.startswith(downloads_path):
        total -= 6

    semi_trusted = [
        (r"\appdata\local\temp\roblox",    20),
        (r"\appdata\local\roblox",         20),
        (r"\appdata\roaming\roblox",       20),
        (r"\appdata\local\steam",          15),
        (r"\appdata\roaming\discord",      15),
        (r"\appdata\local\discord",        15),
        (r"\appdata\local\microsoft",      10),
        (r"\appdata\roaming\microsoft",    10),
        (r"\appdata\local\nvidia",         10),
    ]
    for fragment, reduction in semi_trusted:
        if fragment in fp_lo:
            total -= reduction

    return total

_scan_cache: dict[tuple[str, float], tuple[bool, list[str], str]] = {}
_scan_cache_lock = threading.Lock()

def _cache_lookup(fp: str) -> tuple[bool, list[str], str] | None:
    try:
        mtime = Path(fp).stat().st_mtime
    except OSError:
        return None
    with _scan_cache_lock:
        return _scan_cache.get((fp, mtime))

def _cache_store(fp: str, result: tuple[bool, list[str], str]):
    try:
        mtime = Path(fp).stat().st_mtime
    except OSError:
        return
    with _scan_cache_lock:
        if len(_scan_cache) > 2000:
            keys = list(_scan_cache.keys())
            for k in keys[:1000]:
                del _scan_cache[k]
        _scan_cache[(fp, mtime)] = result

def _read_header(fp: str, n: int = 512) -> bytes:
    try:
        with open(fp, "rb") as f:
            return f.read(n)
    except Exception:
        return b""

def detect_magic(header: bytes) -> str:
    for magic, desc in MAGIC_BYTES:
        if header[:len(magic)] == magic:
            return desc
    return ""

def check_magic_mismatch(fp: str, header: bytes) -> tuple[bool, str]:
    ext = Path(fp).suffix.lower()
    if ext not in _EXT_TO_MAGIC:
        return False, ""
    for em in _EXT_TO_MAGIC[ext]:
        if header[:len(em)] == em:
            return False, ""
    if header[:2] == b"\x4d\x5a":
        return True, (
            f"Magic-byte spoofing detected\n"
            f"      Extension is {ext.upper()} but the file is a Windows PE "
            f"executable — the most common way malware disguises itself."
        )
    actual = detect_magic(header)
    if actual:
        return True, (
            f"Extension / content mismatch\n"
            f"      Extension: {ext.upper()}   Actual content: {actual}"
        )
    return False, ""

def shannon_entropy(fp: str, sample: int = 32768) -> float:
    try:
        with open(fp, "rb") as f:
            data = f.read(sample)
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in freq if c)
    except Exception:
        return 0.0

def scan_file_strings(fp: str) -> list[str]:
    ext = Path(fp).suffix.lower()
    is_binary = ext in {".exe", ".dll", ".scr", ".com"}
    is_script  = ext in {".bat", ".cmd", ".ps1", ".vbs", ".js",
                         ".jse", ".vbe", ".hta", ".wsf"}
    if not (is_binary or is_script):
        return []
    try:
        size = Path(fp).stat().st_size
        if size > 8 * 1024 * 1024:
            return []
        with open(fp, "rb") as f:
            raw = f.read()
    except Exception:
        return []

    found: list[str] = []
    if is_binary:
        for pat in _BINARY_PATTERNS:
            if pat in raw:
                found.append(pat.decode("utf-8", errors="replace"))
    else:
        try:
            text = raw.decode("utf-8", errors="replace").lower()
        except Exception:
            return []
        for pat in _SCRIPT_PATTERNS:
            if pat in text:
                found.append(pat)
    return found

def _word_hits(text: str, word_list: list[str]) -> list[str]:
    hits: list[str] = []
    text_lo = text.lower()
    for word in word_list:
        pattern = r"(?<![a-z0-9])" + re.escape(word) + r"(?![a-z0-9])"
        if re.search(pattern, text_lo):
            hits.append(word)
    return hits

def analyze_file(fp: str) -> tuple[bool, list[str], str]:
    cached = _cache_lookup(fp)
    if cached is not None:
        return cached

    p = Path(fp)
    if not p.exists():
        return False, [], "NONE"

    name    = p.name
    ext     = p.suffix.lower()
    stem_lo = p.stem.lower()
    fp_lo   = fp.lower()

    if _is_trusted_filename(name) or _is_trusted_path(fp):
        result = (False, [], "NONE")
        _cache_store(fp, result)
        return result

    reasons: list[str] = []
    score: int = 0

    score += _path_score_adjustment(fp)

    if ext in DANGEROUS_EXTENSIONS:
        if ext in _LOW_CONTEXT_EXTS:
            score += 1
        else:
            reasons.append(
                f"Dangerous file type ({ext.upper()})\n"
                f"      {DANGEROUS_EXTENSIONS[ext]}"
            )
            score += 2
            if ext in _HIGH_RISK_EXTS:
                score += 1

    parts = name.split(".")
    if len(parts) > 2:
        decoy = "." + parts[-2].lower()
        benign_exts = {
            ".pdf", ".doc", ".docx", ".xls", ".xlsx",
            ".jpg", ".jpeg", ".png", ".mp3", ".mp4",
            ".zip", ".rar", ".txt", ".csv",
        }
        if decoy in benign_exts and ext in DANGEROUS_EXTENSIONS:
            reasons.append(
                f"Double-extension disguise\n"
                f"      Pretends to be {decoy.upper()} but the real extension is "
                f"{ext.upper()} — classic malware technique."
            )
            score += 8

    strong_hits = _word_hits(stem_lo, SUSPICIOUS_WORDS)
    if strong_hits:
        reasons.append(
            f"Suspicious keywords in filename: {', '.join(strong_hits)}\n"
            f"      Legitimate software doesn't normally use these terms."
        )
        score += len(strong_hits) * 2

    if ext in _HIGH_RISK_EXTS:
        weak_hits = _word_hits(stem_lo, _WEAK_SUSPICIOUS_WORDS)
        if weak_hits:
            reasons.append(
                f"Potentially suspicious keywords in filename: {', '.join(weak_hits)}\n"
                f"      These can appear in legitimate files — treated as a minor signal."
            )
            score += len(weak_hits)

    header = _read_header(fp)

    mismatch, mm_reason = check_magic_mismatch(fp, header)
    if mismatch:
        reasons.append(mm_reason)
        score += 10

    if ext in {".exe", ".scr", ".com"}:
        ent = shannon_entropy(fp)
        if ent > 7.7:
            reasons.append(
                f"Extremely high file entropy ({ent:.2f}/8.0)\n"
                f"      File appears heavily packed or encrypted — common malware technique."
            )
            score += 4
        elif ent > 7.4:
            reasons.append(
                f"Elevated file entropy ({ent:.2f}/8.0)\n"
                f"      May contain compressed or encrypted content."
            )
            score += 2

    bad_strings = scan_file_strings(fp)
    if bad_strings:
        reasons.append(
            f"Suspicious API calls or commands found inside the file:\n"
            f"      {', '.join(bad_strings[:6])}"
            + (" …" if len(bad_strings) > 6 else "")
        )
        score += min(len(bad_strings) * 2, 8)

    try:
        size = p.stat().st_size
        if ext == ".exe" and 0 < size < 30_000 and score > 5:
            reasons.append(
                f"Abnormally small executable ({size // 1024} KB)\n"
                f"      Tiny EXEs are often droppers that download real malware."
            )
            score += 2
    except OSError:
        pass

    if ("\\temp\\" in fp_lo or "\\tmp\\" in fp_lo) and ext in _HIGH_RISK_EXTS and score > 6:
        reasons.append(
            "High-risk executable in a Temp folder\n"
            "      Malware commonly stages itself in Temp to avoid detection."
        )
        score += 2

    try:
        import ctypes
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(p))
        if attrs != -1 and (attrs & 0x2):
            reasons.append(
                "File has the Hidden attribute set\n"
                "      Malware hides itself to avoid user detection."
            )
            score += 3
    except Exception:
        pass

    startup_paths = [
        str(_ar / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup").lower(),
        r"c:\programdata\microsoft\windows\start menu\programs\startup",
    ]
    if any(sp in fp_lo for sp in startup_paths) and ext in _HIGH_RISK_EXTS:
        reasons.append(
            "Executable placed in a Windows Startup folder\n"
            "      Will run automatically every time the PC boots."
        )
        score += 5

    score = max(0, score)

    if   score == 0:   result = (False, [], "NONE")
    elif score <= 5:   result = (True, reasons, "LOW")
    elif score <= 9:   result = (True, reasons, "MEDIUM")
    elif score <= 14:  result = (True, reasons, "HIGH")
    else:              result = (True, reasons, "CRITICAL")

    _cache_store(fp, result)
    return result

_whitelist: set[str] = set()

def _reveal_in_explorer(filepath: str):
    norm = os.path.normpath(filepath)
    subprocess.Popen(f'explorer /select,"{norm}"')

def _open_folder(folder: Path):
    os.startfile(str(folder))

def show_threat_window(root, filepath, reasons, risk, auto_quarantined=False):
    import tkinter as tk
    from tkinter import messagebox, scrolledtext

    accent = RISK_COLORS.get(risk, "#c0392b")
    result = {"action": None}

    win = tk.Toplevel(root)
    win.title(
        f"{APP_NAME}  —  "
        + ("Threat Quarantined" if auto_quarantined else "Suspicious File Detected")
    )
    win.configure(bg="#1a1b2e")
    win.resizable(False, False)
    win.attributes("-topmost", True)
    win.grab_set()
    win.focus_force()

    W, H = 650, 540
    win.update_idletasks()
    sx, sy = win.winfo_screenwidth(), win.winfo_screenheight()
    win.geometry(f"{W}x{H}+{(sx - W) // 2}+{(sy - H) // 2}")

    tk.Frame(win, bg=accent, height=4).pack(fill="x", side="top")

    hdr = tk.Frame(win, bg="#22243a", pady=14, padx=20)
    hdr.pack(fill="x")

    badge = tk.Frame(hdr, bg=accent, padx=8, pady=3)
    badge.pack(side="right", anchor="n", padx=(0, 4))
    tk.Label(badge, text=risk, font=("Segoe UI", 8, "bold"),
             fg="white", bg=accent).pack()

    title_text = (
        "CRITICAL Threat — File Quarantined"
        if auto_quarantined else "Suspicious File Detected"
    )
    tk.Label(hdr, text=title_text,
             font=("Segoe UI", 14, "bold"), fg="#e8e8ff", bg="#22243a",
             anchor="w").pack(anchor="w")

    sub_text = (
        "File moved to quarantine. You can restore it from there if it's safe."
        if auto_quarantined else
        "Review the details below and choose what to do."
    )
    tk.Label(hdr, text=sub_text,
             font=("Segoe UI", 9), fg="#8080a8", bg="#22243a",
             anchor="w").pack(anchor="w", pady=(2, 0))

    body = tk.Frame(win, bg="#1a1b2e", padx=20, pady=14)
    body.pack(fill="both", expand=True)

    tk.Label(body, text="FILE",
             font=("Segoe UI", 7, "bold"), fg="#55567a", bg="#1a1b2e",
             anchor="w").pack(anchor="w", pady=(0, 3))

    card_wrap = tk.Frame(body, bg=accent)
    card_wrap.pack(fill="x", pady=(0, 14))
    card = tk.Frame(card_wrap, bg="#22243a", padx=14, pady=10)
    card.pack(fill="x", padx=(3, 0))

    tk.Label(card, text=os.path.basename(filepath),
             font=("Segoe UI", 11, "bold"), fg="#e8e8ff", bg="#22243a",
             wraplength=590, justify="left").pack(anchor="w")

    path_color = "#ffaa44" if auto_quarantined else "#6666aa"
    path_text  = ("[QUARANTINED]  " + filepath) if auto_quarantined else filepath
    tk.Label(card, text=path_text,
             font=("Segoe UI", 8), fg=path_color, bg="#22243a",
             wraplength=590, justify="left").pack(anchor="w", pady=(2, 0))

    tk.Label(body, text="WHY THIS FILE WAS FLAGGED",
             font=("Segoe UI", 7, "bold"), fg="#55567a", bg="#1a1b2e",
             anchor="w").pack(anchor="w", pady=(0, 3))

    box_h = min(max(len(reasons) * 2 + 1, 4), 9)
    txt = scrolledtext.ScrolledText(
        body, height=box_h,
        font=("Segoe UI", 9), fg="#f0c8c8", bg="#22243a",
        relief="flat", padx=12, pady=10, wrap="word",
        state="normal", cursor="arrow",
    )
    txt.pack(fill="x")
    for i, r in enumerate(reasons, 1):
        txt.insert("end", f"{i}.  {r}\n\n")
    txt.config(state="disabled")

    ts = datetime.now().strftime("%B %d, %Y  —  %I:%M %p")
    tk.Label(body, text=f"Detected:  {ts}",
             font=("Segoe UI", 8), fg="#33334a", bg="#1a1b2e").pack(
        anchor="w", pady=(8, 0)
    )

    btn_area = tk.Frame(win, bg="#13141f", pady=14, padx=16)
    btn_area.pack(fill="x", side="bottom")

    BS = dict(
        font=("Segoe UI", 9, "bold"), relief="flat",
        cursor="hand2", pady=10, bd=0, wraplength=130,
        activeforeground="white",
    )

    def act(action: str):
        result["action"] = action
        win.destroy()

    def do_show():
        try:
            _reveal_in_explorer(filepath)
            log.info(f"SHOWN in Explorer: {filepath}")
        except Exception as exc:
            messagebox.showwarning(APP_NAME, f"Could not open Explorer:\n{exc}", parent=win)

    if auto_quarantined:
        tk.Button(
            btn_area, text="OK  (understood)",
            bg="#1a5c35", fg="white", activebackground="#154d2b",
            command=lambda: act("ok"), **BS,
        ).pack(fill="x")
    else:
        for col in range(4):
            btn_area.columnconfigure(col, weight=1)

        tk.Button(btn_area, text="Delete File",
                  bg="#b03030", fg="white", activebackground="#922828",
                  command=lambda: act("delete"), **BS
                  ).grid(row=0, column=0, padx=(0, 5), sticky="ew")

        tk.Button(btn_area, text="Quarantine",
                  bg="#a84a10", fg="white", activebackground="#8f3e0d",
                  command=lambda: act("quarantine"), **BS
                  ).grid(row=0, column=1, padx=5, sticky="ew")

        tk.Button(btn_area, text="Show in Explorer",
                  bg="#1a4f7a", fg="white", activebackground="#154060",
                  command=do_show, **BS
                  ).grid(row=0, column=2, padx=5, sticky="ew")

        tk.Button(btn_area, text="Ignore  (it's safe)",
                  bg="#1a5c35", fg="white", activebackground="#154d2b",
                  command=lambda: act("ignore"), **BS
                  ).grid(row=0, column=3, padx=(5, 0), sticky="ew")

    close_action = "ok" if auto_quarantined else "ignore"
    win.protocol("WM_DELETE_WINDOW", lambda: act(close_action))
    root.wait_window(win)

    if auto_quarantined:
        return

    action = result["action"] or "ignore"
    p      = Path(filepath)

    if action == "delete":
        try:
            if p.exists():
                p.unlink()
            log.info(f"DELETED: {filepath}")
            messagebox.showinfo(APP_NAME, f"File deleted:\n\n{p.name}", parent=root)
        except Exception as exc:
            log.error(f"Delete failed [{filepath}]: {exc}")
            messagebox.showerror(APP_NAME, f"Could not delete file:\n{exc}", parent=root)

    elif action == "quarantine":
        try:
            dest = QUARANTINE / (p.name + f".{int(time.time())}.quarantined")
            if p.exists():
                shutil.move(str(p), str(dest))
            log.info(f"QUARANTINED: {filepath}  ->  {dest}")
            messagebox.showinfo(
                APP_NAME,
                f"File moved to quarantine:\n\n{dest}\n\n"
                "Open the Quarantine folder from the tray menu to review it.",
                parent=root,
            )
        except Exception as exc:
            log.error(f"Quarantine failed [{filepath}]: {exc}")
            messagebox.showerror(APP_NAME, f"Could not quarantine file:\n{exc}", parent=root)

    elif action == "ignore":
        _whitelist.add(p.name)
        log.info(f"IGNORED / whitelisted this session: {filepath}")

def _ai_analyze(findings: list[dict]) -> str:
    if not ANTHROPIC_API_KEY or not findings:
        return ""
    top = findings[:15]
    prompt = (
        "You are a Windows cybersecurity expert. "
        "A file scanner flagged these files on a user's PC. "
        "For each one give: the likely threat type (or why it might be benign), "
        "and a recommended action (safe / quarantine / delete). "
        "Be concise. One line per file:\n"
        "FILENAME — verdict — action\n\n"
        "Files:\n" +
        "\n".join(
            f"- {f['name']}  "
            f"(risk:{f['risk']}, ext:{f.get('ext','?')}, "
            f"flags:{'; '.join(str(r)[:60] for r in f.get('reasons', [])[:2])})"
            for f in top
        )
    )
    try:
        payload = json.dumps({
            "model":      "claude-sonnet-4-6",
            "max_tokens": 1500,
            "messages":   [{"role": "user", "content": prompt}],
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "Content-Type":      "application/json",
                "x-api-key":         ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=40) as resp:
            data = json.loads(resp.read())
            return data["content"][0]["text"]
    except Exception as exc:
        log.error(f"AI analysis error: {exc}")
        return f"(AI analysis unavailable: {exc})"

def _scan_registry_startups() -> list[dict]:
    entries: list[dict] = []
    reg_paths = [
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for hive, path in reg_paths:
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            i   = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, i)
                    val_lo  = val.lower()
                    name_lo = name.lower()
                    flags: list[str] = []
                    kw_hits = _word_hits(name_lo + " " + val_lo, SUSPICIOUS_WORDS)
                    if kw_hits:
                        flags.append(f"suspicious keywords: {', '.join(kw_hits)}")
                    if ("\\temp\\" in val_lo or "\\tmp\\" in val_lo) and not _is_trusted_path(val):
                        flags.append("runs from Temp folder")
                    if "powershell" in val_lo and ("-enc" in val_lo or "-hidden" in val_lo):
                        flags.append("encoded/hidden PowerShell")
                    if flags:
                        entries.append({
                            "location": f"REGISTRY  {path}",
                            "name":     name,
                            "value":    val,
                            "flags":    flags,
                            "risk":     "HIGH",
                            "ext":      "reg",
                            "reasons":  flags,
                        })
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass
    return entries

def _check_hosts_file() -> list[str]:
    hosts  = Path(r"C:\Windows\System32\drivers\etc\hosts")
    issues: list[str] = []
    safe_domains = {
        "localhost", "localhost.localdomain", "broadcasthost",
        "ip6-localhost", "ip6-loopback", "ip6-allnodes", "ip6-allrouters",
    }
    well_known_kw = [
        "google", "microsoft", "windows", "apple", "amazon",
        "facebook", "github", "paypal", "bank", "steam",
    ]
    try:
        for line in hosts.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            ip, domain = parts[0], parts[1].lower()
            if domain in safe_domains:
                continue
            if any(kw in domain for kw in well_known_kw):
                if not ip.startswith(("127.", "0.", "::1")):
                    issues.append(
                        f"{domain}  redirected to  {ip}  (possible DNS hijack)"
                    )
    except Exception:
        pass
    return issues

def _rglob_limited(folder: Path, max_depth: int = 5):
    def _walk(path: Path, depth: int):
        try:
            for item in path.iterdir():
                yield item
                if item.is_dir() and depth < max_depth:
                    yield from _walk(item, depth + 1)
        except PermissionError:
            pass
        except Exception:
            pass
    yield from _walk(folder, 1)

def launch_smart_scan(root):
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox

    scan_cancel  = threading.Event()
    findings_all: list[dict] = []
    scan_stats   = {"scanned": 0, "flagged": 0, "skipped_trusted": 0}

    win = tk.Toplevel(root)
    win.title(f"{APP_NAME}  —  Smart Scan")
    win.configure(bg="#1a1b2e")
    win.resizable(True, True)

    W, H = 720, 580
    win.update_idletasks()
    sx, sy = win.winfo_screenwidth(), win.winfo_screenheight()
    win.geometry(f"{W}x{H}+{(sx - W) // 2}+{(sy - H) // 2}")

    tk.Frame(win, bg="#27ae60", height=4).pack(fill="x")

    hdr = tk.Frame(win, bg="#22243a", pady=12, padx=20)
    hdr.pack(fill="x")
    tk.Label(hdr, text="Smart Scan",
             font=("Segoe UI", 14, "bold"), fg="#e8e8ff", bg="#22243a").pack(anchor="w")
    status_lbl = tk.Label(hdr, text="Preparing scan ...",
                          font=("Segoe UI", 9), fg="#8080a8", bg="#22243a")
    status_lbl.pack(anchor="w", pady=(2, 0))

    pb_frame = tk.Frame(win, bg="#1a1b2e", padx=20, pady=8)
    pb_frame.pack(fill="x")
    pb = ttk.Progressbar(pb_frame, mode="indeterminate", length=680)
    pb.pack(fill="x")
    pb.start(12)
    stats_lbl = tk.Label(pb_frame,
                         text="Scanned: 0   Flagged: 0   Trusted (skipped): 0",
                         font=("Segoe UI", 8), fg="#55567a", bg="#1a1b2e")
    stats_lbl.pack(anchor="w", pady=(4, 0))

    body = tk.Frame(win, bg="#1a1b2e", padx=20, pady=4)
    body.pack(fill="both", expand=True)
    tk.Label(body, text="FINDINGS",
             font=("Segoe UI", 7, "bold"), fg="#55567a", bg="#1a1b2e").pack(
        anchor="w", pady=(0, 3)
    )
    log_txt = scrolledtext.ScrolledText(
        body, font=("Consolas", 8), fg="#c8d0e8", bg="#0e0f1c",
        relief="flat", padx=10, pady=8, wrap="word",
        state="normal", cursor="arrow",
    )
    log_txt.pack(fill="both", expand=True)

    btn_area = tk.Frame(win, bg="#13141f", pady=10, padx=16)
    btn_area.pack(fill="x")
    btn_area.columnconfigure(0, weight=1)
    btn_area.columnconfigure(1, weight=1)

    BS = dict(font=("Segoe UI", 9, "bold"), relief="flat",
              cursor="hand2", pady=8, bd=0, activeforeground="white")

    cancel_btn = tk.Button(
        btn_area, text="Cancel Scan",
        bg="#555577", fg="white", activebackground="#444466",
        command=lambda: scan_cancel.set(), **BS,
    )
    cancel_btn.grid(row=0, column=0, padx=(0, 5), sticky="ew")

    save_btn = tk.Button(
        btn_area, text="Save Report",
        bg="#1a4f7a", fg="white", activebackground="#154060",
        state="disabled", **BS,
    )
    save_btn.grid(row=0, column=1, padx=(5, 0), sticky="ew")

    _pending_lines: list[str] = []
    _flush_scheduled = False

    def _flush_log():
        nonlocal _flush_scheduled
        _flush_scheduled = False
        if not _pending_lines:
            return
        try:
            log_txt.config(state="normal")
            log_txt.insert("end", "\n".join(_pending_lines) + "\n")
            _pending_lines.clear()
            log_txt.see("end")
            log_txt.config(state="disabled")
        except Exception:
            pass

    def _ui_append(text: str):
        _pending_lines.append(text)
        nonlocal _flush_scheduled
        if not _flush_scheduled:
            _flush_scheduled = True
            try:
                root.after(200, _flush_log)
            except Exception:
                pass

    def _ui_status(text: str):
        try:
            status_lbl.config(text=text)
        except Exception:
            pass

    def _ui_stats():
        try:
            stats_lbl.config(
                text=f"Scanned: {scan_stats['scanned']}   "
                     f"Flagged: {scan_stats['flagged']}   "
                     f"Trusted (skipped): {scan_stats['skipped_trusted']}"
            )
        except Exception:
            pass

    def _scan():
        all_locations = list(dict.fromkeys(MONITOR_FOLDERS + DEEP_SCAN_EXTRAS))
        seen_paths: set[str] = set()

        root.after(0, lambda: _ui_append(
            f"=== {APP_NAME} Smart Scan  —  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n"
        ))

        root.after(0, lambda: _ui_status("Scanning startup registry entries ..."))
        reg_issues = _scan_registry_startups()
        if reg_issues:
            root.after(0, lambda: _ui_append(
                f"[REGISTRY]  {len(reg_issues)} suspicious startup entry/entries:\n"
            ))
            for e in reg_issues:
                msg = f"  {e['name']}  =  {e['value'][:90]}  [{', '.join(e['flags'])}]"
                findings_all.append(e)
                root.after(0, lambda m=msg: _ui_append(m))
        else:
            root.after(0, lambda: _ui_append("[REGISTRY]  No suspicious startup entries found."))

        root.after(0, lambda: _ui_status("Checking Windows hosts file ..."))
        hosts_issues = _check_hosts_file()
        if hosts_issues:
            root.after(0, lambda: _ui_append(
                f"\n[HOSTS FILE]  {len(hosts_issues)} suspicious redirect(s):"
            ))
            for h in hosts_issues:
                findings_all.append({"type": "hosts", "name": h, "risk": "HIGH",
                                     "ext": "hosts", "reasons": [h]})
                root.after(0, lambda m=h: _ui_append(f"  WARNING: {m}"))
        else:
            root.after(0, lambda: _ui_append("[HOSTS FILE]  No suspicious entries found."))

        root.after(0, lambda: _ui_append("\n[FILES]  Scanning folders ..."))

        for folder in all_locations:
            if scan_cancel.is_set():
                break
            if not folder.exists():
                continue
            root.after(0, lambda f=str(folder): _ui_status(f"Scanning: {f}"))
            try:
                for fp in _rglob_limited(folder, max_depth=5):
                    if scan_cancel.is_set():
                        break
                    if fp.is_dir():
                        continue
                    fp_str = str(fp)
                    if fp_str in seen_paths:
                        continue
                    if str(DATA_DIR) in fp_str:
                        continue
                    seen_paths.add(fp_str)

                    if _is_trusted_path(fp_str) or _is_trusted_filename(fp.name):
                        scan_stats["skipped_trusted"] += 1
                        scan_stats["scanned"] += 1
                        if scan_stats["scanned"] % 200 == 0:
                            root.after(0, _ui_stats)
                        continue

                    scan_stats["scanned"] += 1
                    if scan_stats["scanned"] % 100 == 0:
                        root.after(0, _ui_stats)

                    try:
                        suspicious, reasons, risk = analyze_file(fp_str)
                    except Exception:
                        continue

                    if suspicious:
                        scan_stats["flagged"] += 1
                        findings_all.append({
                            "type":    "file",
                            "name":    fp.name,
                            "path":    fp_str,
                            "risk":    risk,
                            "ext":     fp.suffix.lower(),
                            "reasons": reasons,
                        })
                        label = f"  [{risk:8s}]  {fp.name}"
                        root.after(0, lambda m=label: _ui_append(m))
                        log.warning(f"SMART SCAN [{risk}]: {fp_str}")

            except Exception as exc:
                log.error(f"Scan error in {folder}: {exc}")

        root.after(0, _ui_stats)

        file_findings = [f for f in findings_all if f.get("type") == "file"]
        if file_findings:
            if ANTHROPIC_API_KEY:
                root.after(0, lambda: _ui_status("Running AI analysis ..."))
                root.after(0, lambda: _ui_append(
                    "\n[AI ANALYSIS]  Sending top findings to Claude AI ..."
                ))
                ai_text = _ai_analyze(file_findings)
                if ai_text:
                    root.after(0, lambda t=ai_text: _ui_append("\n" + t))
            else:
                root.after(0, lambda: _ui_append(
                    "\n[AI ANALYSIS]  No API key configured.\n"
                    "  Add your ANTHROPIC_API_KEY to enable AI-powered verdicts."
                ))

        n_reg   = len([f for f in findings_all if f.get("type") == "registry"])
        n_hosts = len([f for f in findings_all if f.get("type") == "hosts"])
        n_files = len(file_findings)
        cancelled = scan_cancel.is_set()
        summary = (
            f"\n{'=' * 52}\n"
            f"  SCAN {'CANCELLED' if cancelled else 'COMPLETE'}\n"
            f"  Files scanned       : {scan_stats['scanned']}\n"
            f"  Trusted (skipped)   : {scan_stats['skipped_trusted']}\n"
            f"  Suspicious files    : {n_files}\n"
            f"  Registry issues     : {n_reg}\n"
            f"  Hosts file issues   : {n_hosts}\n"
            f"  Total findings      : {len(findings_all)}\n"
            f"{'=' * 52}"
        )
        done_status = "Scan cancelled." if cancelled else "Scan complete."

        def _finish():
            _flush_log()
            _ui_append(summary)
            _ui_status(done_status)
            pb.stop()
            try:
                cancel_btn.config(state="disabled")
                save_btn.config(state="normal")
            except Exception:
                pass

        root.after(0, _finish)

    def _save_report():
        ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = DATA_DIR / f"scan_report_{ts}.txt"
        try:
            content = log_txt.get("1.0", "end")
            report_path.write_text(content, encoding="utf-8")
            subprocess.Popen(["notepad", str(report_path)])
        except Exception as exc:
            messagebox.showerror(APP_NAME, f"Could not save report:\n{exc}")

    save_btn.config(command=_save_report)
    win.protocol("WM_DELETE_WINDOW", lambda: scan_cancel.set() or win.destroy())

    threading.Thread(target=_scan, daemon=True, name="SmartScan").start()

class ShieldHandler(FileSystemEventHandler):
    def __init__(self, alert_q: "queue.Queue[tuple]"):
        self._q        = alert_q
        self._seen:    set[str]           = set()
        self._pending: dict[str, float]   = {}
        self._lock     = threading.Lock()
        self._pool     = ThreadPoolExecutor(max_workers=MAX_SCAN_WORKERS,
                                            thread_name_prefix="Shield")

    def _schedule(self, fp: str):
        with self._lock:
            self._pending[fp] = time.monotonic() + FILE_SETTLE_DELAY

        def _wait_and_eval():
            while True:
                time.sleep(0.5)
                with self._lock:
                    target = self._pending.get(fp)
                    if target is None:
                        return
                    if time.monotonic() < target:
                        continue
                    del self._pending[fp]
                    break
            self._evaluate(fp)

        self._pool.submit(_wait_and_eval)

    def _evaluate(self, fp: str):
        p = Path(fp)
        if not p.exists():
            return

        try:
            if p.stat().st_size > MAX_WATCHER_FILE_SIZE:
                return
        except OSError:
            return

        if _is_trusted_filename(p.name) or _is_trusted_path(fp):
            return

        with self._lock:
            if fp in self._seen or p.name in _whitelist:
                return
            if str(DATA_DIR) in fp:
                return

        suspicious, reasons, risk = analyze_file(fp)
        if not suspicious:
            return

        with self._lock:
            self._seen.add(fp)

        auto_quarantined = False

        if AUTO_DELETE_CRITICAL and risk == "CRITICAL":
            try:
                dest = QUARANTINE / (p.name + f".{int(time.time())}.quarantined")
                shutil.move(str(p), str(dest))
                auto_quarantined = True
                log.warning(f"AUTO-QUARANTINED [CRITICAL]: {fp}  ->  {dest}")
            except Exception as exc:
                log.error(f"Auto-quarantine failed for {fp}: {exc}")
        else:
            log.warning(f"FLAGGED [{risk}]: {fp}")

        self._q.put((fp, reasons, risk, auto_quarantined))

    def on_created(self, event):
        if not event.is_directory:
            self._schedule(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._schedule(event.dest_path)

def _make_tray_image() -> Image.Image:
    size = 64
    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d    = ImageDraw.Draw(img)
    shield = [(32, 3), (61, 15), (61, 37), (32, 61), (3, 37), (3, 15)]
    d.polygon(shield, fill="#27ae60")
    inner  = [(32, 9), (55, 19), (55, 37), (32, 55), (9, 37), (9, 19)]
    d.polygon(inner, fill="#2ecc71")
    d.line([(19, 32), (28, 43), (47, 21)], fill="white", width=5)
    return img

def build_tray_icon(root, stop_evt: threading.Event, observer: Observer) -> pystray.Icon:
    import tkinter as tk
    from tkinter import messagebox

    icon = pystray.Icon(APP_NAME, _make_tray_image(), f"{APP_NAME} — Active")

    def _status(i, item):
        folders    = "\n".join(f"  {f}" for f in MONITOR_FOLDERS if f.exists())
        auto_del   = "Quarantine" if AUTO_DELETE_CRITICAL else "Disabled (ask me)"
        ai_status  = "Configured" if ANTHROPIC_API_KEY else "Not set (optional)"
        upd_status = "Configured" if UPDATE_VERSION_URL else "Not set (optional)"
        root.after(0, lambda: messagebox.showinfo(
            APP_NAME,
            f"{APP_NAME}  v{APP_VERSION}\n\n"
            f"Status:              Running\n"
            f"Auto-quarantine:     {auto_del}\n"
            f"AI analysis:         {ai_status}\n"
            f"Auto-update:         {upd_status}\n\n"
            f"Watching:\n{folders}\n\n"
            f"Log:        {LOG_FILE}\n"
            f"Quarantine: {QUARANTINE}",
        ))

    def _smart_scan(i, item):
        root.after(0, lambda: launch_smart_scan(root))

    def _view_log(i, item):
        subprocess.Popen(["notepad", str(LOG_FILE)])

    def _open_quarantine(i, item):
        try:
            _open_folder(QUARANTINE)
        except Exception as exc:
            root.after(0, lambda: messagebox.showerror(
                APP_NAME, f"Could not open folder:\n{exc}"
            ))

    def _check_update(i, item):
        def _do():
            if not UPDATE_VERSION_URL:
                messagebox.showinfo(
                    APP_NAME,
                    "Auto-update is not configured.\n\n"
                    "Set UPDATE_VERSION_URL and UPDATE_SCRIPT_URL at the top of the script.",
                )
                return
            available, remote = check_for_update()
            if available:
                if messagebox.askyesno(
                    APP_NAME,
                    f"Update available!\n\n"
                    f"Current version : {APP_VERSION}\n"
                    f"New version     : {remote}\n\n"
                    "Download and apply the update now?",
                ):
                    perform_update(remote)
            else:
                messagebox.showinfo(APP_NAME, f"You're on the latest version (v{APP_VERSION}).")
        root.after(0, _do)

    def _toggle_startup(i, item):
        if is_in_startup():
            remove_from_startup()
            root.after(0, lambda: messagebox.showinfo(
                APP_NAME,
                "AI Shield removed from Windows startup.\n"
                "It won't launch automatically on next reboot.",
            ))
        else:
            add_to_startup()
            root.after(0, lambda: messagebox.showinfo(
                APP_NAME,
                "AI Shield added to Windows startup.\n"
                "It will launch automatically on every reboot.",
            ))

    def _quit(i, item):
        stop_evt.set()
        observer.stop()
        i.stop()
        root.after(0, root.quit)

    icon.menu = pystray.Menu(
        pystray.MenuItem(f"{APP_NAME}  v{APP_VERSION}  —  Running", None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Run Smart Scan",         _smart_scan),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Status and Info",        _status),
        pystray.MenuItem("View Log File",          _view_log),
        pystray.MenuItem("Open Quarantine Folder", _open_quarantine),
        pystray.MenuItem("Check for Update",       _check_update),
        pystray.MenuItem("Toggle Auto-Start",      _toggle_startup),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit AI Shield",         _quit),
    )
    return icon

def main():
    import tkinter as tk

    if "--remove" in sys.argv:
        remove_from_startup()
        print("AI Shield removed from Windows startup.")
        sys.exit(0)

    if not is_in_startup():
        add_to_startup()
        log.info("First run: registered in Windows startup.")

    log.info("=" * 60)
    log.info(f"  {APP_NAME} v{APP_VERSION} starting")
    log.info(f"  Script : {os.path.abspath(sys.argv[0])}")
    log.info(f"  AUTO_DELETE_CRITICAL = {AUTO_DELETE_CRITICAL}")
    log.info(f"  Trusted paths        : {len(TRUSTED_PATH_FRAGMENTS)}")
    log.info(f"  Trusted filenames    : {len(TRUSTED_FILENAMES)}")
    log.info("=" * 60)

    if CHECK_UPDATE_ON_START and UPDATE_VERSION_URL:
        def _do_update_check():
            available, remote = check_for_update()
            if available:
                log.info(f"Update available: v{remote} — applying ...")
                perform_update(remote)
        threading.Thread(target=_do_update_check, daemon=True, name="UpdateCheck").start()

    alert_q  : queue.Queue = queue.Queue()
    stop_evt = threading.Event()

    handler  = ShieldHandler(alert_q)
    observer = Observer()
    watched  = 0

    for folder in MONITOR_FOLDERS:
        if folder.exists():
            try:
                observer.schedule(handler, str(folder), recursive=True)
                log.info(f"Watching: {folder}")
                watched += 1
            except Exception as exc:
                log.error(f"Could not watch {folder}: {exc}")

    if watched == 0:
        log.error("No folders could be watched — exiting.")
        sys.exit(1)

    observer.start()
    log.info(f"Observer running — {watched} folder(s) monitored.")

    root = tk.Tk()
    root.withdraw()
    root.title(APP_NAME)
    root.protocol("WM_DELETE_WINDOW", lambda: None)

    tray = build_tray_icon(root, stop_evt, observer)
    threading.Thread(target=tray.run, daemon=True, name="TrayThread").start()

    def poll_alerts():
        while not alert_q.empty():
            try:
                fp, reasons, risk, auto_quarantined = alert_q.get_nowait()
                show_threat_window(root, fp, reasons, risk, auto_quarantined)
            except queue.Empty:
                break
        if not stop_evt.is_set():
            root.after(800, poll_alerts)

    root.after(800, poll_alerts)

    try:
        root.mainloop()
    except Exception as exc:
        log.error(f"Unexpected error in mainloop: {exc}")
    finally:
        observer.stop()
        observer.join(timeout=5)
        log.info(f"{APP_NAME} stopped.")

if __name__ == "__main__":
    main()
