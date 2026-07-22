import ctypes
import ctypes.wintypes
import hashlib
import platform
import subprocess
import uuid


class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _run_hidden(args, timeout=10):
    """Run a subprocess without showing a console window."""
    kwargs = {'shell': False, 'text': True, 'timeout': timeout}
    if platform.system() == "Windows":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        kwargs['startupinfo'] = startupinfo
    return subprocess.check_output(args, **kwargs)


def get_device_fingerprint() -> dict:
    """Generate unique device fingerprints based on hardware information.

    Returns a dictionary with four separate fingerprints:
    - mac_fingerprint: Based on MAC address
    - cpu_fingerprint: Based on CPU ID
    - motherboard_fingerprint: Based on motherboard serial number
    - bios_fingerprint: Based on BIOS serial number

    These fingerprints are tied to the physical device and cannot be easily changed
    without replacing hardware components.
    """
    fingerprints = {
        "mac": "",
        "cpu": "",
        "motherboard": "",
        "bios": ""
    }

    mac = uuid.getnode()
    mac_hex = ':'.join(('%012X' % mac)[i:i+2] for i in range(0, 12, 2))
    fingerprints["mac"] = hashlib.sha256(f"mac:{mac_hex}".encode('utf-8')).hexdigest()

    if platform.system() == "Windows":
        try:
            result = _run_hidden(
                ['powershell', '-Command', '(Get-CimInstance Win32_Processor).ProcessorId']
            )
            cpu_id = result.strip()
            if cpu_id:
                fingerprints["cpu"] = hashlib.sha256(f"cpu:{cpu_id}".encode('utf-8')).hexdigest()
        except Exception:
            pass

        try:
            result = _run_hidden(
                ['powershell', '-Command', '(Get-CimInstance Win32_BaseBoard).SerialNumber']
            )
            mb_serial = result.strip()
            if mb_serial:
                fingerprints["motherboard"] = hashlib.sha256(f"motherboard:{mb_serial}".encode('utf-8')).hexdigest()
        except Exception:
            pass

        try:
            result = _run_hidden(
                ['powershell', '-Command', '(Get-CimInstance Win32_BIOS).SerialNumber']
            )
            bios_serial = result.strip()
            if bios_serial:
                fingerprints["bios"] = hashlib.sha256(f"bios:{bios_serial}".encode('utf-8')).hexdigest()
        except Exception:
            pass
    else:
        try:
            result = _run_hidden(
                ['cat', '/proc/cpuinfo'], timeout=5
            )
            for line in result.split('\n'):
                if 'model name' in line or 'Hardware' in line:
                    fingerprints["cpu"] = hashlib.sha256(f"cpu:{line.strip()}".encode('utf-8')).hexdigest()
                    break
        except Exception:
            pass

    return fingerprints