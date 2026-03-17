"""
SpectraGuard Local Service
Run: python local_service.py
Runs silently in system tray, monitors threats, shows OS notifications.
Zero data leaves the machine.
"""

import threading, time, os, sys, json, subprocess
from datetime import datetime

try:
    import requests as _requests
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

# Try pystray for system tray icon
TRAY_AVAILABLE = False
try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except ImportError:
    pass

# Try plyer for OS notifications
NOTIF_AVAILABLE = False
try:
    from plyer import notification
    NOTIF_AVAILABLE = True
except ImportError:
    pass

BACKEND_URL    = "http://localhost:8000"
CHECK_INTERVAL = 5   # seconds between threat checks

# ── OS Notification ─────────────────────────────────────────────────────────────

def notify(title: str, message: str, urgency: str = "normal"):
    """Send OS notification. Works on Windows, macOS, Linux."""
    if NOTIF_AVAILABLE:
        try:
            notification.notify(
                title    = f"SpectraGuard — {title}",
                message  = message,
                app_name = "SpectraGuard",
                timeout  = 10 if urgency == "critical" else 5,
            )
            return
        except Exception:
            pass

    # Fallback: Windows toast via PowerShell
    if sys.platform == "win32":
        try:
            ps = f'''
Add-Type -AssemblyName System.Windows.Forms
$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = [System.Drawing.SystemIcons]::Shield
$notify.BalloonTipTitle = "SpectraGuard — {title}"
$notify.BalloonTipText = "{message}"
$notify.Visible = $True
$notify.ShowBalloonTip(5000)
Start-Sleep -Seconds 6
$notify.Dispose()
'''
            subprocess.Popen(
                ["powershell", "-WindowStyle", "Hidden", "-Command", ps],
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        except Exception as e:
            print(f"[Notify] Failed: {e}")

    elif sys.platform == "darwin":
        try:
            os.system(f'osascript -e \'display notification "{message}" with title "SpectraGuard — {title}"\'')
        except Exception:
            pass
    else:
        try:
            os.system(f'notify-send "SpectraGuard — {title}" "{message}"')
        except Exception:
            pass

# ── Threat monitor ──────────────────────────────────────────────────────────────

_seen_incident_ids = set()

def check_for_new_threats():
    if not _REQUESTS:
        return
    try:
        res = _requests.get(f"{BACKEND_URL}/incidents", timeout=3,
                            params={"severity": "Critical", "limit": 5})
        incidents = res.json().get("incidents", [])

        for inc in incidents:
            iid = inc.get("incident_id", "")
            if iid in _seen_incident_ids:
                continue
            _seen_incident_ids.add(iid)

            score    = inc.get("sentinel_score", 0)
            severity = inc.get("severity", "Unknown")
            source   = inc.get("ingestion_source", "unknown")
            brief    = inc.get("threat_brief", "Threat detected")[:100]

            if score >= 81:
                notify(f"CRITICAL THREAT ({score}/100)", f"Source: {source}\n{brief}", urgency="critical")
                print(f"[LocalService] 🚨 CRITICAL alert sent — {iid}")
            elif score >= 61:
                notify(f"Likely Malicious ({score}/100)", f"Source: {source}\n{brief}")
                print(f"[LocalService] ⚠ Alert sent — {iid}")

    except Exception:
        pass   # backend not running — silent fail

def monitor_loop():
    print(f"[LocalService] Monitoring started. Checking every {CHECK_INTERVAL}s")
    while True:
        check_for_new_threats()
        time.sleep(CHECK_INTERVAL)

# ── System tray icon ────────────────────────────────────────────────────────────

def make_tray_icon():
    img  = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.polygon([(32,2),(6,14),(6,38),(32,62),(58,38),(58,14)], fill=(10, 132, 255, 230))
    draw.rectangle([22,22,42,46], fill=(255,255,255,200))
    return img

def open_dashboard(icon, item):
    import webbrowser
    webbrowser.open("http://localhost:5173")

def quit_service(icon, item):
    print("[LocalService] Stopping...")
    icon.stop()
    os._exit(0)

def run_tray():
    if not TRAY_AVAILABLE:
        print("[LocalService] pystray not available — running without tray icon")
        print("[LocalService] Install with: pip install pystray pillow")
        monitor_loop()
        return

    icon = pystray.Icon(
        "spectraguard",
        make_tray_icon(),
        "SpectraGuard",
        menu=pystray.Menu(
            pystray.MenuItem("Open Dashboard", open_dashboard, default=True),
            pystray.MenuItem("Status: Running", lambda i, it: None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit SpectraGuard", quit_service),
        )
    )

    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()

    notify("SpectraGuard Active", "Running in background. Zero data leaves your machine.")
    print("[LocalService] ✅ System tray active. Right-click tray icon to open dashboard.")
    icon.run()

# ── Entry point ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("  SpectraGuard Local Service")
    print("  Zero data leaves this machine")
    print("=" * 50)

    if _REQUESTS:
        try:
            import requests as r
            r.get(f"{BACKEND_URL}/health", timeout=2)
            print(f"[LocalService] ✅ Backend detected on {BACKEND_URL}")
        except Exception:
            print(f"[LocalService] ⚠ Backend not running. Start with: uvicorn main:app --port 8000")
            print(f"[LocalService] Monitoring will retry automatically...")
    else:
        print("[LocalService] requests not installed. pip install requests")

    run_tray()
