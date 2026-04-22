
from core import monitor_core
import sys
import time
import signal
from fpdf import FPDF
import datetime
monitor = None

def handle_new_log(sender, text, role):
    colors = {
        "attacker": "\033[91m",  # Red
        "ai": "\033[94m",  # Blue
        "system": "\033[90m",  # Gray
        "reset": "\033[0m"
    }
    color = colors.get(role, colors["reset"])
    print(f"{color}[{sender.upper()}] ({role}): {text}{colors['reset']}")


def handle_new_session(attacker_ip, target, risk):
    print(f"\n\033[93m[!] ALERT: NEW SESSION DETECTED\033[0m")
    print(f"    Source: {attacker_ip} | Target: {target} | Risk: {risk}\n")


def handle_profile_update(ip, profile, risk_score):
    print(f"\033[95m[*] PROFILING {ip}: {profile} (Risk Score: {risk_score}/100)\033[0m")


#Threat Intelligence user interface
def handle_threat_intel(ip, stats, is_simulated):
    malicious_count = stats.get("malicious", 0)

    print("\n\033[41m\033[97m" + "=" * 50 + "\033[0m")
    print(f"\033[91mTHREAT INTEL REPORT VirusTotal \033[0m")
    print(f"Target IP: {ip}")

    if malicious_count > 0:
        print(f"\033[91mWARNING: Flaged as MALICIOUS by {malicious_count} security vendors!\033[0m")
    else:
        print(f"\033[92mStatus: IP appears clean.\033[0m")

    if is_simulated:
        print("\033[93m(Note: Result is simulated for local network testing)\033[0m")
    print("\033[41m\033[97m" + "=" * 50 + "\033[0m\n")

def handle_shutdown(signum, frame):
    global monitor
    print("\n\033[93m[!] Docker Shutdown Detected. Generating final incident report...\033[0m", flush=True)
    if monitor:
        # Save it to the data folder so it syncs with your Windows volume
        saved_path = monitor.generate_pdf_report(save_dir="./data/reports")
        print(f"\033[92m[SUCCESS] Saved as {saved_path}!\033[0m", flush=True)
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)
    monitor = monitor_core(
        on_new_log=handle_new_log,
        on_new_session=handle_new_session,
        on_profile_update=handle_profile_update,
        on_threat_intel=handle_threat_intel
    )

    print("\033[92m MONITOR: LIVE THREAT STREAM \033[0m")
    print("[*] Listening for honeypot logs on UDP port 5000...")

    #start background listener
    monitor.start_listening(host="0.0.0.0", port=5000)

    while True:
        time.sleep(1)
