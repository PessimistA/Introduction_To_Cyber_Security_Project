import socket
import json
import threading
import time
import os
import glob
import requests
from datetime import datetime
from fpdf import FPDF
import signal


VIRUSTOTAL_API_KEY = "VIRUS_TOTAL_API_To_Be_Changed" #change it with a real API 

class monitor_core:
    def __init__(self, on_new_log, on_new_session, on_profile_update=None, on_history_loaded=None,
                 on_threat_intel=None):

        self.on_new_log = on_new_log
        self.on_new_session = on_new_session
        self.on_profile_update = on_profile_update
        self.on_history_loaded = on_history_loaded
        self.on_threat_intel = on_threat_intel  #for VirusTotal
        self.is_running = False

        #state and storage
        self.sessions = {}  #holds live data for PDF generator
        self.log_dir = "./data/session_logs"
        self.attacker_db_path = "./data/attacker_profiles/attacker_history.json"


    def load_historical_logs(self, filter_ip=None, filter_date=None):
        #reads old .jsonl log files from the disk
        if not os.path.exists(self.log_dir):
            return []

        results = []
        pattern = os.path.join(self.log_dir, "*.jsonl")

        for filepath in sorted(glob.glob(pattern)):
            filename = os.path.basename(filepath)
            parts = filename.replace(".jsonl", "").split("_")
            file_date = parts[0] if parts else ""
            file_ip = "_".join(parts[1:-1]).replace("_", ".") if len(parts) > 2 else ""

            if filter_date and file_date != filter_date: continue
            if filter_ip and file_ip != filter_ip: continue

            try:
                with open(filepath, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            results.append(entry)
                        except json.JSONDecodeError:
                            pass
            except Exception:
                pass
        return results

    def get_available_dates(self):
        #finds all dates we have logs for
        if not os.path.exists(self.log_dir):
            return []
        files = glob.glob(os.path.join(self.log_dir, "*.jsonl"))
        dates = set()
        for f in files:
            name = os.path.basename(f)
            parts = name.split("_")
            if parts:
                dates.add(parts[0])
        return sorted(list(dates), reverse=True)

    def get_available_ips(self, date=None):
        #finds all attacker ips
        if not os.path.exists(self.log_dir):
            return []
        pattern = os.path.join(self.log_dir, f"{date}_*.jsonl" if date else "*.jsonl")
        files = glob.glob(pattern)
        ips = set()
        for f in files:
            name = os.path.basename(f).replace(".jsonl", "")
            parts = name.split("_")
            if len(parts) >= 3:
                ip_raw = "_".join(parts[1:-1])
                ips.add(ip_raw.replace("_", "."))
        return sorted(list(ips))

    def get_attacker_summary(self):
        #loads saved database of attacker profiles
        if not os.path.exists(self.attacker_db_path): return {}
        try:
            with open(self.attacker_db_path, "r") as f:
                return json.load(f)
        except:
            return {}

    def get_session_stats(self, ip=None):
        logs = self.load_historical_logs(filter_ip=ip)
        stats = {
            "total_commands": 0,
            "unique_ips": set(),
            "commands_by_type": {},
            "risky_commands": 0,
            "file_reads": 0,
            "download_attempts": 0,
            "login_attempts": 0,
        }
        risky = ["wget", "curl", "chmod", "rm", "python", "bash", "sh", "./", "cat /etc/shadow", "id_rsa"]
        for entry in logs:
            cmd = entry.get("command", "")
            role = entry.get("role", "")
            eip = entry.get("ip", "")

            if role == "attacker" and cmd not in ["SESSION_START"]:
                stats["total_commands"] += 1
                stats["unique_ips"].add(eip)
                base = cmd.split()[0] if cmd else "unknown"
                stats["commands_by_type"][base] = stats["commands_by_type"].get(base, 0) + 1
                if any(r in cmd for r in risky):
                    stats["risky_commands"] += 1
                if cmd.startswith("cat "):
                    stats["file_reads"] += 1
                if base in ["wget", "curl"]:
                    stats["download_attempts"] += 1
                if "login" in cmd.lower():
                    stats["login_attempts"] += 1

        stats["unique_ips"] = list(stats["unique_ips"])
        return stats


    #Threat Intel VirusTotal and pdf reporting

    def _check_virustotal(self, ip):
        #queries VT API to see if the ip is a known global threat
        time.sleep(2)
        if not VIRUSTOTAL_API_KEY or ip.startswith("172.") or ip.startswith("127.") or ip.startswith("192."):
            mock_stats = {"malicious": 14, "suspicious": 3, "harmless": 65, "undetected": 10}
            if self.on_threat_intel: self.on_threat_intel(ip, mock_stats, is_simulated=True)
            return

        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        try:
            res = requests.get(f"https://www.virustotal.com/api/v3/ip-addresses/{ip}", headers=headers, timeout=10)
            if res.status_code == 200:
                stats = res.json()["data"]["attributes"]["last_analysis_stats"]
                if self.on_threat_intel: self.on_threat_intel(ip, stats, is_simulated=False)
        except:
            pass

    def generate_pdf_report(self, save_dir="/app/data/reports"):
        #generates a professional Incident Response pdf from live session data
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", "B", 16)
        pdf.cell(0, 10, "SHADOW HONEYPOT: INCIDENT REPORT", ln=True, align="C")
        pdf.set_font("helvetica", "I", 10)
        pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        pdf.ln(10)

        if not self.sessions:
            pdf.set_font("helvetica", "", 12)
            pdf.cell(0, 10, "No live attacks recorded during this monitor session.", ln=True)
        else:
            for ip, data in self.sessions.items():
                pdf.set_font("helvetica", "B", 14)
                pdf.set_text_color(200, 0, 0)
                pdf.cell(0, 10, f"ATTACKER: {ip} | Profile: {data['profile']}", ln=True)
                pdf.set_text_color(0, 0, 0)
                pdf.set_font("courier", "", 10)
                for entry in data.get('commands', []):
                    pdf.cell(0, 6, f"[{entry['time']}] > {entry['text']}", ln=True)
                pdf.ln(10)

        if not os.path.exists(save_dir):
            os.makedirs(save_dir, exist_ok=True)

        filename = f"Threat_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        full_path = os.path.join(save_dir, filename)

        pdf.output(full_path)
        return full_path



    def _analyze_behavior(self, ip, cmd):
        #calculates risk scores and triggers VirusTotal on new IPs
        if ip not in self.sessions:
            self.sessions[ip] = {"commands": [], "risk_score": 0, "profile": "Unknown", "start_time": time.time()}
            #trigger VirusTotal for new hackers
            threading.Thread(target=self._check_virustotal, args=(ip,), daemon=True).start()

        session = self.sessions[ip]
        #store dict for pdf generator
        session["commands"].append({"time": datetime.now().strftime('%H:%M:%S'), "text": cmd})

        critical_cmds = ["wget", "curl", "chmod +x", "rm -rf", "id_rsa", "shadow", "bash -i", "nc ", "/dev/tcp"]
        recon_cmds = ["ls", "whoami", "pwd", "id", "uname", "netstat", "ps", "env", "history"]

        if any(c in cmd for c in critical_cmds): session["risk_score"] += 25
        if any(c in cmd or cmd.startswith(c) for c in recon_cmds): session["risk_score"] += 5

        score = session["risk_score"]
        if score >= 175:
            session["profile"] = "Advanced Threat"
        elif score >= 100:
            session["profile"] = "Professional Attacker"
        elif score >= 60:
            session["profile"] = "Explorer"
        elif len(session["commands"]) >= 25:
            session["profile"] = "Kiddie"
        else:
            session["profile"] = "Bot"

        if self.on_profile_update:
            self.on_profile_update(ip, session["profile"], min(score, 100))


    def start_listening(self, host="0.0.0.0", port=5000):
        self.is_running = True
        threading.Thread(target=self._udp_server, args=(host, port), daemon=True).start()

    def _udp_server(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
        while self.is_running:
            try:
                data, _ = sock.recvfrom(65535)
                log_data = json.loads(data.decode('utf-8'))
                attacker_ip = log_data.get("attacker_ip") or log_data.get("sender", "unknown")

                if log_data.get("role") == "attacker":
                    self._analyze_behavior(attacker_ip, log_data.get("text", ""))

                if log_data.get("type") == "session":
                    self.on_new_session(log_data["attacker_ip"], log_data.get("target", ""), log_data.get("risk", ""))
                else:
                    self.on_new_log(log_data.get("sender", "unknown"), log_data.get("text", ""),
                                    log_data.get("role", "system"))
            except:
                pass



