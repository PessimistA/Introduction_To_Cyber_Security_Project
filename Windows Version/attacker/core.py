import socket
import threading
import requests
import json
import os
import hashlib
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import time
import base64


class honeypot_core: #this is trap. it manages fake files, personas and logs hackers
    def __init__(self, ui_update_callback):
        self.ui_update = ui_update_callback
        self.is_running = False
        self.monitor_host = "shadow_monitor"
        self.monitor_port = 5000
        self.connection_history = {}
        self.executor = ThreadPoolExecutor(max_workers=50) #handles connections at once
        self.server_sockets = []

        #create necessary folders for logging and security
        os.makedirs("./quarantine", exist_ok=True)
        os.makedirs("./data/attacker_profiles", exist_ok=True)
        os.makedirs("./data/session_logs", exist_ok=True)
        os.makedirs("./data/file_cache", exist_ok=True)

        self.attacker_db_path = "./data/attacker_profiles/attacker_history.json"
        self.attacker_db = self.attacker_db_load()

    def attacker_db_load(self):
        #loads history of everyone who has tried to do hacking
        if os.path.exists(self.attacker_db_path):
            try:
                with open(self.attacker_db_path, "r") as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def attacker_info_save(self, ip, port, action):
        #remembers a specific hacker and what they did
        if ip not in self.attacker_db:
            self.attacker_db[ip] = {
                "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_connections": 0,
                "history": [],
                "identity_seed": random.randint(10000, 99999) #its a unique ID for hacker
            }
        self.attacker_db[ip]["total_connections"] += 1
        self.attacker_db[ip]["history"].append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "port": str(port),
            "action": action
        })
        try:
            with open(self.attacker_db_path, "w") as f:
                json.dump(self.attacker_db, f, indent=4)
        except Exception:
            pass

    def session_to_file_logging(self, attacker_ip, port, cmd, response, role="attacker"):
        #create filename based on todays date and hackers ip
        today = datetime.now().strftime("%Y-%m-%d")
        log_path = f"./data/session_logs/{today}_{attacker_ip.replace('.', '_')}_port{port}.jsonl"
        entry = { #preparing data packet
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": attacker_ip,
            "port": str(port),
            "role": role,
            "command": cmd,
            "response": response[:500] if response else "" #saves first 500 chars to save space
        }
        try:
            with open(log_path, "a") as f: #a is append, adds new line to end of file without deleting old ones
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    def identity_seed_ip(self, attacker_ip):
        if attacker_ip in self.attacker_db:
            return self.attacker_db[attacker_ip].get("identity_seed", 42)
        return int(hashlib.md5(attacker_ip.encode()).hexdigest()[:8], 16) % 90000 + 10000

    def build_vfs(self, attacker_ip):
        #generate a random virtual environment for each attacker. fake files and company names
        seed = self.identity_seed_ip(attacker_ip)
        rng = random.Random(seed)

        personas = [
            {"company": "QuantumFinance Ltd", "user": "jsmith", "hostname": "qfinance-prod-01",
             "ip": f"10.{rng.randint(0, 9)}.{rng.randint(0, 9)}.{rng.randint(10, 50)}"},
            {"company": "NexaCloud Systems", "user": "devops", "hostname": "nexacloud-db-02",
             "ip": f"172.16.{rng.randint(0, 9)}.{rng.randint(10, 50)}"},
            {"company": "HealthCore Analytics", "user": "hcadmin", "hostname": "hca-backend-03",
             "ip": f"192.168.{rng.randint(1, 5)}.{rng.randint(10, 50)}"},
            {"company": "AeroDefense Corp", "user": "sysadmin", "hostname": "aerodefense-sec-01",
             "ip": f"10.{rng.randint(10, 20)}.{rng.randint(0, 9)}.{rng.randint(10, 50)}"},
        ]
        persona = personas[seed % len(personas)]
        db_pass = f"{''.join(rng.choices('abcdef0123456789', k=12))}!@"

        #fake linux folders and passwords
        vfs = {
            "/": ["bin", "etc", "home", "root", "var", "tmp"],
            "/root": ["Desktop", ".bash_history", "credentials.txt"],
            "/etc": ["passwd", "shadow", "hostname"],
            "/var/log": ["auth.log", "syslog"]
        }

        file_contents = {
            "/etc/hostname": persona["hostname"],
            "/etc/passwd": f"root:x:0:0:root:/root:/bin/bash\n{persona['user']}:x:1000:1000::/home/{persona['user']}:/bin/bash",
            "/root/credentials.txt": f"DB_PASS={db_pass}\nUSER={persona['user']}\nIP={persona['ip']}"
        }

        return vfs, file_contents, {"persona": persona, "db_pass": db_pass}

    def start_all_services(self, api_url, sys_prompt, ports_to_listen):
        if self.is_running:
            return
        self.is_running = True
        for port in ports_to_listen:
            threading.Thread(target=self.listen, args=(port, api_url, sys_prompt), daemon=True).start()
            self.ui_update("port_status", port, ("Active", "#00FF00"))

    def listen(self, port, api_url, sys_prompt):
        #it waits for a connecction on a specific port
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #allow quick restarts
        try:
            server.bind(("0.0.0.0", port))
            server.listen(5)
            self.server_sockets.append(server)
            while self.is_running:
                conn, addr = server.accept()
                self.ui_update("port_status", port, ("BREACH", "#ff0000")) #read alert
                self.executor.submit(self.attacker_handling, conn, addr, api_url, sys_prompt, port)
        except Exception as e:
            print(f"Error on port {port}: {e}")

    def query_ai(self, api_url, sys_prompt, user_input):
        url = f"{api_url}/ai-sor"  #
        payload = {"sys_prompt": sys_prompt, "message": user_input}
        try:
            response = requests.post(url, json=payload, timeout=60)
            return response.json().get('answer', "bash: command not found")
        except:
            return "Connection to AI Bridge lost."

    def attacker_handling(self, conn, addr, api_url, sys_prompt, port):
        attacker_ip = addr[0]
        self.attacker_info_save(attacker_ip, port, "Connection established")
        vfs, file_contents, metadata = self.build_vfs(attacker_ip)

        try:
            conn.sendall(f"Ubuntu 22.04 LTS {metadata['persona']['hostname']} login: ".encode())
            # Add simple interaction loop here if needed
            conn.sendall(b"\nAccess Denied\n")
        finally:
            conn.close()
            self.ui_update("port_status", port, ("Active", "#00FF00"))

    def stop_all_services(self):
        self.is_running = False
        for sock in self.server_sockets:
            sock.close()
        print("All honeypot services stopped.")


class AttackerCore:
    def __init__(self, on_receive_callback, on_disconnect_callback):
        self.on_receive_callback = on_receive_callback
        self.on_disconnect_callback = on_disconnect_callback

        self.sock = None
        self.connected = False

        self.encoding_mode = "plain"
        # it connects through socket

    def connect(self, ip, port, timeout=3.0):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            self.sock.connect((ip, int(port)))
            self.sock.settimeout(None)
            self.connected = True

            threading.Thread(target=self._receive_data, daemon=True).start()
            return True, f"Connection success. Port {port} is open."

        except ConnectionRefusedError:
            self.connected = False
            if self.sock: self.sock.close()
            return False, f"Closed: {port} there is no section who is listening this port."

        except socket.timeout:
            self.connected = False
            if self.sock: self.sock.close()
            return False, f"Time flaw: {port} port is not accessable."

        except Exception as e:
            self.connected = False
            if self.sock: self.sock.close()
            return False, f"Connection error: {str(e)}"

    def disconnect(self):
        if self.connected and self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except:
                pass
        self.connected = False
        self.on_disconnect_callback()

    def set_encoding(self, mode):
        if mode in ["plain", "base64", "hex"]:
            self.encoding_mode = mode

    def send_command(self, cmd):
        if not self.connected or not self.sock:
            return

        try:
            if self.encoding_mode == "base64":
                b64_cmd = base64.b64encode(cmd.encode()).decode()
                cmd = f"echo {b64_cmd} | base64 -d | bash"
            elif self.encoding_mode == "hex":
                hex_cmd = cmd.encode().hex()
                cmd = f"echo '{hex_cmd}' | xxd -r -p | bash"

            self.sock.sendall((cmd + "\n").encode('utf-8'))
        except:
            self.disconnect()

    # automated attack
    def run_automated_payload(self, payload_list, delay=1.0):
        def _execute():
            for cmd in payload_list:
                if not self.connected:
                    break
                self.send_command(cmd)
                time.sleep(delay)

        if self.connected:
            threading.Thread(target=_execute, daemon=True).start()

    def _receive_data(self):
        while self.connected:
            try:
                data = self.sock.recv(4096)
                if not data: break

                self.on_receive_callback(data.decode('utf-8', errors='replace'))
            except:
                break
        self.disconnect()
