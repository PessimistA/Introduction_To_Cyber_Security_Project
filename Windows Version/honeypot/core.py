import http.server
import socket
import socketserver
import threading
import requests
import json
import os

AI_BRIDGE_URL = "http://ai_bridge:5000/ask-ai"
MONITOR_URL = "monitor"
MONITOR_PORT = 5000

#this is web trap. it catches hackers looking for vulnerable websites
class honeypot_HTTP_handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        print(f"[DEBUG] Received request for {self.path}", flush=True)

        #log hacker ip and what page they tried to visit
        client_ip = self.client_address[0]
        send_to_monitor(client_ip, f"Web Probe: {self.path}", "attacker")
        try:
            #send http headers to pretend we are in real web server
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            #in case ai fails
            ai_html = "<html><body><h1>System Restricted.</h1></body></html>"

            # try ai
            try:
                # asking ai bridge to generate fake realistic webpage
                advanced_prompt = (
                    f"You are a high end enterprise web server. Generate a highly realistic, "
                    f"professional HTML5 webpage for the requested path: '{self.path}'. "
                    f"Requirements:\n"
                    f"- Use embedded CSS for a modern design.\n"
                    f"- Include realistic elements: a navigation bar, a login form with username and password fields, "
                    f"a fake company footer, copyright dates and so on. they must be well aligned\n"
                    f"- Add convincing server details like 'Apache/2.4.41 (Ubuntu)' or other server details at the bottom.\n"
                    f"- OUTPUT ONLY RAW HTML. No explanations, no markdown formatting."
                )
                payload = {"message": advanced_prompt}

                res = requests.post("http://ai_bridge:5000/ask-ai", json=payload, timeout=45)
                if res.status_code == 200:
                    ai_html = res.json().get("message", ai_html)
            except Exception as ai_err:
                print(f"[DEBUG] AI Bridge skipped: {ai_err}", flush=True)

            #send ai fake created website to hacker's browser
            self.wfile.write(ai_html.encode('utf-8'))
            print(f"[DEBUG] Successfully served {self.path}", flush=True)

        except Exception as e:
            print(f"[ERROR] Web Handler failed: {e}", flush=True)

#this sends real time alerts to dashboard
def send_to_monitor(sender, text, role):
    #sends logs to monitor service via UDP
    data = {"sender": sender, "text": text, "role": role}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(json.dumps(data).encode(), (MONITOR_URL, MONITOR_PORT))
    except:
        pass

#this catches hackers trying to send terminal commands
def handle_client(client_socket, addr, port):
    ip = addr[0]
    send_to_monitor(f"Port {port}", f"New Session from {ip}", "system")

    # this is a fake ubuntu login banner to track hacker
    initial_banner = "Ubuntu 22.04 LTS\nlogin: root\nPassword: \nLast login: Mon Apr 13 14:02:21 2026\nroot@ubuntu:~# "
    client_socket.send(initial_banner.encode())
    while True:
        try:
            #wait for attacker to type command
            data = client_socket.recv(1024).decode().strip()
            if not data or data.lower() in ['exit', 'quit']:
                break

            #send command to ai and lets ai decide how to respond
            payload = {"message": data}

            try:
                res = requests.post("http://ai_bridge:5000/ask-ai", json=payload, timeout=45)

                res_data = res.json()

                if "message" in res_data:
                    response = res_data["message"]
                else:
                    response = f"DEBUG: keys received {list(res_data.keys())}, but no message"
            except requests.exceptions.Timeout:
                response = "bash: system busy, try again"
            except Exception as e:
                response = f"bash: ERROR {e}"

            print(f"[DEBUG] 7. Sending response back to hacker...", flush=True)
            client_socket.send(f"{response}\nroot@ubuntu:~# ".encode())

            #send ai fake response back to attacker
            client_socket.send(f"{response}\nroot@ubuntu:~# ".encode())

            # log everything to monitor
            send_to_monitor(ip, data, "attacker")
            send_to_monitor("AI_HONEYPOT", response, "ai")

        except Exception as e:
            print(f"Session Error: {e}")
            break

    client_socket.close()
def start_honeypot(port):
    #starts tcp listened on background thread
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    print(f"[*] Honeypot listening on port {port}...")
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr, port)).start()


def start_web_honeypot():
    #starts web/http listener on background thread
    # this allows port to be reused immediately if you restart container
    socketserver.TCPServer.allow_reuse_address = True

    try:
        # Creates the server on port 8888 using the Handler class
        with socketserver.TCPServer(("0.0.0.0", 8888), honeypot_HTTP_handler) as httpd:
            print("[*] Web Honeypot listening on port 8888...", flush=True)
            httpd.serve_forever()
    except Exception as e:
        print(f"[!] Web Honeypot failed to start: {e}", flush=True)

if __name__ == "__main__":
    #start both traps at same time using threading

    #start the web honeypot
    web_thread = threading.Thread(target=start_web_honeypot, daemon=True)
    web_thread.start()

    #start the tcp honeypot
    tcp_thread = threading.Thread(target=start_honeypot, args=(80,), daemon=True)
    tcp_thread.start()

    print("[!] All Honeypot systems active (Ports 80 & 8888).")

    #keep main program alive so background threads dont close
    while True:
        import time
        time.sleep(10)
