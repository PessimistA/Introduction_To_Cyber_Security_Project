# 🛡️ ShadowGuard: AI-Driven Honeypot System

ShadowGuard is a highly interactive honeypot system developed to trap cyber attackers, analyze their behavior and gather threat intelligence. Unlike traditional static honeypots, it integrates with Large Language Models (LLMs) to build a unique, dynamic and convincing Virtual File System tailored to each attacker's IP address.

## 💻 Cross-Platform Support
This project has been updated to support two distinct environments:

* **Linux Version (Docker/GUI):** The original containerized version using Docker and X11 forwarding.
* **Windows Version (Native CLI):** A lightweight, headless Python port designed for Windows or any system without X-Server/XLauncher support.

---

## ✨ Key Features
* **🧠 Dynamic AI Reactions:** Uses a local LLM to generate realistic terminal outputs in seconds based on the attacker's commands.
* **🕵️ Attacker Profiling & Risk Scoring:** Instantly analyzes commands (such as `wget`, `cat /etc/shadow`) to calculate risk scores and profile the attacker, which range from *Bot* to *Advanced Threat*.
* **🦠 VirusTotal Integration:** Automatically queries the VirusTotal API to check if an attacking IP is a known global threat.
* **📄 Automated Incident Reporting:** Generates professional PDF Threat Reports summarizing attacker commands and risk profiles upon system shutdown.
* **📂 Personalized Virtual Systems:** Hashes the attacker's IP to generate a consistent identity seed, presenting a fake corporate profile (such as *QuantumFinance Ltd* or *NexaCloud Systems*), complete with fake credentials.
* **🕸️ Built-In Red Team Module:** Includes an attacker client, `main_cli.py`, capable of encoding payloads in Base64 or Hex to test the honeypot's evasion detection.

---

## 🏗️ Architecture & Core Components
The system is split into four primary components:

1. **The Honeypot (`honeypot_core`):** The main trap. Opens listening ports, handles incoming socket connections and builds the fake Linux filesystem.
2. **The AI Bridge (`app.py`):** A Flask API that acts as a middleman between the isolated Honeypot and the host machine's LM Studio, ensuring the AI replies strictly as a Linux terminal.
3. **The Monitor (`monitor_cli.py`):** A live UDP listener that displays real-time threat intelligence, logs attacker keystrokes and generates the final PDF report.
4. **The Attacker (`main_cli.py`):** A Red Team testing tool to connect to the honeypot and simulate manual or automated attacks.

---

## 🛠️ Installation & Setup

### Requirements for BOTH versions:
* **LM Studio:** You need a local AI model running. Go to the "Local Server" tab in LM Studio and start the server at `localhost:1234`.
* **VirusTotal API:** Open `core.py` and replace `VIRUSTOTAL_API_KEY = "VIRUS_TOTAL_API_To_Be_Changed"` with your actual API key for full threat intel functionality.

### 🪟 Windows Environment (Native CLI - No UI)
This version is optimized to run natively without Docker or XLauncher. Ensure Python 3.10+ is installed.

1. **Install required Python libraries:**
   ```powershell
   pip install flask requests fpdf
   ```

2. **Open a terminal and start the Monitor to watch for attacks:**
   ```powershell
   python monitor_cli.py
   ```

3. **Open a second terminal to run the Attacker (Red Team) module to test the system:**
   ```powershell
   python main_cli.py
   ```

*(Note: When you shut down the monitor by pressing `Ctrl+C`, it will automatically generate a PDF report in the `./data/reports` folder)*

---

## ⚠️ Legal Disclaimer
This project was developed solely for educational purposes, cybersecurity research, and the analysis of defense mechanisms. Because it contains high-interaction features and directly executes AI-generated text, **it is not recommended to connect it directly to production networks without adequate isolation**. The developers accept no responsibility for any consequences arising from the misuse of this tool.
