# Accurate-Cyber-Defense-Network-Intrusion-Cyber-Bot
Accurate-Cyber-Defense-Network-Intrusion-Cyber-Bot (ACDNIC-Bot) is an advanced, lightweight, and intelligent cybersecurity tool designed to monitor, detect, and report suspicious network activities in real time. 


Built specifically for small to medium-sized organizations, educational institutions, and cybersecurity enthusiasts, ACDNIC-Bot provides robust network intrusion monitoring, anomaly detection, and automated alerts through Telegram integration, all while being easily deployable on PythonAnywhere — a popular cloud-based Python platform.

In an era where cyber threats are growing both in frequency and complexity, ACDNIC-Bot empowers users to actively defend their digital environments by leveraging open-source technologies, Python programming, and remote bot communication via Telegram. The bot is ideal for IT admins, students, hobbyists, and developers who want an automated tool that watches over network traffic and gives instant updates on possible breaches, unauthorized access attempts, or malware-related behaviors.

Key Features
1. Real-Time Network Intrusion Monitoring
At the heart of ACDNIC-Bot is a sophisticated network monitoring engine that uses Python-based packet sniffers (like Scapy or socket modules) to continuously observe incoming and outgoing packets on the host machine. It filters, logs, and analyzes packet metadata such as IP addresses, ports, MAC addresses, and protocols. Based on predefined rules or AI models, it detects behaviors that indicate intrusion attempts — such as port scanning, spoofed packets, flood attacks, or command-and-control communications.

2. Threat Classification and Analysis
Using machine learning algorithms or rule-based logic, the bot classifies threats into categories like:

Reconnaissance Attacks (e.g., Nmap scans)

Brute Force Attacks (e.g., repeated SSH login attempts)

DoS/DDoS behavior (e.g., ICMP flood, SYN flood)

Suspicious Traffic Patterns (e.g., unusual port activity or encrypted backdoor traffic)

Alerts are then customized based on severity, helping the administrator prioritize their response.

3. Telegram Bot Integration
To ensure instant alerts and remote accessibility, ACDNIC-Bot integrates seamlessly with Telegram Bot API. Users simply:

Create a Telegram bot using BotFather.

Obtain a bot token and chat ID.

Configure the credentials in the bot script.

Once configured, the bot automatically sends real-time intrusion alerts, threat reports, and summary statistics directly to the user’s Telegram app. This ensures that even while away from the system, administrators remain in control and informed of any security incidents.

4. PythonAnywhere Hosting Compatibility
ACDNIC-Bot is optimized for deployment on PythonAnywhere, a cloud platform that allows users to run and schedule Python scripts 24/7. With a lightweight codebase, minimal dependencies, and secure settings, the bot:

Runs on PythonAnywhere’s free or paid plans.

Requires no complex installations.

Can be scheduled as a recurring task or run as a web app.

Sends alerts via Telegram without requiring local server infrastructure.

This makes it highly accessible for users with limited technical infrastructure or those looking for a serverless cloud monitoring approach.

5. Customizable Rules and Configuration
Users can easily modify the detection rules via a configuration file or admin interface. This includes:

Whitelist IPs and ports

Adjust sensitivity for certain attack patterns

Enable or disable Telegram alerts

Set auto-blocking behaviors (optional)

This flexibility ensures ACDNIC-Bot can be adapted to various environments, from home networks to academic labs.

How It Works
Initialization
When launched, the bot initializes by loading user-defined configurations, sets up the packet sniffer, and establishes a connection with the Telegram bot.

Packet Capture
It starts sniffing packets in real time using tools like Scapy or socket. For each packet, it extracts relevant data (source/destination IPs, protocols, flags, etc.).

Threat Detection
It evaluates traffic patterns against built-in and user-defined intrusion detection logic. If suspicious activity is found, it assigns a threat level (LOW, MEDIUM, HIGH).

Alert Dispatch
Upon detection of an event, a detailed alert message is generated, including:

Threat type and severity

Source and destination IP/port

Timestamp

Recommended action

This message is immediately sent to the Telegram chat configured by the user.

Logging and Reporting
All activity is logged in a secure, timestamped format for further forensic analysis. Daily or weekly reports can be sent via Telegram or exported as logs.

Telegram Alert Example
yaml
Copy
Edit
⚠️ ALERT: Possible Intrusion Detected
Type: Port Scanning Activity
Severity: HIGH
Source IP: 192.168.0.150
Destination Port: 22, 80, 443
Time: 2025-07-20 20:15:33
Recommended Action: Check system logs and block IP.
Use Cases
Home Network Security: Keep your personal Wi-Fi safe from neighbors or unknown scanners.

University Labs: Monitor lab networks for malicious activity or hacking attempts.

Small Businesses: Get intrusion alerts even when off-site, using the Telegram integration.

Cybersecurity Students: Learn real-world intrusion detection with hands-on tools.

Cyber Range Simulations: Integrate into testbeds for red-team vs blue-team exercises.

Deployment Steps (PythonAnywhere)
Sign up at https://www.pythonanywhere.com

Upload the acdnic_bot.py script and any configuration files.

Install dependencies using the Bash console (pip install --user scapy requests).

Configure Scheduled Tasks to run the script periodically or manually run via console.

Set up your Telegram Bot Token and Chat ID in a .env file or directly in script.

Start Monitoring: Receive intrusion alerts directly to your Telegram in minutes.

**How to install**

git clone https://github.com/Iankulani/Accurate-Cyber-Defense-Network-Intrusion-Cyber-Bot.git

**How to run**

python Accurate-Cyber-Defense-Network-Intrusion-Cyber-Bot.py

