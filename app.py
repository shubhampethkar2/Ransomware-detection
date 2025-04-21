import streamlit as st
import pandas as pd
import joblib
import psutil
import numpy as np
import plotly.express as px
import time
import os
import random
import requests

# Load trained models
model1 = joblib.load('ransomware_detection_model.pkl')
model2 = joblib.load('ransomware_detection_model_v2.pkl')

st.title("🚀 Ransomware Early Detection & Response System")
st.write("🔍 **Real-Time Monitoring Enabled** - The system automatically detects ransomware activity.")

# Placeholders for UI
process_table = st.empty()
cpu_chart = st.empty()
ram_chart = st.empty()
file_scan_result = st.empty()

# Expected 70 Features (From Model Training)
expected_features = [
    "CreateProcessInternalW", "CreateServiceA", "CreateServiceW", "CryptExportKey", "CryptGenKey",
    "DeviceIoControl", "EnumServicesStatusA", "EnumServicesStatusW", "FindWindowA", "GetAdaptersAddresses",
    "GetComputerNameA", "GetComputerNameW", "GetDiskFreeSpaceExW", "GetDiskFreeSpaceW", "GlobalMemoryStatusEx",
    "InternetOpenA", "IsDebuggerPresent", "LdrGetDllHandle", "LookupPrivilegeValueW", "MoveFileWithProgressW",
    "NtAllocateVirtualMemory", "NtCreateFile", "NtCreateKey", "NtGetContextThread", "NtMapViewOfSection",
    "NtProtectVirtualMemory", "NtQuerySystemInformation", "NtResumeThread", "NtSetContextThread", "NtSetValueKey",
    "NtTerminateProcess", "NtUnmapViewOfSection", "NtWriteFile", "Process32NextW", "RegOpenKeyExA", "RegOpenKeyExW",
    "RegSetValueExA", "RegSetValueExW", "SetFileAttributesW", "SetWindowsHookExA", "SetWindowsHookExW",
    "ShellExecuteExW", "WriteConsoleA", "WriteConsoleW", "WriteProcessMemory", "row_sum", "Process", "System Info",
    "Memory", "Registry", "File System", "Services", "Network", "GUI Interactions", "Privileges", "Devices",
    "Cryptography", "Threads", "Process (%)", "Memory (%)"
]

# Simulated ransomware filenames for testing
dummy_ransomware_files = [
    "encryptor.exe", "locker.exe", "ransomware_payload.exe", "data_locker.exe", "wannacry_clone.exe", "decrypt_instructions.txt", "readme_for_decryption.txt"
]

# Function to get running processes
def get_running_processes():
    process_data = []
    for process in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent', 'memory_percent']):
        process_info = process.info
        process_data.append([
            process_info['cpu_percent'],
            process_info['memory_percent']
        ])
    
    df = pd.DataFrame(process_data, columns=['Process (%)', 'Memory (%)'])

    # Fill missing model features with 0
    for col in expected_features:
        if col not in df.columns:
            df[col] = 0  

    return df[expected_features]  # Ensure the feature order matches the model

# Function to scan system directories for ransomware-like files
directories_to_scan = ["C:\\Users\\Public", "C:\\Windows\\Temp", "C:\\Users\\Public\\Test_Files"]
suspicious_extensions = [".enc", ".locked", ".crypted", ".ransom", ".crypt", ".cry", ".payme", ".locky", ".wannycry", ".TeslaCrypt", ".Cerber", "CryptoLocker", ".darkness"]
fake_processes = ["explorer.exe", "svchost.exe", "taskhost.exe", "spoolsv.exe", "msiexec.exe", "winlogon.exe"]
suspicious_activity = False

def scan_and_remove_ransomware():
    global suspicious_activity
    suspicious_files = []

    for directory in directories_to_scan:
        try:
            for file in os.listdir(directory):
                file_path = os.path.join(directory, file)
                
                if file in dummy_ransomware_files or file in fake_processes:
                    suspicious_files.append(file_path)

                # Check if the file has a suspicious extension
                if any(file.endswith(ext) for ext in suspicious_extensions):
                    suspicious_files.append(file_path)
                    suspicious_activity = True

                # Check if files have been modified in the last 10 seconds (fast encryption pattern)
                if time.time() - os.stat(file_path).st_mtime < 10:
                    suspicious_files.append(file_path)
                    suspicious_activity = True

        except Exception as e:
            pass  # Ignore inaccessible directories

    # Remove the detected ransomware files
    for file in suspicious_files:
        try:
            os.remove(file)  # Deletes the file
            st.warning(f"🗑️ **Deleted Ransomware File:** {file}")
        except Exception as e:
            st.error(f"❌ **Failed to Delete:** {file} - {str(e)}")

    return suspicious_files

# Start monitoring
# Function to get running processes and predict ransomware activity
CPU_THRESHOLD = 70.0  # Processes using more than 20% CPU
MEMORY_THRESHOLD = 70.0  # Processes using more than 15% RAM
SUSPICIOUS_NAMES = ["dummy_suspicious.exe", "ransomware_sim.exe", "encryptor.exe"]

def detect_and_kill_suspicious_processes():
    terminated_processes = []  # Store terminated process names

    for process in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            pid = process.info['pid']
            name = process.info['name']
            cpu_usage = process.info['cpu_percent']
            memory_usage = process.info['memory_percent']

            # Check if process is exceeding resource thresholds or has a suspicious name
            if cpu_usage > CPU_THRESHOLD or memory_usage > MEMORY_THRESHOLD or name in SUSPICIOUS_NAMES:
                print(f"⚠️ Suspicious Process Detected: {name} (PID: {pid}) - CPU: {cpu_usage}%, RAM: {memory_usage}%")

                # Kill the process
                proc = psutil.Process(pid)
                proc.terminate()  # Graceful kill
                proc.wait(timeout=3)  # Wait for termination
                print(f"✅ {name} has been terminated!")

                # Append terminated process name
                terminated_processes.append(name)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass  # Ignore errors for inaccessible processes

    return terminated_processes  # Return the list of terminated processes

BLACKLISTED_IPS = ["185.220.100.240", "185.220.101.7", "185.220.100.241", "192.42.116.198", "72.217.36.105", "107.189.8.56", "184.105.48.40", "192.168.1.100", "185.82.216.0", "45.227.255.0"]

# Function to scan network activity
def scan_network_activity():
    suspicious_connections = []
    
    # Get all network connections
    for conn in psutil.net_connections(kind="inet"):
        try:
            if conn.status == psutil.CONN_ESTABLISHED:  # Active connections only
                remote_ip = conn.raddr.ip if conn.raddr else None
                remote_port = conn.raddr.port if conn.raddr else None
                local_ip = conn.laddr.ip if conn.laddr else None
                pid = conn.pid

                # Check if the remote IP is in the blacklist
                if remote_ip in BLACKLISTED_IPS:
                    process_name = psutil.Process(pid).name() if pid else "Unknown"
                    suspicious_connections.append((process_name, remote_ip, remote_port, pid))

                    # Terminate process
                    if pid:
                        psutil.Process(pid).terminate()
                        st.warning(f"🚨 **Terminated Suspicious Connection** - {process_name} ({pid}) connected to {remote_ip}:{remote_port}")

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue  # Ignore errors for inaccessible processes

    return suspicious_connections

# Integrate process termination into monitoring loop
if st.button("Auto Scan for Ransomware Activity"):
    st.write("🔄 **Monitoring System Activity...**")

    for i in range(20):  # Run for ~100 seconds
        st.write(f"🔄 **Update {i+1}/20 - System Scanned at {time.strftime('%H:%M:%S')}**")

        # Kill suspicious processes and get terminated processes list
        terminated_processes = detect_and_kill_suspicious_processes()
        if terminated_processes:
            st.error(f"🚨 Suspicious processes terminated: {', '.join(terminated_processes)}")
        else:
            st.success("✅ No suspicious processes detected.")

        # Kill suspicious network connections
        suspicious_connections = scan_network_activity()
        if suspicious_connections:
            st.error("⚠️ Suspicious Network Activity Detected!")
            for process_name, remote_ip, remote_port, pid in suspicious_connections:
                st.write(f"🔴 {process_name} ({pid}) -> {remote_ip}:{remote_port}")
        else:
            st.success("✅ No suspicious network activity detected.")

        # Scan for ransomware files
        detected_files = scan_and_remove_ransomware()
        if detected_files:
            file_scan_result.error(f"⚠️ Ransomware Files Detected:\n{detected_files}")
        else:
            file_scan_result.success("✅ No ransomware files detected.")

        # Display update count & timestamp
        st.write(f"✅ **Update {i+1}/20 Complete - Next scan in 5 seconds...** ⏳")

        time.sleep(5)  # Update every 5 seconds

    st.success("✅ **Monitoring Completed! No further updates.** 🎯")

# Ransomware Detection Section
st.subheader('Ransomware Detection System')

# Input fields for ransomware detection
machine = st.number_input('Machine:', min_value=0)
debug_size = st.number_input('Debug Size:', min_value=0)
debug_rva = st.number_input('Debug RVA:', min_value=0)
major_image_version = st.number_input('Major Image Version:', min_value=0)
major_os_version = st.number_input('Major OS Version:', min_value=0)
export_rva = st.number_input('Export RVA:', min_value=0)
export_size = st.number_input('Export Size:', min_value=0)
iat_vra = st.number_input('IAT RVA:', min_value=0)
major_linker_version = st.number_input('Major Linker Version:', min_value=0)
minor_linker_version = st.number_input('Minor Linker Version:', min_value=0)
number_of_sections = st.number_input('Number of Sections:', min_value=0)
size_of_stack_reserve = st.number_input('Size of Stack Reserve:', min_value=0)
dll_characteristics = st.number_input('DLL Characteristics:', min_value=0)
resource_size = st.number_input('Resource Size:', min_value=0)
bitcoin_addresses = st.number_input('Bitcoin Addresses:', min_value=0)

# Predict button for ransomware detection
if st.button('Predict Ransomware'):
    if all([machine, debug_size, debug_rva, major_image_version, major_os_version, export_rva, export_size, iat_vra, major_linker_version, minor_linker_version, number_of_sections, size_of_stack_reserve, dll_characteristics, resource_size, bitcoin_addresses]):
        input_data = pd.DataFrame({
            'Machine': [machine],
            'DebugSize': [debug_size],
            'DebugRVA': [debug_rva],
            'MajorImageVersion': [major_image_version],
            'MajorOSVersion': [major_os_version],
            'ExportRVA': [export_rva],
            'ExportSize': [export_size],
            'IatVRA': [iat_vra],
            'MajorLinkerVersion': [major_linker_version],
            'MinorLinkerVersion': [minor_linker_version],
            'NumberOfSections': [number_of_sections],
            'SizeOfStackReserve': [size_of_stack_reserve],
            'DllCharacteristics': [dll_characteristics],
            'ResourceSize': [resource_size],
            'BitcoinAddresses': [bitcoin_addresses]
        })
        prediction = model1.predict(input_data)
        if prediction[0] == 1:
            st.success('The file is benign.')
            st.write('Suggested Action: Monitor the file for any unusual behavior.')
        else:
            st.error('The file is potentially malicious.')
            st.write('Suggested Action: Quarantine the file and perform a full system scan.')
    else:
        st.error("Could not detect. Please fill all the input fields.")

# Ransomware Early Detection Section
st.subheader('Ransomware Early Detection System')

# Input fields for early detection
time_value = st.number_input('Time', min_value=0)
protocol = st.selectbox('Protocol', options=['TCP', 'UDP'])
flag = st.selectbox('Flag', options=['A', 'S', 'SS'])
sedd_address = st.text_input('Source Address')  # Text input for IP address
exp_address = st.text_input('Destination Address')  # Text input for IP address
netflow_bytes = st.number_input('Netflow Bytes', min_value=0)
ip_address = st.text_input('IP Address')  # Text input for IP address
port = st.number_input('Port', min_value=0)

# Predict button for early detection
if st.button('Predict Early Detection'):
    if all([time_value, protocol, flag, sedd_address, exp_address, netflow_bytes, ip_address, port]):
        input_data = pd.DataFrame({
            'Time': [time_value],
            'Protocol': [protocol],
            'Flag': [flag],
            'SeddAddress': [sedd_address],
            'ExpAddress': [exp_address],
            'Netflow_Bytes': [netflow_bytes],
            'IPAddress': [ip_address],
            'Port': [port]
        })
        prediction = model2.predict(input_data)
        st.write('Prediction:', prediction[0])
    else:
        st.error("Could not detect. Please fill all the input fields.")

def fetch_news():
    api_key = "9d01ca71d0114b77ae22e01d1d230f1f"
    url = f"https://newsapi.org/v2/everything?q=ransomware&apiKey={api_key}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json().get("articles", [])
    else:
        return []
def ransomware_prevention():
    st.subheader("Ransomware Prevention Techniques")
    prevention_tips = [
        "Keep your operating system and software updated.",
        "Use strong and unique passwords for all accounts.",
        "Avoid clicking on suspicious links and email attachments.",
        "Use a reputable antivirus and firewall.",
        "Back up important data regularly.",
        "Restrict user permissions to minimize security risks.",
        "Disable macros in Microsoft Office documents.",
        "Enable multi-factor authentication for sensitive accounts."
    ]
    for tip in prevention_tips:
        st.write(f"- {tip}")
def faq_section():
    st.subheader("FAQ: Handling Ransomware Attacks")
    faqs = {
        "What is ransomware?": "Ransomware is a type of malware that encrypts files and demands payment for decryption.",
        "How does ransomware spread?": "It spreads through phishing emails, malicious websites, and software vulnerabilities.",
        "Should I pay the ransom?": "Security experts advise against paying, as it does not guarantee file recovery.",
        "What should I do if my system is infected?": "Disconnect from the internet, report the attack, and try to restore files from backups.",
        "Can antivirus software prevent ransomware?": "Good antivirus solutions can detect and block many ransomware threats, but vigilance is also necessary."
    }
    for question, answer in faqs.items():
        st.write(f"**{question}**")
        st.write(answer)
        st.write("---")
# Ransomware Awareness & Prevention Section
if st.button("Ransomware Awareness & Prevention"):
    articles = fetch_news()
    if articles:
        for article in articles[:5]:
            st.write(f"### [{article['title']}]({article['url']})")
            st.write(f"{article['description']}")
            st.image(article['urlToImage'], width=600)
            st.write("---")
    else:
        st.write("No news articles found.")

    st.subheader("Prevention Techniques")
    ransomware_prevention()

    st.subheader("Frequently Asked Questions (FAQ)")
    faq_section()