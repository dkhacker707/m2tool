import os
import requests
import sqlite3
import hashlib
import shutil
import base64
import time
import subprocess
import math
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from dotenv import load_dotenv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from fpdf import FPDF

# Load environment variables
load_dotenv()

# VirusTotal API settings
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "c4f5884f96005d4d945c768bb91a96f4adcba0699855678f2c0883cec8c2e56a")
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files"

# Gmail API settings
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

# Database settings
DATABASE_NAME = "malware_scan.db"

# Quarantine directory
QUARANTINE_DIR = "quarantine"
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# Known malware signatures (MD5 hashes)
KNOWN_MALWARE_HASHES = {
    "e99a18c428cb38d5f260853678922e03",  # Example hash 1
    "5d41402abc4b2a76b9719d911017c592",  # Example hash 2
    # Add more known malware hashes here
}

# YARA rules file
YARA_RULES_FILE = "malware_rules.yar"

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY,
            file_path TEXT,
            file_hash TEXT,
            malicious INTEGER,
            suspicious INTEGER,
            heuristic_score REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# Function to calculate file entropy
def calculate_entropy(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
        if not data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy

# Function to calculate MD5 hash of a file
def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# Function to check if a file matches YARA rules
def check_yara_rules(file_path):
    if not os.path.exists(YARA_RULES_FILE):
        print(f"YARA rules file '{YARA_RULES_FILE}' not found.")
        return False, "YARA rules file missing."

    try:
        result = subprocess.run(
            ["yara", YARA_RULES_FILE, file_path],
            capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout:
            return True, f"YARA rule match: {result.stdout.strip()}"
        return False, "No YARA rule matches."
    except Exception as e:
        return False, f"YARA scan failed: {e}"

# Function to monitor file behavior (sandbox-like)
def monitor_behavior(file_path):
    try:
        # Simulate execution in a sandbox
        print(f"Monitoring behavior of {file_path}...")
        time.sleep(5)  # Simulate execution time
        # Check for suspicious behavior (e.g., file modifications, network connections)
        # This is a placeholder for actual behavioral analysis
        return False, "No suspicious behavior detected."
    except Exception as e:
        return False, f"Behavior monitoring failed: {e}"

# Function to check if a file is malicious (offline detection)
def is_malicious_offline(file_path):
    file_hash = calculate_md5(file_path)
    entropy = calculate_entropy(file_path)

    # Debug: Print file hash and entropy
    print(f"File hash: {file_hash}, Entropy: {entropy}")

    # Signature-based detection
    if file_hash in KNOWN_MALWARE_HASHES:
        print(f"Known malware signature detected: {file_hash}")
        return True, "Known malware signature detected."

    # Heuristic detection
    if entropy > 7.5 and file_path.endswith((".exe", ".dll", ".php")):
        print(f"High entropy ({entropy:.2f}) and suspicious file type.")
        return True, f"High entropy ({entropy:.2f}) and suspicious file type."

    # YARA rule detection
    yara_malicious, yara_details = check_yara_rules(file_path)
    if yara_malicious:
        print(f"YARA rule match: {yara_details}")
        return True, yara_details

    # Behavioral analysis
    behavior_malicious, behavior_details = monitor_behavior(file_path)
    if behavior_malicious:
        print(f"Suspicious behavior detected: {behavior_details}")
        return True, behavior_details

    print("No threats detected.")
    return False, "No threats detected."

# Function to scan a file using VirusTotal API
def scan_file(file_path):
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
    }
    with open(file_path, "rb") as file:
        files = {"file": (os.path.basename(file_path), file)}
        for _ in range(3):  # Retry up to 3 times
            response = requests.post(VIRUSTOTAL_API_URL, headers=headers, files=files)
            if response.status_code == 409:
                print(f"File {file_path} is already being processed. Retrying in 10 seconds...")
                time.sleep(10)  # Wait 10 seconds before retrying
                continue
            elif response.status_code != 200:
                print(f"API request failed with status code {response.status_code}: {response.text}")
                return {"error": f"API request failed with status code {response.status_code}"}
            break
        else:
            return {"error": "Max retries reached. File could not be processed."}

    try:
        return response.json()
    except ValueError as e:
        print(f"Failed to decode JSON: {e}")
        return {"error": "Invalid JSON response"}

# Function to authenticate with Gmail API
def authenticate_gmail():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds

# Function to create a PDF report
def create_pdf_report(report, threats_found):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=14, style="B")  # Bold and larger font for the title

    # Add a title
    pdf.cell(200, 10, txt="Malware Scan Report", ln=True, align="C")
    pdf.ln(10)  # Add some space after the title

    # Add scan summary
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Threats Found: {threats_found}", ln=True)
    pdf.cell(200, 10, txt=f"Total Files Scanned: {len(report)}", ln=True)
    pdf.ln(10)  # Add some space after the summary

    # Add File Hashes as a paragraph
    pdf.set_font("Arial", size=12, style="B")
    pdf.cell(200, 10, txt="File Hashes:", ln=True)
    pdf.set_font("Arial", size=10)
    hashes = [entry["hash"] for entry in report if entry["hash"] != "N/A"]
    hash_text = ", ".join(hashes)  # Combine hashes into a single string
    pdf.multi_cell(0, 10, txt=hash_text)  # Display hashes in a paragraph
    pdf.ln(10)  # Add some space after the hashes

    # Add Malicious Files as a paragraph
    pdf.set_font("Arial", size=12, style="B")
    pdf.cell(200, 10, txt="Malicious Files:", ln=True)
    pdf.set_font("Arial", size=10)
    malicious_files = [entry["path"] for entry in report if entry["malicious"] == 1]
    malicious_text = ", ".join(malicious_files) if malicious_files else "None"
    pdf.multi_cell(0, 10, txt=malicious_text)  # Display malicious files in a paragraph
    pdf.ln(10)  # Add some space after the malicious files

    # Add Suspicious Files as a paragraph
    pdf.set_font("Arial", size=12, style="B")
    pdf.cell(200, 10, txt="Suspicious Files:", ln=True)
    pdf.set_font("Arial", size=10)
    suspicious_files = [entry["path"] for entry in report if entry["suspicious"] == 1]
    suspicious_text = ", ".join(suspicious_files) if suspicious_files else "None"
    pdf.multi_cell(0, 10, txt=suspicious_text)  # Display suspicious files in a paragraph
    pdf.ln(10)  # Add some space after the suspicious files

    # Add Entropy Values as a paragraph
    pdf.set_font("Arial", size=12, style="B")
    pdf.cell(200, 10, txt="Entropy Values:", ln=True)
    pdf.set_font("Arial", size=10)
    entropy_values = [f"{entry['entropy']:.2f}" for entry in report]
    entropy_text = ", ".join(entropy_values)  # Combine entropy values into a single string
    pdf.multi_cell(0, 10, txt=entropy_text)  # Display entropy values in a paragraph
    pdf.ln(10)  # Add some space after the entropy values

    # Add Threat Details as a paragraph
    pdf.set_font("Arial", size=12, style="B")
    pdf.cell(200, 10, txt="Threat Details:", ln=True)
    pdf.set_font("Arial", size=10)
    threat_details = [entry.get("threat_details", "N/A") for entry in report]
    threat_text = ", ".join(threat_details)  # Combine threat details into a single string
    pdf.multi_cell(0, 10, txt=threat_text)  # Display threat details in a paragraph
    pdf.ln(10)  # Add some space after the threat details

    # Add a table for file paths
    pdf.set_font("Arial", size=10, style="B")  # Bold font for headers
    pdf.set_fill_color(200, 220, 255)  # Light blue background for headers
    pdf.cell(200, 10, txt="File Paths", border=1, fill=True, ln=True)

    # Reset font for table content
    pdf.set_font("Arial", size=10)
    pdf.set_fill_color(255, 255, 255)  # White background for content

    for entry in report:
        pdf.cell(200, 10, txt=entry["path"], border=1, ln=True)

    # Save the PDF
    pdf.output("scan_report.pdf")
    print("PDF report generated: scan_report.pdf")

# Function to send an email with a PDF attachment
def send_email(subject, body, pdf_file_path):
    creds = authenticate_gmail()
    service = build("gmail", "v1", credentials=creds)

    # Create the email message
    msg = MIMEMultipart()
    msg["To"] = "hackerreal935@gmail.com"
    msg["Subject"] = subject

    # Attach the body
    msg.attach(MIMEText(body, "plain"))

    # Attach the PDF file
    with open(pdf_file_path, "rb") as attachment:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f"attachment; filename={os.path.basename(pdf_file_path)}",
        )
        msg.attach(part)

    # Encode the message in base64
    raw_message = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
    message = {"raw": raw_message}

    try:
        # Send the email
        service.users().messages().send(userId="me", body=message).execute()
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Function to quarantine a file
def quarantine_file(file_path):
    quarantine_path = os.path.join(QUARANTINE_DIR, os.path.basename(file_path))
    shutil.move(file_path, quarantine_path)
    print(f"File quarantined: {quarantine_path}")

# Function to scan a directory
def scan_directory(directory):
    report = []
    threats_found = False
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Scanning file: {file_path}")

            # Debug: Print file type and size
            file_size = os.path.getsize(file_path) / (1024 * 1024)  # Size in MB
            print(f"File type: {os.path.splitext(file)[1]}, Size: {file_size:.2f} MB")

            # Skip files larger than 650 MB
            if file_size > 650:
                print(f"File {file_path} is too large ({file_size:.2f} MB). Skipping...")
                continue

            # Check for specific file types
            if file.endswith((".php", ".dll", ".exe")):
                print(f"Detected suspicious file type: {file}")

            # Offline detection
            malicious_offline, threat_details_offline = is_malicious_offline(file_path)
            if malicious_offline:
                print(f"Offline detection found a threat: {threat_details_offline}")
                report.append({
                    "path": file_path,
                    "hash": calculate_md5(file_path),
                    "malicious": 1,
                    "suspicious": 1,
                    "entropy": calculate_entropy(file_path),
                    "threat_details": threat_details_offline
                })
                quarantine_file(file_path)
                threats_found = True
                continue  # Skip VirusTotal scan if offline detection finds a threat

            # VirusTotal API scan
            result = scan_file(file_path)
            if "error" in result:
                print(f"Error scanning file {file_path}: {result['error']}")
                report.append({
                    "path": file_path,
                    "hash": "N/A",
                    "malicious": 0,
                    "suspicious": 0,
                    "entropy": 0.0,
                    "threat_details": result["error"]
                })
                continue

            if "data" in result and "id" in result["data"]:
                file_id = result["data"]["id"]
                analysis_url = f"{VIRUSTOTAL_API_URL}/{file_id}"
                headers = {
                    "x-apikey": VIRUSTOTAL_API_KEY,
                }
                analysis_response = requests.get(analysis_url, headers=headers)
                analysis_result = analysis_response.json()
                print("VirusTotal API Response:", analysis_result)  # Debug: Print API response

                if "error" in analysis_result and analysis_result["error"]["code"] == "NotFoundError":
                    print(f"File {file_path} not found in VirusTotal database.")
                    report.append({
                        "path": file_path,
                        "hash": calculate_md5(file_path),
                        "malicious": 0,
                        "suspicious": 0,
                        "entropy": calculate_entropy(file_path),
                        "threat_details": "File not found in VirusTotal database."
                    })
                    continue

                if "data" in analysis_result and "attributes" in analysis_result["data"]:
                    stats = analysis_result["data"]["attributes"]["last_analysis_stats"]
                    entropy = calculate_entropy(file_path)
                    heuristic_score = entropy  # Simple heuristic score (can be enhanced)
                    threat_details = f"Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}, Entropy: {entropy}"
                    report.append({
                        "path": file_path,
                        "hash": calculate_md5(file_path),
                        "malicious": stats["malicious"],
                        "suspicious": stats["suspicious"],
                        "entropy": entropy,
                        "threat_details": threat_details
                    })

                    # Debug: Print scan results
                    print(f"Scan results for {file_path}: {threat_details}")

                    # Quarantine if malicious or suspicious
                    if stats["malicious"] > 0 or stats["suspicious"] > 0:
                        print(f"Threat detected by VirusTotal: {threat_details}")
                        quarantine_file(file_path)
                        threats_found = True

                    # Save results to database
                    conn = sqlite3.connect(DATABASE_NAME)
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO scan_results (file_path, file_hash, malicious, suspicious, heuristic_score)
                        VALUES (?, ?, ?, ?, ?)
                    """, (file_path, calculate_md5(file_path), stats["malicious"], stats["suspicious"], heuristic_score))
                    conn.commit()
                    conn.close()
            else:
                print(f"No scan data for {file_path}: {result}")
                report.append({
                    "path": file_path,
                    "hash": "N/A",
                    "malicious": 0,
                    "suspicious": 0,
                    "entropy": 0.0,
                    "threat_details": result.get("error", "Unknown error")
                })

    # Debugging: Print the report list
    print("Report List:")
    for entry in report:
        print(entry)

    return report, threats_found

# File system event handler for real-time monitoring
class FileChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            print(f"File modified: {event.src_path}")
            scan_directory(os.path.dirname(event.src_path))

# Main function
def main():
    init_db()

    directory = input("Enter the directory to scan: ")
    if not os.path.isdir(directory):
        print("Invalid directory!")
        return

    print("Starting scan...")
    report, threats_found = scan_directory(directory)

    # Create PDF report
    create_pdf_report(report, threats_found)

    # Prepare email content
    subject = "Malware Scan Report"
    body = "The malware scan has completed. "
    if threats_found:
        body += "Threats were detected. Please review the attached PDF report for details."
    else:
        body += "No threats were detected. The PDF report is attached."

    # Send the email with the PDF attachment
    send_email(subject, body, "scan_report.pdf")

    # Start real-time monitoring
    event_handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, path=directory, recursive=True)
    observer.start()
    print(f"Started real-time monitoring on {directory}...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
