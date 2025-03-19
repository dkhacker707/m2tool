import os
import requests
import sqlite3
import hashlib
import shutil
import base64
import time
import xml.etree.ElementTree as ET
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

# Load environment variables
load_dotenv()

# VirusTotal API settings
VIRUSTOTAL_API_KEY = "YOUR VIRUS TOTAL API"
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files"

# Gmail API settings
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

# Database settings
DATABASE_NAME = "malware_scan.db"

# Quarantine directory
QUARANTINE_DIR = "quarantine"
os.makedirs(QUARANTINE_DIR, exist_ok=True)

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
                entropy += -p_x * (p_x.__log2__())
        return entropy

# Function to calculate MD5 hash of a file
def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

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

# Function to create an XML report
def create_xml_report(report, threats_found):
    root = ET.Element("ScanReport")
    for entry in report:
        file_element = ET.SubElement(root, "File")
        file_element.set("path", entry["path"])
        file_element.set("hash", entry["hash"])
        file_element.set("malicious", str(entry["malicious"]))
        file_element.set("suspicious", str(entry["suspicious"]))
        file_element.set("entropy", str(entry["entropy"]))
        if threats_found:
            file_element.set("threat_details", entry["threat_details"])

    tree = ET.ElementTree(root)
    tree.write("scan_report.xml", encoding="utf-8", xml_declaration=True)

    # Debugging: Print the XML content
    print("XML Report Content:")
    ET.dump(root)

# Function to send an email with an XML attachment
def send_email(subject, body, xml_file_path):
    creds = authenticate_gmail()
    service = build("gmail", "v1", credentials=creds)

    # Create the email message
    msg = MIMEMultipart()
    msg["To"] = "YOUR_EMAIL"
    msg["Subject"] = subject

    # Attach the body
    msg.attach(MIMEText(body, "plain"))

    # Attach the XML file
    with open(xml_file_path, "rb") as attachment:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f"attachment; filename={os.path.basename(xml_file_path)}",
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

            # Check for specific file types
            if file.endswith((".php", ".dll", ".exe")):
                print(f"Detected suspicious file type: {file}")

            result = scan_file(file_path)
            if "error" in result:
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

                    # Quarantine if malicious or suspicious
                    if stats["malicious"] > 0 or stats["suspicious"] > 0:
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

    # Create XML report
    create_xml_report(report, threats_found)

    # Prepare email content
    subject = "Malware Scan Report"
    body = "The malware scan has completed. "
    if threats_found:
        body += "Threats were detected. Please review the attached XML report for details."
    else:
        body += "No threats were detected. The XML report is attached."

    # Send the email with the XML attachment
    send_email(subject, body, "scan_report.xml")

    # Start real-time monitoring
    event_handler = FileChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, path=directory, recursive=True)
    observer.start()
    print(f"Started real-time monitoring on {directory}...")

    try:
        while True:
            pass
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()