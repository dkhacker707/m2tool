M2tool is a Python-based application designed to scan files and directories for malware using the VirusTotal API. It provides real-time monitoring, heuristic analysis, and email reporting with PDF attachments. The tool is built with a focus on detecting .php, .dll, and .exe payload files.
________________________________________
Features:

(A) File Scanning:

•	Scans files using the VirusTotal API.

•	Detects .php, .dll, and .exe files.

•	Calculates file hashes (MD5) for signature-based detection.

•	Uses YARA rules for advanced malware detection.

(B) Real-Time Monitoring:

•	Monitors directories for new or modified files using the Watchdog library.

•	Automatically scans files when they are added or modified.

(C) Heuristic Analysis:

•	Calculates file entropy to detect suspicious files.

•	Uses YARA rules for advanced malware detection.

(D) Quarantine Functionality:

•	Moves suspicious or malicious files to a quarantine directory for further inspection.

(E) Email Reporting:

•	Sends scan reports via email with PDF attachments using the Gmail API.

•	Includes details such as file paths, hashes, entropy values, and threat details.

(F) Database Integration:

•	Stores scan results in an SQLite database for historical analysis.

•	Tracks file paths, hashes, malicious status, suspicious status, and heuristic scores.
________________________________________
Technologies Used:

•	Python: The core programming language used for the project.

•	VirusTotal API: For scanning files and detecting malware.

•	Gmail API: For sending email reports with PDF attachments.

•	SQLite: For storing scan results in a lightweight database.

•	Watchdog: For real-time file system monitoring.

•	Google OAuth 2.0: For secure authentication with the Gmail API.

•	FPDF: For generating PDF reports.

•	dotenv: For managing environment variables securely.

•	YARA: For advanced malware detection using custom rules.
________________________________________
Prerequisites:

Before running the program, ensure you have the following:

1.	Python 3.7 or higher: Download and install Python from python.org.

2.	VirusTotal API Key: Sign up at VirusTotal and get an API key.

3.	Google Cloud Project:

o	Create a project in the Google Cloud Console.

o	Enable the Gmail API.

o	Generate OAuth 2.0 credentials (credentials.json).

4.	YARA Rules File: Create or download a .yar file containing YARA rules for malware detection. Place it in the project directory as malware_rules.yar.
________________________________________
Setup and Installation

1. Clone the Repository:

Clone the repository to your local machine:

bash
git clone https://github.com/dkhacker707/m2tool.git

cd m2tool

3. Install Dependencies

Install the required Python libraries:

bash

pip install -r requirements.txt

5. Set Up Environment Variables:

Create a .env file in the project directory and add the following:

VIRUSTOTAL_API_KEY=your_virustotal_api_key

GMAIL_EMAIL=your_email@gmail.com

Replace your_virustotal_api_key with your actual VirusTotal API key and your_email@gmail.com with your Gmail address.

6. Add credentials.json:

Place the credentials.json file (downloaded from the Google Cloud Console) in the project directory. This file is required for authenticating with the Gmail API.

8. Add YARA Rules File:

Place your YARA rules file (malware_rules.yar) in the project directory. This file is used for advanced malware detection.

Usage:

1.	Run the script:
bash

python m2tool.py

3.	Enter the directory you want to scan when prompted.

4.	The script will:

o	Scan the directory for malicious files.

o	Generate a PDF report (scan_report.pdf).

o	Send the report via email to the address specified in the .env file.

o	Start real-time monitoring of the directory for new or modified files.
________________________________________
PDF Report:

The generated PDF report includes:

•	A summary of threats found.

•	File hashes.

•	Malicious and suspicious files.

•	Entropy values.

•	Threat details.

Email Notification:

An email will be sent to the specified address with the PDF report attached.

Notes:

•	Ensure the .env file is not shared or uploaded to public repositories, as it contains sensitive information.

•	The quarantine directory (quarantine/) is automatically created in the project directory. Suspicious files will be moved here.

•	For real-time monitoring, the script uses the Watchdog library. Press Ctrl+C to stop monitoring.

•	The YARA rules file (malware_rules.yar) must be placed in the project directory for advanced malware detection
