M2tool 
M2tool is a Python-based application designed to scan files and directories for malware using the Malware Tool API's (Virus Total, Microsoft Defender, AVG, Kaspersky etc). It provides real-time monitoring, heuristic analysis, and email reporting with XML attachments. The tool is built with a focus on detecting .php, .dll, and .exe payload files.


Features
(A) File Scanning:
-Scans files using the VirusTotal API.
-Detects .php, .dll, and .exe files.

(B) Real-Time Monitoring:
-Monitors directories for new or modified files.

(C) Heuristic Analysis:
-Calculates file entropy to detect suspicious files.

(D) Quarantine Functionality:
-Moves suspicious files to a quarantine directory.

(F) Email Reporting:
-Sends scan reports via email with XML attachments.

(E) Database Integration:
-Stores scan results in an SQLite database.

Technologies Used;
||| Python: The core programming language used for the project.
||| VirusTotal API: For scanning files and detecting malware.
||| Gmail API: For sending email reports.
||| SQLite: For storing scan results.
||| Watchdog: For real-time file system monitoring.
||| Google OAuth 2.0: For secure authentication with the Gmail API.
||| XML: For generating structured scan reports.

Prerequisites
Before running the program, ensure you have the following:
1. Python 3.7 or higher

2. VirusTotal API Key: Sign up at VirusTotal and get an API key.

3. Google Cloud Project:
Create a project in the Google Cloud Console.
Enable the Gmail API.
Generate OAuth 2.0 credentials (credentials.json).
