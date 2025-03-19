M2tool is a Python-based application designed to scan files and directories for malware using the Malware Tool API's (Virus Total, Microsoft Defender, AVG, Kaspersky etc). It provides real-time monitoring, heuristic analysis, and email reporting with XML attachments. The tool is built with a focus on detecting .php, .dll, and .exe payload files.


Features;

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
-Create a project in the Google Cloud Console.
-Enable the Gmail API.
-Generate OAuth 2.0 credentials (credentials.json).

Setup and Installation
1. Clone the Repository
Clone the repository to your local machine:

git clone https://github.com/dkhacker707/m2tool.git

cd m2tool

2. Install Dependencies
Install the required Python libraries:

pip install -r requirements.txt

4. Set Up Environment Variables
Create a .env file in the project directory and add the following:

VIRUSTOTAL_API_KEY=your_virustotal_api_key

EMAIL_ADDRESS=your_email@gmail.com

4. Add credentials.json
Place the credentials.json file (from Google Cloud Console) in the project directory.



