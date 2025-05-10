import os
import json
import time
import asyncio
from aiohttp import web
import sqlite3
from datetime import datetime
import logging
from colorama import Fore, Style
from dotenv import load_dotenv, find_dotenv

# find .env automagically by walking up directories until it's found
dotenv_path = find_dotenv()

# load up the entries as environment variables
load_dotenv(dotenv_path)

# Configuration
HOST = "0.0.0.0"
SOCKET_PORT = 5050
HTTP_PORT = 8080
SAVE_DIR = "received_reports"
DATABASE = "reports.db"
USERNAME = "admin"                   # hii ni username 
PASSWORD = "antimalwaresoc@@2025!!"  # hii ni database password
IP_LOG_FILE = "clients-ipaddr.txt"

frames = [
    rf"""
      [ {Fore.CYAN}Starting Server...{Style.RESET_ALL} ]
        ______
       |  __  | 
       | |__| |  Author: AuxGrep
       |______|  Website: https://github.com/AuxGrep
        \||||/
         ||||
    """,
    rf"""
      [ {Fore.MAGENTA}Initializing...{Style.RESET_ALL} ]
        ______
       |  __  | 
       | |__| |  Author: AuxGrep
       |______|  Website: https://github.com/AuxGrep
      --\||||/--
         ||||
    """,
    rf"""
      [ {Fore.YELLOW}Connecting...{Style.RESET_ALL} ]
        ______
       |  __  | 
       | |__| |  Author: AuxGrep
       |______|  Website: https://github.com/AuxGrep
       --||||--
         ||||
    """,
    rf"""
      [ {Fore.GREEN}Server Running!{Style.RESET_ALL} ]
        ______
       |  __  | 
       | |__| |  Author: {Fore.MAGENTA}AuxGrep{Style.RESET_ALL}
       |______|  Website: https://github.com/AuxGrep
        \||||/
         ||||
    """
]

# banner Animation Function
def animate_server(frames, delay=0.5, cycles=1):
    for _ in range(cycles):
        for frame in frames:
            os.system('clear' if os.name == 'posix' else 'cls')  # Clear screen
            print(frame)
            time.sleep(delay)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("server.log"), logging.StreamHandler()]
)
logger = logging.getLogger("SOCDashboard")

# Initialize SQLite database
def init_db():
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    host TEXT,
                    filename TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    data TEXT
                )"""
            )
            logger.info(f"{Fore.GREEN}Database{Style.RESET_ALL} initialized successfully.")
    except sqlite3.Error as e:
        logger.error(f"{Fore.RED}Error initializing database: {e}{Style.RESET_ALL}")

# Save client IP to a text file
def save_client_ip(ip):
    try:
        with open(IP_LOG_FILE, "a") as f:
            f.write(f"{ip}\n")
        logger.info(f"Saved client IP: {ip}")
    except Exception as e:
        logger.error(f"Error saving client IP: {e}")

# Save report to SQLite and JSON file
def save_report(ip, host, filename, data):
    file_path = os.path.join(SAVE_DIR, host, filename)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    try:
        # Save to JSON file
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        logger.info(f"Saved report to {file_path}.")

        # Save to database
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO reports (ip, host, filename, data) VALUES (?, ?, ?, ?)",
                (ip, host, filename, json.dumps(data))
            )
        logger.info(f"Saved report to database: {filename}")
    except (sqlite3.Error, OSError) as e:
        logger.error(f"Error saving report: {e}")

# Async Socket Server to Receive JSON Files
async def handle_client(reader, writer):
    client_address = writer.get_extra_info("peername")
    client_ip = client_address[0]
    logger.info(f"New connection from {client_ip}")

    try:
        # Read until EOF to ensure full data reception
        data = await reader.read(-1)
        decoded_data = data.decode("utf-8").strip()

        try:
            json_data = json.loads(decoded_data)
            logger.info(f"Valid JSON received from {client_ip}")

            # Save client IP to a text file
            save_client_ip(client_ip)

            # Extract filename and host from JSON data
            filename = json_data.get("data", {}).get("id", f"report_{datetime.now().strftime('%Y%m%d%H%M%S')}.json")
            host = json_data.get("data", {}).get("type", "unknown_host")

            # Save the report
            save_report(client_ip, host, filename, json_data)

            # Send the heartbeat to the client
            writer.write(b"File received successfully.\n")
            await writer.drain()

        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON received from {client_ip}: {e}")
            writer.write(b"Invalid JSON format.\n")
            await writer.drain()

    except Exception as e:
        logger.error(f"Error handling client {client_ip}: {e}")
        writer.write(b"Failed to process the file.\n")
        await writer.drain()

    finally:
        writer.close()
        await writer.wait_closed()
        logger.info(f"Connection closed with {client_ip}")

# Start the asynchronous socket server fUNC
async def start_socket_server():
    server = await asyncio.start_server(handle_client, HOST, SOCKET_PORT)
    async with server:
        logger.info(f"Socket server running on {HOST}:{SOCKET_PORT}")
        await server.serve_forever()

# Fetch statistics from the database
def fetch_statistics():
    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()

            # Total reports
            cursor.execute("SELECT COUNT(*) FROM reports")
            total_reports = cursor.fetchone()[0]

            # MYASS wanted to show you unique IP
            cursor.execute("SELECT COUNT(DISTINCT ip) FROM reports")
            unique_ips = cursor.fetchone()[0]

            # Recent activity
            cursor.execute("SELECT timestamp FROM reports ORDER BY timestamp DESC LIMIT 1")
            last_activity = cursor.fetchone()[0]

            return {
                "total_reports": total_reports,
                "unique_ips": unique_ips,
                "last_activity": last_activity
            }
    except sqlite3.Error as e:
        logger.error(f"Error fetching statistics: {e}")
        return {}

# Render the admin dashboard with a list of reports and statistics
async def render_dashboard(request):
    try:
        # Fetch reports from the database
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, ip, host, filename, timestamp FROM reports ORDER BY timestamp DESC")
            reports = cursor.fetchall()

        # Check if there is any data in the database or the received_reports folder
        if not reports and not os.listdir(SAVE_DIR):
            # No data available, display animation and message
            no_data_message = """
            <html>
                <head>
                    <title>Anti-Malware Admin</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            margin: 0;
                            padding: 0;
                            background: radial-gradient(circle, rgba(44,62,80,1) 0%, rgba(52,73,94,1) 100%);
                            color: #ecf0f1;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            height: 100vh;
                        }
                        .no-data {
                            text-align: center;
                            animation: fadeIn 2s infinite;
                        }
                        @keyframes fadeIn {
                            0% { opacity: 0; }
                            50% { opacity: 1; }
                            100% { opacity: 0; }
                        }
                        h1 {
                            color: #ecf0f1;
                        }
                    </style>
                </head>
                <body>
                    <div class="no-data">
                        <h1>No Data Available</h1>
                    </div>
                </body>
            </html>
            """
            return web.Response(text=no_data_message, content_type="text/html")

        # Fetch statistics
        stats = fetch_statistics()
        rows = "".join(
            f"<tr><td>{id}</td><td>{ip}</td><td>{host}</td><td>{filename}</td><td>{timestamp}</td></tr>"
            for id, ip, host, filename, timestamp in reports
        )
        html_content = f"""
        <html>
            <head>
                <title>Anti-Malware Admin</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        margin: 0;
                        padding: 0;
                        background: radial-gradient(circle, rgba(44,62,80,1) 0%, rgba(52,73,94,1) 100%);
                        color: #ecf0f1;
                    }}
                    .container {{
                        max-width: 1200px;
                        margin: 0 auto;
                        padding: 20px;
                    }}
                    .stats {{
                        display: flex;
                        justify-content: space-between;
                        margin-bottom: 20px;
                    }}
                    .stat-card {{
                        background: rgba(255, 255, 255, 0.1);
                        padding: 20px;
                        border-radius: 8px;
                        text-align: center;
                        flex: 1;
                        margin: 0 10px;
                        box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.5);
                    }}
                    .stat-card h2 {{
                        margin: 0;
                        font-size: 24px;
                        color: #3498db;
                    }}
                    .stat-card p {{
                        margin: 5px 0 0;
                        font-size: 16px;
                        color: #bdc3c7;
                    }}
                    table {{
                        width: 100%;
                        border-collapse: collapse;
                        background-color: rgba(255, 255, 255, 0.1);
                        box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.5);
                        border-radius: 8px;
                        overflow: hidden;
                    }}
                    th, td {{
                        padding: 12px 15px;
                        text-align: left;
                        border-bottom: 1px solid #ddd;
                    }}
                    th {{
                        background-color: rgba(52,152,219,0.9);
                        color: #fff;
                        text-transform: uppercase;
                    }}
                    td {{
                        background-color: rgba(52,73,94,0.9);
                        color: #ecf0f1;
                    }}
                    tr:hover {{
                        background-color: rgba(44,62,80,1);
                    }}
                    h1 {{
                        text-align: center;
                        margin: 20px 0;
                        color: #ecf0f1;
                    }}
                </style>
                <meta http-equiv="refresh" content="5">
            </head>
            <body>
                <div class="container">
                    <h1>Anti-Malware Admin Panel</h1>
                    <div class="stats">
                        <div class="stat-card">
                            <h2>{stats.get('total_reports', 0)}</h2>
                            <p>Total Reports</p>
                        </div>
                        <div class="stat-card">
                            <h2>{stats.get('unique_ips', 0)}</h2>
                            <p>Unique IPs</p>
                        </div>
                        <div class="stat-card">
                            <h2>{stats.get('last_activity', 'N/A')}</h2>
                            <p>Last Activity</p>
                        </div>
                    </div>
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>IP Address</th>
                                <th>Host</th>
                                <th>Filename</th>
                                <th>Timestamp</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rows}
                        </tbody>
                    </table>
                </div>
            </body>
        </html>
        """
        return web.Response(text=html_content, content_type="text/html")
    except Exception as e:
        logger.error(f"Error rendering dashboard: {e}")
        return web.Response(status=500, text="Internal Server Error")

# Start the HTTP server for the admin dashboard.
async def start_http_server():
    app = web.Application()
    app.router.add_get("/", render_dashboard)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, HOST, HTTP_PORT)
    logger.info(f"HTTP server running at http://{HOST}:{HTTP_PORT}")
    await site.start()

# Main Function
def main():
    init_db()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(asyncio.gather(start_socket_server(), start_http_server()))
    except KeyboardInterrupt:
        logger.info("Shutting down servers...")
    finally:
        loop.close()

if __name__ == "__main__":
    animate_server(frames=frames)
    logger.info("Starting SOC dashboard...")
    main()
