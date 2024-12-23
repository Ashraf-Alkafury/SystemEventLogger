Log Analyzer with System Monitoring
This project is a Python-based log analysis tool that retrieves Windows Event Logs from various log types such as PowerShell, Security, System, and Application logs. The tool fetches logs from the past X hours, extracts essential information from them, and saves the results into a CSV file for further analysis.

Additionally, the tool monitors the system's resources in real-time (CPU and memory usage) and displays them on a user-friendly GUI built with Tkinter.

Key Features:
Fetch Logs: Collects logs from various Windows event logs (PowerShell, Security, System, Application, Sysmon).
Time Filter: Allows the user to specify a time range (in hours) to fetch logs from the last X hours.
Log Parsing: Extracts relevant data from the logs, including Event ID, Timestamp, User Info, Command, Process ID, and Event Type.
Export to CSV: Saves the filtered logs into a CSV file for further analysis and reporting.
Real-time System Monitoring: Displays real-time CPU and memory usage stats.
User-friendly Interface: Built with Tkinter, the GUI is simple and intuitive, providing a seamless experience for users to interact with the tool.

Modules Used:
win32evtlog: Fetches Windows Event Logs.
psutil: Monitors system resource usage (CPU, memory).
csv: Handles CSV file writing.
Tkinter: Builds the graphical user interface (GUI).
