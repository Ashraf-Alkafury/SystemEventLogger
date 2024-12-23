import pyfiglet
import win32evtlog
import csv
import time
import re
import psutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime, timedelta


def fetch_all_events(hours=6):
    log_types = [
        "Microsoft-Windows-PowerShell/Operational",
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-Sysmon/Operational"
    ]

    time_threshold = datetime.now() - timedelta(hours=hours)
    all_events = []

    try:
        for log_type in log_types:
            try:
                log_handle = win32evtlog.OpenEventLog(None, log_type)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

                while True:
                    records = win32evtlog.ReadEventLog(log_handle, flags, 0)
                    if not records:
                        break

                    for record in records:
                        if record.TimeGenerated >= time_threshold:
                            user_info = "No User Data"
                            command = "No Data Available"

                            if hasattr(record, "StringInserts") and record.StringInserts:
                                user_info = record.StringInserts[1] if len(record.StringInserts) > 1 else "No User Info"
                                command = record.StringInserts[-1]

                            event_data = {
                                "EventID": record.EventID,
                                "LogType": log_type,
                                "Timestamp": record.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                                "Command": command,
                                "User": user_info,
                                "ProcessID": record.EventCategory,
                                "EventType": "Error" if record.EventType == 1 else (
                                    "Warning" if record.EventType == 2 else "Info")
                            }
                            all_events.append(event_data)

                win32evtlog.CloseEventLog(log_handle)
            except Exception as e:
                print(f"Error processing log {log_type}: {e}")
    except Exception as e:
        print(f"An error occurred while fetching events: {e}")

    return all_events


def save_to_csv(events, filename="Ashraf&Shaboury.csv"):
    try:
        with open(filename, "w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=["EventID", "LogType", "Timestamp", "Command", "User", "ProcessID",
                                                      "EventType"])
            writer.writeheader()
            writer.writerows(events)
        print(f"Events have been written to {filename}")
    except Exception as e:
        print(f"Failed to write to file: {e}")


def monitor_system_resources():
    cpu_usage = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    memory_usage = memory.percent

    return cpu_usage, memory_usage


def create_gui():
    def fetch_logs():
        try:
            hours = int(hours_entry.get())
            events = fetch_all_events(hours)
            if events:
                save_to_csv(events, "Ashraf&Shaboury.csv")
                messagebox.showinfo("Success", "Logs fetched and saved to Ashraf&Shaboury.csv")
            else:
                messagebox.showinfo("Info", "No events found.")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number of hours.")

    def monitor_resources():
        cpu, memory = monitor_system_resources()
        cpu_label.config(text=f"CPU Usage: {cpu}%")
        memory_label.config(text=f"Memory Usage: {memory}%")
        root.after(1000, monitor_resources)

    root = tk.Tk()
    root.title("Log Analyzer")

    banner_frame = ttk.Frame(root, padding="10")
    banner_frame.grid(row=0, column=0, columnspan=2)

    banner_label = ttk.Label(banner_frame, text="Log Analyzer", font=("Helvetica", 16, "bold"))
    banner_label.pack()

    hours_label = ttk.Label(root, text="Enter hours to fetch logs:")
    hours_label.grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)

    hours_entry = ttk.Entry(root)
    hours_entry.grid(row=1, column=1, padx=10, pady=5)

    fetch_button = ttk.Button(root, text="Fetch Logs", command=fetch_logs)
    fetch_button.grid(row=2, column=0, columnspan=2, pady=10)

    cpu_label = ttk.Label(root, text="CPU Usage: 0%", font=("Helvetica", 10))
    cpu_label.grid(row=3, column=0, padx=10, pady=5)

    memory_label = ttk.Label(root, text="Memory Usage: 0%", font=("Helvetica", 10))
    memory_label.grid(row=3, column=1, padx=10, pady=5)

    monitor_resources()

    root.mainloop()


if __name__ == "__main__":
    create_gui()
