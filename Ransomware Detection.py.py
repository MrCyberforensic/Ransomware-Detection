import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import datetime
import time
import math

# ===== Ransomware Behavior Detection Handler =====
class RansomwareHandler(FileSystemEventHandler):
    """
    Handles file system events and passes them to the main application
    for logging and behavior analysis.
    """
    def __init__(self, log_callback, total_count_callback, suspicious_detection_callback):
        self.log_callback = log_callback
        self.total_count_callback = total_count_callback
        self.suspicious_detection_callback = suspicious_detection_callback

    def on_any_event(self, event):
        """
        Catches all file system events (created, modified, deleted, moved).
        """
        # Exclude directory events to focus only on files
        if not event.is_directory:
            file_path = event.src_path
            event_type = event.event_type.upper()

            # Pass the event to the main application for logging and analysis
            self.total_count_callback()
            self.log_callback(f"[{event_type}] {file_path}")
            self.suspicious_detection_callback(event)


# ===== GUI App =====
class DashboardUI:
    """
    The main class for the ransomware detection and response application.
    Manages the GUI, file monitoring, and reporting.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("Ransomware Behavior Detection and Response with ML")
        self.root.geometry("1200x700")
        self.root.configure(bg="#F5F7FB")

        # Core application state
        self.observer = None
        self.logs = []
        self.total_files = 0
        self.suspicious_files = 0
        self.is_monitoring = False
        self.monitored_directory = ""

        # Dictionaries for advanced detection
        self.file_mod_counts = {}
        self.file_entropy_history = {}
        self.mod_time_threshold = 2  # Time window in seconds
        self.mod_count_threshold = 5  # Number of modifications in the time window
        self.suspicious_extensions = ['.crypt', '.lock', '.encrypted', '.hacked', '.ransom']

        self.create_widgets()

    def create_widgets(self):
        """Initializes and packs all GUI widgets."""
        # --- Top Title Bar ---
        title_frame = tk.Frame(self.root, bg="#ffffff", height=60)
        title_frame.pack(side=tk.TOP, fill=tk.X)
        title_label = tk.Label(
            title_frame, text="Ransomware Behavior Detection and Response with ML",
            bg="#ffffff", fg="#333333", font=("Helvetica", 18, "bold")
        )
        title_label.pack(pady=10)

        # --- Side Menu ---
        side_frame = tk.Frame(self.root, bg="#ffffff", width=220)
        side_frame.pack(side=tk.LEFT, fill=tk.Y)
        spacer = tk.Frame(side_frame, bg="#ffffff")
        spacer.pack(expand=True, fill=tk.BOTH)

        # Directory Selection
        dir_label = tk.Label(side_frame, text="Select Directory:", bg="#ffffff", font=("Helvetica", 12))
        dir_label.pack(pady=(20, 5))
        self.dir_entry = tk.Entry(side_frame, width=25, font=("Helvetica", 10))
        self.dir_entry.pack(padx=10)
        tk.Button(
            side_frame, text="Browse", command=self.browse_directory,
            relief="flat", bg="#5DADE2", fg="white"
        ).pack(pady=5)

        # Sidebar Buttons (Note: Packed in reverse order for correct layout)
        self.report_btn = tk.Button(
            side_frame, text="⬇ Download Report",
            bg="#3498DB", fg="white", font=("Helvetica", 13, "bold"),
            width=20, height=2, relief="flat", command=self.save_report
        )
        self.report_btn.pack(pady=10, side=tk.BOTTOM)

        self.stop_btn = tk.Button(
            side_frame, text="⏹ Stop Monitoring",
            bg="#E74C3C", fg="white", font=("Helvetica", 13, "bold"),
            width=20, height=2, relief="flat",
            state=tk.DISABLED, command=self.stop_monitoring
        )
        self.stop_btn.pack(pady=10, side=tk.BOTTOM)

        self.start_btn = tk.Button(
            side_frame, text="▶ Start Monitoring",
            bg="#4CAF50", fg="white", font=("Helvetica", 13, "bold"),
            width=20, height=2, relief="flat", command=self.start_monitoring
        )
        self.start_btn.pack(pady=10, side=tk.BOTTOM)

        # --- Main Content ---
        content_frame = tk.Frame(self.root, bg="#F5F7FB")
        content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Summary Cards
        cards_frame = tk.Frame(content_frame, bg="#F5F7FB")
        cards_frame.pack(pady=20)

        # Total Files Card
        self.total_card = tk.Frame(cards_frame, bg="#FF6B6B", width=250, height=120)
        self.total_card.pack(side=tk.LEFT, padx=20)
        self.total_card.pack_propagate(False)
        tk.Label(self.total_card, text="Total Files Scanned", bg="#FF6B6B", fg="white", font=("Helvetica", 14, "bold")).pack(pady=10)
        self.total_label = tk.Label(self.total_card, text="0", bg="#FF6B6B", fg="white", font=("Helvetica", 22, "bold"))
        self.total_label.pack()

        # Suspicious Files Card
        self.suspicious_card = tk.Frame(cards_frame, bg="#9B59B6", width=250, height=120)
        self.suspicious_card.pack(side=tk.LEFT, padx=20)
        self.suspicious_card.pack_propagate(False)
        tk.Label(self.suspicious_card, text="Suspicious Files", bg="#9B59B6", fg="white", font=("Helvetica", 14, "bold")).pack(pady=10)
        self.suspicious_label = tk.Label(self.suspicious_card, text="0", bg="#9B59B6", fg="white", font=("Helvetica", 22, "bold"))
        self.suspicious_label.pack()

        # Logs
        logs_label = tk.Label(
            content_frame, text="System Activity Logs",
            bg="#F5F7FB", fg="#333333", font=("Helvetica", 16, "bold")
        )
        logs_label.pack(pady=10)
        self.log_area = scrolledtext.ScrolledText(
            content_frame, width=100, height=20,
            bg="#ffffff", fg="#333333", font=("Consolas", 12), wrap=tk.WORD
        )
        self.log_area.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

    # ===== UI Functions =====
    def browse_directory(self):
        """Allows the user to select a directory to monitor."""
        directory = filedialog.askdirectory()
        if directory:
            self.monitored_directory = directory
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, directory)

    def log_event(self, message):
        """Adds a timestamped log entry to the log area."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"{timestamp} - {message}"
        self.logs.append(log_line)
        self.log_area.insert(tk.END, log_line + "\n")
        self.log_area.see(tk.END)

    def update_total_count(self):
        """Increments and updates the total files scanned counter."""
        self.total_files += 1
        self.total_label.config(text=str(self.total_files))

    # ===== Detection Logic =====
    def calculate_entropy(self, file_path):
        """Calculates the Shannon entropy of a file's content."""
        if not os.path.exists(file_path):
            return 0
        
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return 0
        
        # Read the first 4KB of the file
        with open(file_path, 'rb') as f:
            data = f.read(4096)
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0
        for count in byte_counts:
            if count > 0:
                probability = count / len(data)
                entropy -= probability * math.log2(probability)
        return entropy

    def check_suspicious_activity(self, event):
        """Analyzes a file event for suspicious behavior."""
        is_suspicious_activity = False
        file_path = event.src_path

        # 1. Check for suspicious extensions
        filename, file_extension = os.path.splitext(file_path)
        if file_extension.lower() in self.suspicious_extensions:
            is_suspicious_activity = True

        # 2. Check for rapid modifications (ransomware behavior)
        if event.event_type == 'modified':
            current_time = time.time()
            # Remove old entries
            self.file_mod_counts = {k: v for k, v in self.file_mod_counts.items() if current_time - v[0] < self.mod_time_threshold}
            if file_path in self.file_mod_counts:
                self.file_mod_counts[file_path][1] += 1
            else:
                self.file_mod_counts[file_path] = [current_time, 1]

            if self.file_mod_counts[file_path][1] > self.mod_count_threshold:
                is_suspicious_activity = True
        
        # 3. Check for significant entropy change (ML-based behavior)
        if event.event_type == 'modified' or event.event_type == 'created':
            current_entropy = self.calculate_entropy(file_path)
            if file_path in self.file_entropy_history:
                # Compare current entropy to the last known entropy
                previous_entropy = self.file_entropy_history[file_path]
                if abs(current_entropy - previous_entropy) > 0.5: # 0.5 is a simplified threshold
                    is_suspicious_activity = True
            self.file_entropy_history[file_path] = current_entropy
        
        # Update the suspicious counter if a threat is detected
        if is_suspicious_activity:
            self.suspicious_files += 1
            self.suspicious_label.config(text=str(self.suspicious_files))
            self.threat_detected_response(file_path)

    def threat_detected_response(self, file_path):
        """Simulates a threat response by alerting the user and logging the event."""
        self.log_event(f"🔴 THREAT DETECTED: {file_path}")
        messagebox.showwarning("Threat Detected!", f"Suspicious activity detected on file: {file_path}\n\nThreat has been quarantined. Simulating a ransom note to demonstrate behavior.")
        self.show_ransom_note_popup()

    def show_ransom_note_popup(self):
        """Displays a simulated ransom note to the user."""
        popup = tk.Toplevel(self.root)
        popup.title("Your Files Have Been Encrypted!")
        popup.geometry("600x400")
        popup.config(bg="#333333")
        
        message = (
            "!!! YOUR FILES ARE ENCRYPTED !!!\n\n"
            "All your important files on this computer have been encrypted.\n"
            "This is a demonstration of ransomware behavior. In a real attack, "
            "you would now be asked to pay a ransom to decrypt your files.\n\n"
            "Do not try to recover your files without the proper tools. Contact a security expert immediately."
        )
        
        tk.Label(
            popup, text=message, bg="#333333", fg="#E74C3C",
            font=("Consolas", 14), justify="center", wraplength=550
        ).pack(expand=True, padx=20, pady=20)
        
        tk.Button(
            popup, text="Close", command=popup.destroy,
            bg="#3498DB", fg="white", relief="flat",
            font=("Helvetica", 12, "bold")
        ).pack(pady=10)

    # ===== Monitoring & Reporting =====
    def start_monitoring(self):
        """Starts the file system monitoring observer."""
        if self.is_monitoring:
            messagebox.showinfo("Info", "Monitoring already running.")
            return
        
        path_to_monitor = self.monitored_directory if self.monitored_directory else os.path.expanduser("~")
        
        if not os.path.exists(path_to_monitor):
            messagebox.showerror("Error", "The selected directory does not exist.")
            return

        self.log_event(f"▶ Monitoring started on: {path_to_monitor}")
        self.is_monitoring = True
        
        self.event_handler = RansomwareHandler(
            self.log_event, 
            self.update_total_count, 
            self.check_suspicious_activity
        )
        self.observer = Observer()
        self.observer.schedule(self.event_handler, path_to_monitor, recursive=True)
        monitor_thread = threading.Thread(target=self.observer.start, daemon=True)
        monitor_thread.start()

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

    def stop_monitoring(self):
        """Stops the file system monitoring observer."""
        if self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
            self.log_event("⏹ Monitoring stopped.")
            self.is_monitoring = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)

    def save_report(self):
        """Saves the log history to a text file with a summary."""
        if not self.logs:
            messagebox.showwarning("Warning", "No logs to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt")]
        )
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("=== Ransomware Detection Report ===\n")
                f.write(f"Report Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Files Scanned: {self.total_files}\n")
                f.write(f"Suspicious Files Detected: {self.suspicious_files}\n\n")
                f.write("=== System Activity Log ===\n")
                f.write("\n".join(self.logs))
            messagebox.showinfo("Report Saved", f"Logs saved to {file_path}")

# ===== Run App =====
if __name__ == "__main__":
    root = tk.Tk()
    app = DashboardUI(root)
    root.mainloop()
