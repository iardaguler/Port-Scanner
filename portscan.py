import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import queue
import csv
import subprocess
import platform

# ================= CONFIG =================
DEFAULT_THREADS = 150
DEFAULT_TIMEOUT = 0.6

# ================= MAIN CLASS =================
class CyberPortScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Port Scanner")
        self.root.geometry("1050x680")
        self.root.configure(bg="#020617")
        self.root.resizable(False, False)
        self.center_window()

        # STATE
        self.queue = queue.Queue()
        self.stop_flag = threading.Event()
        self.scanning = False
        self.results_data = []
        self.total_ports = 0
        self.scanned_ports = 0

        self.build_ui()
        self.root.after(100, self.process_queue)

    # ================= WINDOW =================
    def center_window(self):
        w, h = 1050, 690
        x = (self.root.winfo_screenwidth() - w) // 2
        y = (self.root.winfo_screenheight() - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    # ================= UI =================
    def build_ui(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Green.Horizontal.TProgressbar",
            troughcolor="#020617",
            background="#00ff9c",
            thickness=18
        )

        # HEADER
        header = tk.Frame(self.root, bg="#020617", height=55)
        header.pack(fill="x")
        self.title_label = tk.Label(header, text="CYBER PORT SCANNER", fg="#00ff9c", bg="#020617", font=("Segoe UI", 18, "bold"))
        self.title_label.pack(side="left", padx=20)
        self.status_label = tk.Label(header, text="Idle", fg="#94a3b8", bg="#020617", font=("Segoe UI", 11))
        self.status_label.pack(side="right", padx=20)

        # MAIN
        main = tk.Frame(self.root, bg="#020617")
        main.pack(fill="both", expand=True)

        # LEFT PANEL
        left = tk.Frame(main, bg="#020617", width=360)
        left.pack(side="left", fill="y")

        self.target_entry = self.create_entry(left, "Target")

        # Scan modes
        self.scan_mode = tk.StringVar(value="quick")
        self.custom_radio = None
        for text, val in [
            ("⚡ Quick Scan (1–1024)", "quick"),
            ("🔍 Full Scan (1–65535)", "full"),
            ("🎯 Custom Range", "custom")
        ]:
            rb = tk.Radiobutton(left, text=text, value=val, variable=self.scan_mode,
                                bg="#020617", fg="#e5e7eb", selectcolor="#020617", font=("Segoe UI", 10))
            rb.pack(anchor="w", padx=20)
            if val == "custom":
                self.custom_radio = rb  # Custom Range radio reference
        self.scan_mode.trace_add("write", self.toggle_custom_range)

        # CUSTOM RANGE FRAME (Start/End Port alt alta)
        self.custom_frame = tk.Frame(left, bg="#020617")

        tk.Label(self.custom_frame, text="Start Port", fg="#38bdf8", bg="#020617", font=("Segoe UI", 10, "bold")).grid(
        row=0, column=0, padx=20, pady=5, sticky="w")
        self.start_port = tk.Entry(self.custom_frame, bg="#020617", fg="#e5e7eb", insertbackground="white", width=20)
        self.start_port.grid(row=1, column=0, padx=20, pady=5)

        tk.Label(self.custom_frame, text="End Port", fg="#38bdf8", bg="#020617", font=("Segoe UI", 10, "bold")).grid(
        row=2, column=0, padx=20, pady=5, sticky="w")
        self.end_port = tk.Entry(self.custom_frame, bg="#020617", fg="#e5e7eb", insertbackground="white", width=20)
        self.end_port.grid(row=3, column=0, padx=20, pady=5)

        self.custom_frame.pack_forget()  # başta gizli

        # Performance sliders
        self.thread_slider = self.create_slider(left, "Threads", 50, 500, DEFAULT_THREADS)
        self.timeout_slider = self.create_slider(left, "Timeout (sec)", 0.2, 3.0, DEFAULT_TIMEOUT, is_float=True)

        # Buttons
        self.create_button(left, "▶ START SCAN", "#00ff9c", self.start_scan)
        self.create_button(left, "⏹ STOP SCAN", "#f87171", self.stop_scan)
        self.create_button(left, "🧹 CLEAR SCREEN", "#64748b", self.clear_screen)
        self.create_button(left, "💾 EXPORT RESULTS", "#38bdf8", self.export_results)

        # RIGHT PANEL
        right = tk.Frame(main, bg="#020617")
        right.pack(side="right", fill="both", expand=True)

        self.progress = tk.DoubleVar()
        ttk.Progressbar(right, variable=self.progress, maximum=100, style="Green.Horizontal.TProgressbar").pack(fill="x", padx=15, pady=10)

        scrollbar = tk.Scrollbar(right)
        scrollbar.pack(side="right", fill="y")

        self.results = tk.Listbox(right, bg="#020617", fg="#00ff9c", font=("Consolas", 10), bd=0, yscrollcommand=scrollbar.set)
        self.results.pack(fill="both", expand=True, padx=10, pady=10)
        scrollbar.config(command=self.results.yview)

    # ================= UI HELPERS =================
    def create_entry(self, parent, label):
        tk.Label(parent, text=label, fg="#38bdf8", bg="#020617", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=20, pady=(10,5))
        e = tk.Entry(parent, bg="#020617", fg="#e5e7eb", insertbackground="white")
        e.pack(fill="x", padx=20)
        return e

    def create_slider(self, parent, label, minv, maxv, default, is_float=False):
        tk.Label(parent, text=label, fg="#38bdf8", bg="#020617", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=20, pady=(10,0))
        var = tk.DoubleVar(value=default) if is_float else tk.IntVar(value=default)
        tk.Scale(parent, from_=minv, to=maxv, variable=var, orient="horizontal", bg="#020617", fg="#e5e7eb",
                 resolution=0.1 if is_float else 1, highlightthickness=0).pack(fill="x", padx=20)
        return var

    def create_button(self, parent, text, color, cmd):
        tk.Button(parent, text=text, bg=color, fg="#020617", font=("Segoe UI", 11, "bold"), bd=10, height=1, command=cmd).pack(fill="x", padx=20, pady=5)

    def toggle_custom_range(self, *_):
        if self.scan_mode.get() == "custom":
            self.custom_frame.pack(after=self.custom_radio, fill="x", pady=(1,0))
        else:
            self.custom_frame.pack_forget()

    # ================= LOGIC =================
    def validate_target(self, target):
        try:
            socket.gethostbyname(target)
            return True
        except:
            return False

    def os_fingerprint(self,target):
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            out = subprocess.check_output(["ping", param, "1", target], stderr=subprocess.DEVNULL, text=True).lower()
            ttl = None
            for part in out.split():
                if "ttl=" in part:
                    ttl = int(part.split("ttl=")[1])
                    break
            if ttl is None:
                return "Unknown"

            # Tahmini OS
            if ttl <= 64:
                return "Linux/macOS"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Network Device"
        except:
            return "Unknown"

    def grab_banner(self, sock):
        try:
            sock.sendall(b"\r\n")
            return sock.recv(1024).decode(errors="ignore").strip()[:60]
        except:
            return ""

    def start_scan(self):
        if self.scanning: return
        target = self.target_entry.get().strip()
        if not target or not self.validate_target(target):
            messagebox.showerror("Error", "Invalid target")
            return

        # OS fingerprint
        os_guess = self.os_fingerprint(target)
        self.title_label.config(text=f"CYBER PORT SCANNER | OS: {os_guess}")

        # PORT RANGE
        try:
            mode = self.scan_mode.get()
            if mode == "quick":
                ports = range(1,1025)
            elif mode == "full":
                ports = range(1,65536)
            else:
                ports = range(int(self.start_port.get()), int(self.end_port.get())+1)
        except:
            messagebox.showerror("Error", "Invalid port range")
            return

        self.stop_flag.clear()
        self.results.delete(0, tk.END)
        self.results_data.clear()
        self.total_ports = len(ports)
        self.scanned_ports = 0
        self.progress.set(0)
        self.scanning = True
        self.status_label.config(text="Scanning...")

        threading.Thread(target=self.scan_ports, args=(target, ports, int(self.thread_slider.get()), float(self.timeout_slider.get())), daemon=True).start()

    def stop_scan(self):
        if not self.scanning: return
        self.stop_flag.set()
        self.scanning = False
        self.scanned_ports = 0
        self.progress.set(0)
        self.status_label.config(text="Scan stopped")

    def scan_ports(self, target, ports, threads, timeout):
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for port in ports:
                if self.stop_flag.is_set(): break
                executor.submit(self.scan_tcp, target, port, timeout)
        self.queue.put(("done", None))

    def scan_tcp(self, target, port, timeout):
        if self.stop_flag.is_set(): return
        try:
            s = socket.socket()
            s.settimeout(timeout)
            if s.connect_ex((target, port)) == 0:
                banner = self.grab_banner(s)
                self.queue.put(("open", "TCP", port, banner))
            s.close()
        except:
            pass
        finally:
            if not self.stop_flag.is_set(): self.queue.put(("progress", None))

    def process_queue(self):
        while not self.queue.empty():
            msg = self.queue.get()
            if msg[0]=="open":
                proto, port, banner = msg[1:]
                line = f"[ {proto} ] Port {port}"
                if banner: line += f" | {banner}"
                self.results.insert(tk.END, line)
                self.results_data.append((proto, port, banner))
            elif msg[0]=="progress":
                if self.scanning:
                    self.scanned_ports += 1
                    self.progress.set((self.scanned_ports/self.total_ports)*100)
            elif msg[0]=="done":
                if self.scanning:
                    self.status_label.config(text="Scan completed")
                self.scanning = False
        self.root.after(100, self.process_queue)

    # ================= UTILS =================
    def clear_screen(self):
        self.results.delete(0, tk.END)
        self.results_data.clear()
        self.progress.set(0)
        self.status_label.config(text="Idle")

    def export_results(self):
        if not self.results_data:
            messagebox.showwarning("Warning", "No results to export")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt"), ("CSV", "*.csv")])
        if not path: return
        if path.endswith(".csv"):
            with open(path,"w",newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Protocol","Port","Banner"])
                writer.writerows(self.results_data)
        else:
            with open(path,"w") as f:
                for r in self.results_data:
                    f.write(f"{r}\n")

# ================= RUN =================
if __name__ == "__main__":
    root = tk.Tk()
    CyberPortScanner(root)
    root.mainloop()
