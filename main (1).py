#MACTOOLS OPEN CODE github.com/winmatwey/mac-tools
import os
import shutil
import subprocess
import platform
import psutil
import stat
import hashlib
import time
import pty
import threading
import select
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog, ttk, simpledialog


# ----------------------
# Theme colors
# ----------------------
BG = "#1e1e1e"          # dark background
FG = "#008000"          # black text
BTN_BG = "#ffffff"      # white buttons
BTN_HOVER = "#e0e0e0"   # hover effect
ACCENT = "#4da3ff"      # headers/label color
FONT = ("Helvetica", 11)
FONT_TITLE = ("Helvetica", 13, "bold")
FONT_MONO = ("Courier", 10)

# ----------------------
# Paths
# ----------------------
CACHE_PATHS = [os.path.expanduser("~/Library/Caches"), "/Library/Caches"]
LAUNCH_PATHS = [os.path.expanduser("~/Library/LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"]
LOG_PATH = os.path.expanduser("~/Library/Logs")
REPORT = []

# ----------------------
# Helpers
# ----------------------
def log(title, data):
    REPORT.append(f"\n=== {title} ===\n{data}")

def show_text(title, content):
    log(title, content)
    win = tk.Toplevel()
    win.title(title)
    win.configure(bg=BG)
    win.geometry("900x450")
    txt = scrolledtext.ScrolledText(win, bg=BG, fg=FG, font=FONT_MONO, insertbackground=FG)
    txt.pack(expand=True, fill="both")
    txt.insert("end", content)

def styled_button(parent, text, command):
    btn = tk.Label(
        parent,
        text=text,
        bg=BTN_BG,
        fg=FG,
        font=FONT_BTN,
        anchor="w",
        padx=12,
        pady=8,
        cursor="hand2"
    )

    btn.bind("<Enter>", lambda e: btn.config(bg=BTN_HOVER))
    btn.bind("<Leave>", lambda e: btn.config(bg=BTN_BG))
    btn.bind("<Button-1>", lambda e: command())

    btn.pack(fill="x", pady=4)
    return btn

def need_sudo_hint():
    if os.geteuid() != 0:
        messagebox.showwarning("Permissions", "Some actions require sudo.\nRun with:\nsudo python3 filename.py")

# ----------------------
# Scrollable Frame
# ----------------------
class ScrollableFrame(tk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        canvas = tk.Canvas(self, bg=BG, highlightthickness=0)
        canvas.configure(
            bg=BG,
            highlightthickness=0
        )
        scrollbar = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.scrollable_frame = tk.Frame(canvas, bg=BG)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window(
            (0, 0),
            window=self.scrollable_frame,
            anchor="nw"
        )

        self.window_id = canvas.create_window(
            (0, 0),
            window=self.scrollable_frame,
            anchor="nw"
        )

        def resize_canvas(event):
            canvas.itemconfig(self.window_id, width=event.width)

        canvas.bind("<Configure>", resize_canvas)

        canvas.bind("<Configure>", resize_canvas)
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
# ----------------------
# FILE EXPLORER
# ----------------------
def file_explorer():
    import re
    win = tk.Toplevel()
    win.title("🗂 File Explorer PRO")
    win.geometry("1200x700")
    win.configure(bg=BG)

    cwd = tk.StringVar(value=os.path.expanduser("~"))
    filter_var = tk.StringVar()
    sort_by = tk.StringVar(value="Name")

    # ---------------- TOP BAR ----------------
    top = tk.Frame(win, bg=BG)
    top.pack(fill="x", padx=5, pady=5)

    tk.Button(top, text="🏠", command=lambda: load_dir(os.path.expanduser("~"))).pack(side="left")
    tk.Button(top, text="⬆", command=lambda: load_dir(os.path.dirname(cwd.get()))).pack(side="left")
    tk.Button(top, text="🔄", command=lambda: load_dir(cwd.get())).pack(side="left")

    path_entry = tk.Entry(top, textvariable=cwd, bg=BTN_BG, fg=FG)
    path_entry.pack(side="left", fill="x", expand=True, padx=5)

    tk.Label(top, text="🔎 Filter:", bg=BG, fg=ACCENT).pack(side="left", padx=(5,0))
    search = tk.Entry(top, textvariable=filter_var, bg=BTN_BG, fg=FG, width=20)
    search.pack(side="left", padx=5)

    tk.Label(top, text="Sort by:", bg=BG, fg=ACCENT).pack(side="left", padx=(10,0))
    sort_option = ttk.Combobox(top, textvariable=sort_by, values=["Name", "Size", "Date", "Perms"], width=10)
    sort_option.pack(side="left", padx=5)

    # ---------------- TREEVIEW ----------------
    cols = ("size", "perm", "mtime")
    tree = ttk.Treeview(win, columns=cols, show="tree headings")
    tree.heading("#0", text="Name")
    tree.heading("size", text="Size")
    tree.heading("perm", text="Perms")
    tree.heading("mtime", text="Modified")
    tree.column("#0", width=500)
    tree.column("size", width=100, anchor="e")
    tree.column("perm", width=100)
    tree.column("mtime", width=160)
    tree.pack(expand=True, fill="both", padx=5, pady=5)

    # ---------------- HELPERS ----------------
    def format_size(size):
        for unit in ["B","KB","MB","GB","TB"]:
            if isinstance(size, int) and size < 1024:
                return f"{size} {unit}"
            size = size / 1024
        return f"{size:.2f} PB"

    def load_dir(path):
        try:
            path = os.path.abspath(os.path.expanduser(path))
            cwd.set(path)
            tree.delete(*tree.get_children())

            items = []
            flt = filter_var.get().lower()

            for name in sorted(os.listdir(path)):
                if flt and flt not in name.lower():
                    continue
                full = os.path.join(path, name)
                try:
                    st = os.stat(full)
                    size = st.st_size if os.path.isfile(full) else "-"
                    perm = stat.filemode(st.st_mode)
                    mtime = time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime))
                except:
                    size, perm, mtime = "?", "?", "?"
                items.append((name, size, perm, mtime, full, os.path.isdir(full)))

            # -------- SORTING ----------
            key_map = {"Name":0,"Size":1,"Perms":2,"Date":3}
            key = key_map.get(sort_by.get(), 0)
            items.sort(key=lambda x: x[key] if x[key] != "-" else 0)

            for i in items:
                tag = "folder" if i[5] else ""
                tree.insert("", "end", text=i[0], values=(i[1], i[2], i[3]), tags=(tag,))

            tree.tag_configure("folder", foreground="#4da3ff")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ---------------- SELECTION ----------------
    def selected():
        sel = tree.selection()
        if not sel:
            return None
        name = tree.item(sel[0], "text")
        return os.path.join(cwd.get(), name)

    def open_item(event=None):
        p = selected()
        if not p:
            return
        if os.path.isdir(p):
            load_dir(p)
        else:
            subprocess.Popen(["open", p])

    tree.bind("<Double-1>", open_item)
    search.bind("<KeyRelease>", lambda e: load_dir(cwd.get()))
    sort_option.bind("<<ComboboxSelected>>", lambda e: load_dir(cwd.get()))
# ---------------- CONTEXT MENU ----------------
    menu = tk.Menu(win, tearoff=0)

    def new_file():
        name = simpledialog.askstring("New file", "Filename:")
        if name:
            open(os.path.join(cwd.get(), name), "w").close()
            load_dir(cwd.get())

    def new_folder():
        name = simpledialog.askstring("New folder", "Folder name:")
        if name:
            os.mkdir(os.path.join(cwd.get(), name))
            load_dir(cwd.get())

    def delete():
        p = selected()
        if p and messagebox.askyesno("Delete", f"Delete {p}?"):
            shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
            load_dir(cwd.get())

    def rename():
        p = selected()
        if not p:
            return
        new = simpledialog.askstring("Rename", "New name:")
        if new:
            os.rename(p, os.path.join(os.path.dirname(p), new))
            load_dir(cwd.get())

    def copy_path():
        p = selected()
        if p:
            win.clipboard_clear()
            win.clipboard_append(p)
            messagebox.showinfo("Copied", p)

    def md5_hash():
        p = selected()
        if p and os.path.isfile(p):
            h = hashlib.md5(open(p,"rb").read()).hexdigest()
            show_text("MD5", h)

    def sha256_hash():
        p = selected()
        if p and os.path.isfile(p):
            h = hashlib.sha256(open(p,"rb").read()).hexdigest()
            show_text("SHA256", h)

    def perms():
        p = selected()
        if p:
            st = os.stat(p)
            show_text("Permissions",
                      f"Path: {p}\nMode: {stat.filemode(st.st_mode)}\nUID: {st.st_uid}\nGID: {st.st_gid}")

    def xattrs():
        p = selected()
        if p:
            out = subprocess.getoutput(f"xattr -l '{p}'")
            show_text("xattr", out or "No attributes")

    def open_finder():
        p = selected()
        if p:
            subprocess.Popen(["open", "-R", p])

    def open_terminal():
        p = selected() or cwd.get()
        subprocess.Popen(["open", "-a", "Terminal", p])

    menu.add_command(label="Open", command=open_item)
    menu.add_command(label="Show in Finder", command=open_finder)
    menu.add_command(label="Open in Terminal", command=open_terminal)
    menu.add_separator()
    menu.add_command(label="New File", command=new_file)
    menu.add_command(label="New Folder", command=new_folder)
    menu.add_command(label="Rename", command=rename)
    menu.add_command(label="Delete", command=delete)
    menu.add_separator()
    menu.add_command(label="Copy Path", command=copy_path)
    menu.add_command(label="MD5 Hash", command=md5_hash)
    menu.add_command(label="SHA256 Hash", command=sha256_hash)
    menu.add_command(label="Permissions", command=perms)
    menu.add_command(label="xattr", command=xattrs)

    def popup(event):
        iid = tree.identify_row(event.y)
        if iid:
            tree.selection_set(iid)
            menu.tk_popup(event.x_root, event.y_root)

    tree.bind("<Button-3>", popup)

    load_dir(cwd.get())
# ----------------------
# EMBEDDED TERMINAL
# ----------------------
import os, subprocess, threading, tkinter as tk
from tkinter import scrolledtext, simpledialog

def embedded_terminal():
    win = tk.Toplevel()
    win.title("🖥 Admin Terminal (stable)")
    win.geometry("900x500")
    win.configure(bg="#1e1e1e")

    output = scrolledtext.ScrolledText(
        win, bg="#000000", fg="#00ff00",
        font=("Courier", 10), state="disabled"
    )
    output.pack(expand=True, fill="both")

    entry = tk.Entry(win, bg="#ffffff", fg="#000000")
    entry.pack(fill="x", padx=5, pady=5)
    entry.focus()

    history = []
    hist_index = 0

    sudo_pass = simpledialog.askstring(
        "Sudo authentication",
        "Enter sudo password:",
        show="*",
        parent=win
    )

    if not sudo_pass:
        return

    def write(text):
        output.config(state="normal")
        output.insert("end", text)
        output.see("end")
        output.config(state="disabled")

    write("🔐 Admin terminal ready (sudo enabled)\n\n")

    def run_command(cmd):
        write(f"$ {cmd}\n")

        def worker():
            try:
                p = subprocess.Popen(
                    ["sudo", "-S"] + cmd.split(),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                out, _ = p.communicate(sudo_pass + "\n")
                write(out + "\n")
            except Exception as e:
                write(str(e) + "\n")

        threading.Thread(target=worker, daemon=True).start()

    def on_enter(event=None):
        nonlocal hist_index
        cmd = entry.get().strip()
        if not cmd:
            return "break"

        history.append(cmd)
        hist_index = len(history)
        entry.delete(0, "end")
        run_command(cmd)
        return "break"

    def history_up(event):
        nonlocal hist_index
        if history and hist_index > 0:
            hist_index -= 1
            entry.delete(0, "end")
            entry.insert(0, history[hist_index])

    def history_down(event):
        nonlocal hist_index
        if hist_index < len(history) - 1:
            hist_index += 1
            entry.delete(0, "end")
            entry.insert(0, history[hist_index])
        else:
            entry.delete(0, "end")

    entry.bind("<Return>", on_enter)
    entry.bind("<Up>", history_up)
    entry.bind("<Down>", history_down)
# ----------------------
# Finder Control
# ----------------------
def finder_restart():
    subprocess.run(["killall", "Finder"])
    subprocess.run(
        ["open", "/System/Library/CoreServices/Finder.app"]
    )
    messagebox.showinfo("Finder", "🔄 Finder restarted")
# ----------------------
# Ui control
# ----------------------
def kill_process(name):
    subprocess.run(["killall", name],
                   stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)

def ui_reset():
    kill_process("Dock")
    kill_process("Finder")
    kill_process("SystemUIServer")

    messagebox.showinfo(
        "UI",
        "🧱 UI RESTARTED\n\n"
        "Dock, Finder and Menu Bar are hidden and restored"
    )
# ----------------------
# Maintenance
# ----------------------
def clean_cache():
    removed = 0
    for path in CACHE_PATHS:
        if not os.path.exists(path): continue
        for i in os.listdir(path):
            p = os.path.join(path, i)
            try:
                if os.path.isdir(p): shutil.rmtree(p)
                else: os.remove(p)
                removed += 1
            except: pass
    messagebox.showinfo("🧹 Clean Cache", f"Removed: {removed} items")

def clear_logs():
    removed = 0
    if os.path.exists(LOG_PATH):
        for f in os.listdir(LOG_PATH):
            try:
                p = os.path.join(LOG_PATH, f)
                if os.path.isdir(p): shutil.rmtree(p)
                else: os.remove(p)
                removed += 1
            except: pass
    messagebox.showinfo("🧼 Clear Logs", f"Removed: {removed} items")

# ----------------------
# Startup / Persistence
# ----------------------
def get_startup_items():
    items = []
    for p in LAUNCH_PATHS:
        if not os.path.exists(p): continue
        for f in os.listdir(p):
            if f.endswith(".plist"): items.append(os.path.join(p,f))
    return sorted(items)

def manage_startup():
    items = get_startup_items()
    win = tk.Toplevel()
    win.title("🚀 Startup Manager")
    win.configure(bg=BG)
    win.geometry("900x500")

    listbox = tk.Listbox(win, selectmode=tk.MULTIPLE, font=FONT_MONO, bg=BTN_BG, fg=FG, selectbackground=ACCENT)
    listbox.pack(expand=True, fill="both")
    for i in items: listbox.insert("end", i)

    def select_all(): listbox.select_set(0, "end")
    def delete_selected():
        selected = listbox.curselection()
        removed = 0
        failed = 0
        for i in selected:
            try:
                os.remove(listbox.get(i))
                removed += 1
            except: failed += 1
        messagebox.showinfo("Result", f"Removed: {removed}\nFailed: {failed}")
        win.destroy()

    tk.Button(win, text="Select All", command=select_all, bg=ACCENT, fg=BG).pack(pady=2)
    tk.Button(win, text="Delete Selected", command=delete_selected, bg="red", fg=FG).pack(pady=2)
# ----------------------
# Security
# ----------------------
def gatekeeper(): show_text("🔐 Gatekeeper Status", subprocess.getoutput("spctl --status"))
def unsigned_apps():
    apps = []
    for root in ["/Applications", os.path.expanduser("~/Applications")]:
        if os.path.exists(root):
            for a in os.listdir(root):
                if a.endswith(".app"):
                    p = os.path.join(root,a)
                    try:
                        if subprocess.run(["codesign","-v",p], capture_output=True).returncode != 0: apps.append(p)
                    except: pass
    show_text("⚠️ Unsigned Apps", "\n".join(apps) or "None found")
def sudo_users():
    try:
        out = subprocess.getoutput("dscl . -read /Groups/admin GroupMembership")
        show_text("👑 Sudo Users", out)
    except: show_text("👑 Sudo Users", "Error retrieving sudo users")
# ----------------------
# Security Scanner
# ----------------------
def security_baseline():
    win = tk.Toplevel()
    win.title("🛡 Security Scanner")
    win.geometry("900x550")
    win.configure(bg=BG)

    tree = ttk.Treeview(
        win,
        columns=("status", "details"),
        show="headings"
    )
    tree.heading("status", text="Status")
    tree.heading("details", text="Details")
    tree.column("status", width=120, anchor="center")
    tree.column("details", width=740)
    tree.pack(expand=True, fill="both", padx=10, pady=10)

    def add(name, status, details):
        icon = {"OK": "🟢", "WARN": "🟡", "RISK": "🔴"}[status]
        tree.insert("", "end", values=(f"{icon} {name}", details))

    # --- Checks ---
    sip = subprocess.getoutput("csrutil status")
    add("SIP", "OK" if "enabled" in sip else "RISK", sip)

    gatekeeper = subprocess.getoutput("spctl --status")
    add("Gatekeeper", "OK" if "enabled" in gatekeeper else "RISK", gatekeeper)

    fw = subprocess.getoutput("defaults read /Library/Preferences/com.apple.alf globalstate")
    add("Firewall", "OK" if fw != "0" else "RISK", f"State: {fw}")

    fv = subprocess.getoutput("fdesetup status")
    add("FileVault", "OK" if "On" in fv else "WARN", fv)

    ssh = subprocess.getoutput("systemsetup -getremotelogin")
    add("SSH", "WARN" if "On" in ssh else "OK", ssh)

    root_login = subprocess.getoutput("dsenableroot -q")
    add("Root Login", "RISK" if "enabled" in root_login.lower() else "OK", root_login)

    auto_login = subprocess.getoutput("defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser")
    add("Auto Login", "RISK" if auto_login else "OK", auto_login or "Disabled")

    note = tk.Label(
        win,
        text="⚠️ Results are informational. Review risks manually.",
        bg=BG, fg=ACCENT
    )
    note.pack(pady=5)
# ----------------------
# System / Audit
# ----------------------
def system_info(): show_text("🖥 System Info", f"macOS: {platform.mac_ver()[0]}\nCPU: {platform.processor()}\nArch: {platform.machine()}")
def disk_usage(): show_text("💾 Disk Usage", subprocess.getoutput("df -h"))
def login_history(): show_text("📋 Login History", subprocess.getoutput("last -10"))
def cron_jobs(): show_text("🕒 Cron Jobs", subprocess.getoutput("crontab -l") or "Empty")
def mount_points(): show_text("🗂 Volumes", subprocess.getoutput("mount"))
# ----------------------
# Network
# ----------------------
def network(): show_text("🌐 Network Interfaces", subprocess.getoutput("ifconfig"))
def active_connections(): show_text("🔗 Active Connections", subprocess.getoutput("lsof -i -n -P | head -50"))
def dns(): show_text("🧩 DNS Config", subprocess.getoutput("scutil --dns"))
# ----------------------
# Task Manager
# ----------------------
def task_manager():
    win = tk.Toplevel()
    win.title("🖥 Task Manager")
    win.geometry("900x500")

    tree = ttk.Treeview(win, columns=("PID","CPU%","MEM%","CMD"), show="headings")
    tree.pack(expand=True, fill="both")
    for col in ("PID","CPU%","MEM%","CMD"): tree.heading(col, text=col)

    for p in psutil.process_iter(['pid','name','cpu_percent','memory_percent']):
        tree.insert("", "end", values=(p.info['pid'], p.info['cpu_percent'], p.info['memory_percent'], p.info['name']))

    def kill_selected():
        sel = tree.selection()
        removed = 0
        failed = 0
        for i in sel:
            pid = int(tree.item(i)['values'][0])
            try:
                psutil.Process(pid).kill()
                removed += 1
            except:
                failed += 1
        messagebox.showinfo("Task Manager", f"Killed: {removed}\nFailed: {failed}")
        win.destroy()

    tk.Button(win, text="Kill Selected", command=kill_selected, bg="red", fg=FG).pack(pady=2)
# ------------------------------
# Incident Response / Forensics
# ------------------------------
def incident_response_center():
    win = tk.Toplevel()
    win.title("🧾 Incident Response & Forensics")
    win.geometry("1100x650")
    win.configure(bg=BG)

    nb = ttk.Notebook(win)
    nb.pack(expand=True, fill="both")

    # ---------- Helper ----------
    def tab(title):
        f = tk.Frame(nb, bg=BG)
        nb.add(f, text=title)
        return f

    def output_box(parent):
        txt = scrolledtext.ScrolledText(
            parent, bg=BG, fg=FG, font=FONT_MONO
        )
        txt.pack(expand=True, fill="both", padx=5, pady=5)
        return txt

    # ======================
    # INCIDENT SNAPSHOT
    # ======================
    t1 = tab("📸 Snapshot")
    out1 = output_box(t1)

    def snapshot():
        out1.delete("1.0", "end")
        data = {
            "Processes": "ps aux",
            "Network": "netstat -anv",
            "Users": "dscl . list /Users",
            "Logins": "last",
            "Sudoers": "cat /etc/sudoers | grep -v '^#'",
            "Startup": "ls /Library/LaunchDaemons ~/Library/LaunchAgents",
            "System": "system_profiler SPSoftwareDataType"
        }
        for title, cmd in data.items():
            out1.insert("end", f"\n=== {title} ===\n")
            out1.insert("end", subprocess.getoutput(cmd) + "\n")

    styled_button(t1, "📸 Collect Snapshot", snapshot)

    # ======================
    # PERSISTENCE
    # ======================
    t2 = tab("🔁 Persistence")
    out2 = output_box(t2)

    def persistence():
        out2.delete("1.0", "end")
        checks = {
            "LaunchAgents": "ls ~/Library/LaunchAgents",
            "LaunchDaemons": "ls /Library/LaunchDaemons",
            "Cron": "crontab -l",
            "Login Items": "osascript -e 'tell application \"System Events\" to get the name of every login item'"
        }
        for k, c in checks.items():
            out2.insert("end", f"\n=== {k} ===\n")
            out2.insert("end", subprocess.getoutput(c) + "\n")

    styled_button(t2, "🔁 Scan Persistence", persistence)

    # ======================
    # TIMELINE
    # ======================
    t3 = tab("⏱ Timeline")
    out3 = output_box(t3)

    def timeline():
        out3.delete("1.0", "end")
        cmds = [
            ("Recent Logins", "last"),
            ("Recent Files", "find ~ -type f -mtime -2 | head -100"),
            ("Installed Apps", "ls -lt /Applications | head -20")
        ]
        for title, cmd in cmds:
            out3.insert("end", f"\n=== {title} ===\n")
            out3.insert("end", subprocess.getoutput(cmd) + "\n")

    styled_button(t3, "⏱ Build Timeline", timeline)

    # ======================
    # LIVE STATE
    # ======================
    t4 = tab("📊 Live State")
    out4 = output_box(t4)

    def live_state():
        out4.delete("1.0", "end")
        cmds = {
            "Uptime": "uptime",
            "CPU Load": "sysctl -n vm.loadavg",
            "Memory": "vm_stat",
            "Disk": "df -h",
            "Users": "who"
        }
        for k, c in cmds.items():
            out4.insert("end", f"\n=== {k} ===\n")
            out4.insert("end", subprocess.getoutput(c) + "\n")

    styled_button(t4, "📊 Refresh State", live_state)

    # ======================
    # EXPORT
    # ======================
    t5 = tab("💾 Export")
    info = tk.Label(
        t5,
        text="Export data by copying output from tabs.\n(Zip / auto-export can be added next)",
        bg=BG, fg=ACCENT
    )
    info.pack(pady=20)

import json, plistlib, csv, binascii
import xml.dom.minidom

def file_viewer():
    path = filedialog.askopenfilename()
    if not path:
        return

    win = tk.Toplevel()
    win.title(f"📄 File Viewer — {os.path.basename(path)}")
    win.geometry("950x600")
    win.configure(bg=BG)

    txt = scrolledtext.ScrolledText(
        win, bg=BG, fg=FG, font=FONT_MONO
    )
    txt.pack(expand=True, fill="both")

    try:
        ext = os.path.splitext(path)[1].lower()

        if ext == ".json":
            with open(path) as f:
                obj = json.load(f)
            txt.insert("end", json.dumps(obj, indent=2))

        elif ext == ".plist":
            with open(path, "rb") as f:
                obj = plistlib.load(f)
            txt.insert("end", json.dumps(obj, indent=2))

        elif ext == ".xml":
            dom = xml.dom.minidom.parse(path)
            txt.insert("end", dom.toprettyxml())

        elif ext in [".csv"]:
            with open(path) as f:
                reader = csv.reader(f)
                for row in reader:
                    txt.insert("end", " | ".join(row) + "\n")

        elif ext in [".ini", ".cfg", ".env", ".log", ".txt"]:
            with open(path, errors="ignore") as f:
                txt.insert("end", f.read())

        elif os.path.getsize(path) < 5_000_000:
            with open(path, errors="ignore") as f:
                txt.insert("end", f.read())

        else:
            with open(path, "rb") as f:
                data = f.read(512)
            txt.insert("end", "BINARY PREVIEW:\n")
            txt.insert("end", binascii.hexlify(data).decode())

    except Exception as e:
        txt.insert("end", f"ERROR:\n{e}")
# ----------------------
# GUI
# ----------------------
root = tk.Tk()
# ===== SAFE DESIGN PATCH =====

BG = "#0e1116"
CARD_BG = "#1b2030"
BTN_BG = "#1f2535"
BTN_HOVER = "#2b3250"
ACCENT = "#5aa2ff"
FG = "#e7e9ee"

FONT_GROUP = ("SF Pro Display", 13, "bold")
FONT_BTN = ("SF Pro Display", 11)
FONT_MONO = ("JetBrains Mono", 11)

root.configure(bg=BG)
root.title("MacTools")
root.geometry("296x1000")
root.configure(bg=BG)
root.resizable(False, True)
need_sudo_hint()

def add_group(parent, title):
    frame = tk.Frame(parent, bg=CARD_BG)
    frame.pack(fill="x", pady=8)

    label = tk.Label(
        frame,
        text=title,
        bg=CARD_BG,
        fg=ACCENT,
        font=FONT_GROUP,
        anchor="w"
    )
    label.pack(fill="x", padx=10, pady=(8, 4))

    inner = tk.Frame(frame, bg=CARD_BG)
    inner.pack(fill="x", padx=8, pady=(0, 8))

    return inner
scroll_frame = ScrollableFrame(root)
scroll_frame.pack(expand=True, fill="both")
main_frame = scroll_frame.scrollable_frame
main_frame.configure(bg=BG)
title = tk.Label(
    main_frame,
    text="MacTools",
    bg=BG,
    fg=FG,
    font=("SF Pro Display", 20, "bold"),
    anchor="w"
)
title.pack(fill="x", padx=16, pady=(12, 18))
# --- Groups & buttons ---
mf_maint = add_group(main_frame, "🧹 Maintenance")
styled_button(mf_maint, "🧹 Clean Cache", clean_cache)
styled_button(mf_maint, "🧼 Clear Logs", clear_logs)
styled_button(mf_maint, "🚀 Manage Startup", manage_startup)


mf_sec = add_group(main_frame, "🛡 Security")
styled_button(mf_sec, "🔐 Gatekeeper Status", gatekeeper)
styled_button(mf_sec, "⚠️ Unsigned Apps", unsigned_apps)
styled_button(mf_sec, "👑 Sudo Users", sudo_users)
styled_button(mf_sec, "🛡 Security Scanner", security_baseline)


mf_sys = add_group(main_frame, "🧠 System Info & Audit")
styled_button(mf_sys, "🖥 System Info", system_info)
styled_button(mf_sys, "💾 Disk Usage", disk_usage)
styled_button(mf_sys, "🕒 Cron Jobs", cron_jobs)
styled_button(mf_sys, "🗂 Volumes", mount_points)
styled_button(mf_sys, "🧾 Open IR Center", incident_response_center)

mf_net = add_group(main_frame, "🌐 Network")
styled_button(mf_net, "🌐 Interfaces", network)
styled_button(mf_net, "🔗 Active Connections", active_connections)
styled_button(mf_net, "🧩 DNS Config", dns)

mf_dev = add_group(main_frame, "🧰 Tools")
styled_button(mf_dev, "🖥 Task Manager", task_manager)
styled_button(mf_dev, "🗂 File Explorer", file_explorer)
styled_button(mf_dev, "🖥 Open Terminal", embedded_terminal)
styled_button(mf_dev, "📄 File Viewer", file_viewer)

mf_kiosk = add_group(main_frame, "🧱UI Control")
styled_button(mf_kiosk, "🧱 Restart UI", ui_reset)
styled_button(mf_kiosk, "🔄 Restart Finder", finder_restart)

root.mainloop()
