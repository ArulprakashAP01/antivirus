import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import sys
import threading
import psutil
import datetime
import string
import tkinter.font as tkfont
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from antivirus.scanner import Scanner
from firewall.rules import FirewallRules
from utils.admin import is_admin
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

class FirewallAntivirusApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('PROSECURELABS')
        # Make full screen
        self.state('zoomed')  # For Windows
        self.minsize(1000, 700)
        self.resizable(True, True)

        # Create a 3D-like colorful background using Canvas
        self.bg_canvas = tk.Canvas(self, width=1920, height=1080, highlightthickness=0)
        self.bg_canvas.pack(fill='both', expand=True)
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        # Multi-stop gradient: orange -> yellow -> black -> pink
        stops = [
            (0, (255, 140, 0)),    # orange
            (0.3, (255, 200, 0)),  # yellow
            (0.6, (20, 20, 20)),   # black (dark)
            (0.8, (255, 0, 120)),  # magenta
            (1, (255, 120, 180)),  # pink
        ]
        for i in range(h):
            t = i / h
            for j in range(len(stops)-1):
                if stops[j][0] <= t <= stops[j+1][0]:
                    frac = (t - stops[j][0]) / (stops[j+1][0] - stops[j][0])
                    r = int(stops[j][1][0] + frac * (stops[j+1][1][0] - stops[j][1][0]))
                    g = int(stops[j][1][1] + frac * (stops[j+1][1][1] - stops[j][1][1]))
                    b = int(stops[j][1][2] + frac * (stops[j+1][1][2] - stops[j][1][2]))
                    color = f'#{r:02x}{g:02x}{b:02x}'
                    self.bg_canvas.create_line(0, i, w, i, fill=color)
                    break
        # Overlay large, semi-transparent ellipses for 3D effect (no white)
        try:
            self.bg_canvas.create_oval(w*0.1, h*0.1, w*0.6, h*0.7, fill='#ff880020', outline='')
            self.bg_canvas.create_oval(w*0.5, h*0.3, w*0.95, h*0.95, fill='#14141440', outline='')
            self.bg_canvas.create_oval(w*0.3, h*0.6, w*0.8, h*1.1, fill='#ffb34720', outline='')
        except Exception:
            pass  # If alpha not supported, skip ellipses

        # Place a frame on top of the canvas for all widgets
        self.main_frame = tk.Frame(self.bg_canvas, bg='', highlightthickness=0)
        self.bg_canvas.create_window((0, 0), window=self.main_frame, anchor='nw', width=w, height=h)

        # Set a dark cybersecurity theme
        style = ttk.Style(self)
        if 'vista' in style.theme_names():
            style.theme_use('vista')
        else:
            style.theme_use('clam')
        # Custom style for cybersecurity look
        style.configure('Cyber.TFrame', background='#181c20')
        style.configure('Cyber.TLabel', background='#181c20', foreground='#39ff14', font=('Consolas', 12))
        style.configure('CyberHeader.TLabel', background='#181c20', foreground='#00e6ff', font=('Arial', 28, 'bold'))
        style.configure('CyberSubHeader.TLabel', background='#181c20', foreground='#ff0080', font=('Arial', 16, 'bold'))
        style.configure('Cyber.TButton', font=('Arial', 14, 'bold'), foreground='#000', background='#39ff14', borderwidth=0, focusthickness=3, focuscolor='none', padding=10)
        style.map('Cyber.TButton', foreground=[('active', '#181c20')], background=[('active', '#00e6ff'), ('!active', '#39ff14')])
        style.configure('Cyber.Horizontal.TProgressbar', troughcolor='#222', bordercolor='#39ff14', background='#39ff14', lightcolor='#00e6ff', darkcolor='#ff0080')
        # Header/banner
        header = tk.Frame(self.main_frame, bg='#181c20', height=80, bd=0, highlightthickness=0)
        header.pack(fill='x')
        header_label = ttk.Label(
            header, text='🛡️ PROSECURELABS', style='CyberHeader.TLabel', anchor='w'
        )
        header_label.pack(side='left', padx=40, pady=20)
        # Colored divider under header
        divider = tk.Frame(self.main_frame, bg='#00e6ff', height=5, bd=0, highlightthickness=0)
        divider.pack(fill='x')
        # Add a footer
        footer = tk.Frame(self.main_frame, bg='#181c20', height=30)
        footer.pack(side='bottom', fill='x')
        footer_label = ttk.Label(footer, text='© 2024 PROSECURELABS | Professional Antivirus & Firewall', style='Cyber.TLabel')
        footer_label.pack(side='right', padx=20)

        tab_control = ttk.Notebook(self.main_frame)
        tab_control.pack(expand=1, fill='both', padx=30, pady=(0,20))

        # Add emoji/icons to tab labels
        antivirus_tab = ttk.Frame(tab_control)
        firewall_tab = ttk.Frame(tab_control)
        logs_tab = ttk.Frame(tab_control)
        settings_tab = ttk.Frame(tab_control)
        tab_control.add(antivirus_tab, text='🛡️ Antivirus')
        tab_control.add(firewall_tab, text='🔥 Firewall')
        tab_control.add(logs_tab, text='📋 Logs')
        tab_control.add(settings_tab, text='⚙️ Settings')

        # Card-like frame for Antivirus tab
        av_card = tk.Frame(antivirus_tab, bg='#23272b', bd=2, relief='groove', highlightbackground='#39ff14', highlightthickness=2)
        av_card.pack(padx=40, pady=40, fill='both', expand=True)
        av_frame = tk.Frame(av_card, bg='#23272b')
        av_frame.pack(padx=30, pady=30, fill='both', expand=True)
        scan_file_btn = ttk.Button(av_frame, text='📄 Scan File', command=self.scan_file, style='Cyber.TButton')
        scan_file_btn.grid(row=0, column=0, padx=15, pady=15, sticky='ew')
        scan_folder_btn = ttk.Button(av_frame, text='📁 Scan Folder', command=self.scan_folder, style='Cyber.TButton')
        scan_folder_btn.grid(row=0, column=1, padx=15, pady=15, sticky='ew')
        full_scan_btn = ttk.Button(av_frame, text='🖥️ Full System Scan', command=self.full_system_scan, style='Cyber.TButton')
        full_scan_btn.grid(row=0, column=2, padx=15, pady=15, sticky='ew')
        self.scan_result_text = tk.Text(av_frame, height=12, width=80, state='disabled', font=('Consolas', 12), bg='#101820', fg='#00e6ff', bd=2, relief='solid')
        self.scan_result_text.grid(row=1, column=0, columnspan=3, padx=5, pady=15, sticky='nsew')
        self.scan_result_text.tag_configure('filename', foreground='#00e6ff')
        ttk.Label(av_frame, text='Scan Log:', style='CyberSubHeader.TLabel').grid(row=2, column=0, sticky='w', pady=(10,0))
        self.log_text = tk.Text(av_frame, height=6, width=80, state='disabled', font=('Consolas', 11), bg='#101820', fg='#39ff14', bd=1, relief='solid')
        self.log_text.grid(row=3, column=0, columnspan=3, padx=5, pady=5, sticky='nsew')
        self.log_text.tag_configure('log_green', foreground='#39ff14')
        av_frame.grid_rowconfigure(1, weight=1)
        av_frame.grid_columnconfigure(0, weight=1)
        av_frame.grid_columnconfigure(1, weight=1)
        av_frame.grid_columnconfigure(2, weight=1)
        self.av_progress = ttk.Progressbar(av_frame, length=400, mode='indeterminate', style='Cyber.Horizontal.TProgressbar')
        self.av_progress.grid(row=4, column=0, columnspan=3, pady=15)
        self.save_report_btn = ttk.Button(av_frame, text='💾 Save Report', command=self.save_report, state='disabled', style='Cyber.TButton')
        self.save_report_btn.grid(row=5, column=0, pady=15)
        self.save_pdf_btn = ttk.Button(av_frame, text='📝 Save as PDF', command=self.save_report_pdf, state='disabled', style='Cyber.TButton')
        self.save_pdf_btn.grid(row=5, column=1, pady=15)
        self.last_report = ''
        self.last_report_data = None  # For PDF export

        # Card-like frame for Firewall tab
        fw_card = tk.Frame(firewall_tab, bg='#23272b', bd=2, relief='groove', highlightbackground='#00e6ff', highlightthickness=2)
        fw_card.pack(padx=40, pady=40, fill='both', expand=True)
        # Add Rule button (large, colorful)
        add_rule_btn = ttk.Button(fw_card, text='➕ Add Rule', command=self.add_rule, style='Cyber.TButton')
        add_rule_btn.pack(fill='x', pady=(0, 15), padx=10)
        fw_label = ttk.Label(fw_card, text='Firewall features will appear here.', style='CyberSubHeader.TLabel')
        fw_label.pack(pady=30)
        fw_progress = ttk.Progressbar(fw_card, length=400, mode='indeterminate', style='Cyber.Horizontal.TProgressbar')
        fw_progress.pack(pady=10)
        fw_progress.start(30)
        # Add inbound and outbound rules Treeviews
        columns = ('name', 'action', 'localip', 'remoteip', 'localport', 'remoteport')
        self.fw_rule_view = tk.StringVar(value='inbound')
        fw_radio_frame = tk.Frame(fw_card, bg='#23272b')
        fw_radio_frame.pack(fill='x', pady=(10,0))
        tk.Radiobutton(fw_radio_frame, text='Inbound Rules', variable=self.fw_rule_view, value='inbound', bg='#23272b', fg='#39ff14', font=('Arial', 12, 'bold'), selectcolor='#101820', activebackground='#23272b', activeforeground='#00e6ff', command=self._show_fw_tree).pack(side='left', padx=10)
        tk.Radiobutton(fw_radio_frame, text='Outbound Rules', variable=self.fw_rule_view, value='outbound', bg='#23272b', fg='#39ff14', font=('Arial', 12, 'bold'), selectcolor='#101820', activebackground='#23272b', activeforeground='#00e6ff', command=self._show_fw_tree).pack(side='left', padx=10)
        self.inbound_tree = ttk.Treeview(fw_card, columns=columns, show='headings', height=10, style='Cyber.Treeview')
        for col, label in zip(columns, ['Rule Name', 'Action', 'Local IP', 'Remote IP', 'Local Port', 'Remote Port']):
            self.inbound_tree.heading(col, text=label)
            self.inbound_tree.column(col, width=100)
        self.inbound_tree.tag_configure('allow', foreground='#39ff14')
        self.inbound_tree.tag_configure('block', foreground='#ff1744')
        self.outbound_tree = ttk.Treeview(fw_card, columns=columns, show='headings', height=10, style='Cyber.Treeview')
        for col, label in zip(columns, ['Rule Name', 'Action', 'Local IP', 'Remote IP', 'Local Port', 'Remote Port']):
            self.outbound_tree.heading(col, text=label)
            self.outbound_tree.column(col, width=100)
        self.outbound_tree.tag_configure('allow', foreground='#39ff14')
        self.outbound_tree.tag_configure('block', foreground='#ff1744')
        self.inbound_tree.pack(fill='both', expand=True, padx=10, pady=10)
        self.outbound_tree.pack_forget()
        # Add network connections text widget below rules
        conn_label = ttk.Label(fw_card, text='Active Network Connections:', style='CyberSubHeader.TLabel')
        conn_label.pack(anchor='w', padx=10, pady=(10,0))
        conn_frame = tk.Frame(fw_card, bg='#23272b')
        conn_frame.pack(fill='both', expand=False, padx=10, pady=(0,10))
        self.conn_text = tk.Text(conn_frame, height=8, width=90, state='disabled', font=('Consolas', 10), bg='#101820', fg='#00e6ff')
        self.conn_text.pack(side='left', fill='both', expand=True)
        conn_scroll = ttk.Scrollbar(conn_frame, command=self.conn_text.yview)
        self.conn_text['yscrollcommand'] = conn_scroll.set
        conn_scroll.pack(side='right', fill='y')
        # Card-like frame for Logs tab
        logs_card = tk.Frame(logs_tab, bg='#23272b', bd=2, relief='groove', highlightbackground='#ff0080', highlightthickness=2)
        logs_card.pack(padx=40, pady=40, fill='both', expand=True)
        logs_label = ttk.Label(logs_card, text='Logs will appear here.', style='CyberSubHeader.TLabel')
        logs_label.pack(pady=30)
        # Logs tab - real logs
        logs_frame = tk.Frame(logs_tab, bg='#23272b')
        logs_frame.pack(padx=40, pady=40, fill='both', expand=True)
        ttk.Label(logs_frame, text='Event Log:', style='CyberSubHeader.TLabel').pack(anchor='w')
        self.logs_text = tk.Text(logs_frame, height=15, width=80, state='disabled', font=('Consolas', 11), bg='#101820', fg='#39ff14')
        self.logs_text.pack(fill='both', expand=True, pady=5)
        logs_scroll = ttk.Scrollbar(logs_frame, command=self.logs_text.yview)
        self.logs_text['yscrollcommand'] = logs_scroll.set
        logs_scroll.pack(side='right', fill='y')
        clear_logs_btn = ttk.Button(logs_frame, text='Clear Logs', command=self.clear_logs, style='Cyber.TButton')
        clear_logs_btn.pack(anchor='e', pady=5)
        # Card-like frame for Settings tab
        settings_card = tk.Frame(settings_tab, bg='#23272b', bd=2, highlightbackground='#39ff14', highlightthickness=2)
        settings_card.pack(padx=40, pady=40, fill='both', expand=True)
        settings_label = ttk.Label(settings_card, text='Settings', style='CyberSubHeader.TLabel')
        settings_label.pack(pady=30)
        # Settings tab - real settings
        settings_frame = tk.Frame(settings_card, bg='#23272b')
        settings_frame.pack(padx=40, pady=40, fill='both', expand=True)
        admin = is_admin()
        admin_color = '#39ff14' if admin else '#ff1744'
        admin_text = 'Administrator' if admin else 'Standard User'
        admin_label = ttk.Label(settings_frame, text=f'Admin Status: {admin_text}', foreground=admin_color, background='#23272b', font=('Arial', 12, 'bold'))
        admin_label.grid(row=0, column=0, sticky='w', pady=5)
        update_btn = ttk.Button(settings_frame, text='Update Signatures', command=self.update_signatures, style='Cyber.TButton')
        update_btn.grid(row=1, column=0, sticky='w', pady=10)
        self.update_status = tk.StringVar()
        self.update_status.set('Signatures up to date.')
        update_status_label = ttk.Label(settings_frame, textvariable=self.update_status, font=('Arial', 10), background='#23272b', foreground='#00e6ff')
        update_status_label.grid(row=1, column=1, sticky='w', padx=10)
        ttk.Label(settings_frame, text='App Info:', style='CyberSubHeader.TLabel').grid(row=2, column=0, sticky='w', pady=(20,0))
        ttk.Label(settings_frame, text='PROSECURELABS', style='Cyber.TLabel').grid(row=3, column=0, sticky='w')
        ttk.Label(settings_frame, text='Version: 1.0', style='Cyber.TLabel').grid(row=4, column=0, sticky='w')
        ttk.Label(settings_frame, text='Author: Arul Prakash', style='Cyber.TLabel').grid(row=5, column=0, sticky='w')

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set('Ready')
        status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor='w', font=('Arial', 12))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.scanner = Scanner(signature_db_path=os.path.join('antivirus', 'signatures.db'))
        self.logs = []
        self.fw_rules = FirewallRules()

        # Initial load (must come after all widgets are created)
        self.refresh_rules()
        self.refresh_connections()
        self.after(5000, self.refresh_connections_periodically)
        self.after(2000, self.full_system_scan)  # Automatically start full system scan after 2 seconds

    def scan_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            start_time = datetime.datetime.now()
            self.status_var.set(f'Scanning file: {file_path}')
            self.av_progress.start(20)
            self.log_action(f"--- Scan Started: File Scan ---\nTarget: {file_path}\nStart Time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            file_hash = self.scanner.hash_file(file_path)
            result, virus_name, vt_details = self.scanner.scan_file(file_path)
            file_info = self.get_file_info(file_path)
            # Format and display result in professional style
            result_lines = [self.format_scan_table_header()]
            result_lines.append(self.format_scan_table_row(file_path, file_hash, result, virus_name, file_info, vt_details))
            self.display_scan_result_table(result_lines)
            self.log_action(self.format_scan_log(file_path, file_hash, result, file_info, virus_name, vt_details))
            if result == 'Infected':
                vt_msg = self.format_vt_details(vt_details) if vt_details else ''
                self.show_hacker_alert(file_path, virus_name, vt_msg)
            end_time = datetime.datetime.now()
            threat_count = 1 if result == 'Infected' else 0
            # Generate professional report
            self.last_report_data = dict(
                scan_type='File Scan',
                target=file_path,
                start_time=start_time,
                end_time=end_time,
                file_results=[(file_path, file_hash, result, virus_name, file_info, vt_details)],
                infected_files=[(file_path, virus_name, vt_details)] if result == 'Infected' else [],
                file_count=1,
                threat_count=threat_count
            )
            self.save_pdf_btn.config(state='normal')
            report = self.format_professional_report(
                scan_type='File Scan',
                target=file_path,
                start_time=start_time,
                end_time=end_time,
                file_results=[(file_path, file_hash, result, virus_name, file_info, vt_details)],
                infected_files=[(file_path, virus_name, vt_details)] if result == 'Infected' else [],
                file_count=1,
                threat_count=threat_count
            )
            self.last_report = report
            self.save_report_btn.config(state='normal')
            messagebox.showinfo('Scan Report', report)
            self.log_action(f"--- Scan Complete ---\nEnd Time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\nFiles Scanned: 1\nThreats Found: {threat_count}\n")
            self.status_var.set('Ready')
            self.av_progress.stop()

    def scan_folder(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            start_time = datetime.datetime.now()
            self.status_var.set(f'Scanning folder: {folder_path}')
            self.av_progress.start(20)
            self.log_action(f"--- Scan Started: Folder Scan ---\nTarget: {folder_path}\nStart Time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            results = self.scanner.scan_folder(folder_path, return_hashes=True)
            file_count = 0
            threat_count = 0
            infected_files = []
            file_results = []
            result_lines = [self.format_scan_table_header()]
            for file_path, (result, file_hash, virus_name, vt_details) in results.items():
                file_info = self.get_file_info(file_path)
                result_lines.append(self.format_scan_table_row(file_path, file_hash, result, virus_name, file_info, vt_details))
                self.log_action(self.format_scan_log(file_path, file_hash, result, file_info, virus_name, vt_details))
                file_count += 1
                file_results.append((file_path, file_hash, result, virus_name, file_info, vt_details))
                if result == 'Infected':
                    threat_count += 1
                    infected_files.append((file_path, virus_name, vt_details))
                    vt_msg = self.format_vt_details(vt_details) if vt_details else ''
                    self.show_hacker_alert(file_path, virus_name, vt_msg)
            self.display_scan_result_table(result_lines)
            end_time = datetime.datetime.now()
            # Generate professional report
            self.last_report_data = dict(
                scan_type='Folder Scan',
                target=folder_path,
                start_time=start_time,
                end_time=end_time,
                file_results=file_results,
                infected_files=infected_files,
                file_count=file_count,
                threat_count=threat_count
            )
            self.save_pdf_btn.config(state='normal')
            report = self.format_professional_report(
                scan_type='Folder Scan',
                target=folder_path,
                start_time=start_time,
                end_time=end_time,
                file_results=file_results,
                infected_files=infected_files,
                file_count=file_count,
                threat_count=threat_count
            )
            self.last_report = report
            self.save_report_btn.config(state='normal')
            messagebox.showinfo('Scan Report', report)
            self.log_action(f"--- Scan Complete ---\nEnd Time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\nFiles Scanned: {file_count}\nThreats Found: {threat_count}\n")
            self.status_var.set('Ready')
            self.av_progress.stop()

    def format_scan_table_header(self):
        return (f"{'File':60} {'Result':10} {'Virus Type':18} {'Size':10} {'Type':6} {'Modified':19}")

    def format_scan_table_row(self, file_path, file_hash, result, virus_name, file_info, vt_details=None):
        size_str = f"{file_info['size']} bytes"
        if isinstance(file_info['size'], int):
            if file_info['size'] > 1024*1024:
                size_str = f"{file_info['size']/1024/1024:.2f} MB"
            elif file_info['size'] > 1024:
                size_str = f"{file_info['size']/1024:.2f} KB"
        vt_str = ''
        if result == 'Infected' and vt_details:
            vt_str = f" [VT: {vt_details.get('detection_ratio','')}, {', '.join(vt_details.get('engines',[])[:3])}...]"
        return (f"{file_path[:60]:60} {result:10} {virus_name[:18] if result == 'Infected' else '':18} {size_str:10} {file_info['type'][:6]:6} {file_info['mtime']:19}{vt_str}")

    def display_scan_result_table(self, lines):
        self.scan_result_text.config(state='normal')
        self.scan_result_text.delete(1.0, tk.END)
        for line in lines:
            # Highlight file name (first word in each line) in black
            if line.strip():
                file_name = line.split()[0]
                self.scan_result_text.insert(tk.END, file_name, 'filename')
                self.scan_result_text.insert(tk.END, line[len(file_name):] + '\n')
            else:
                self.scan_result_text.insert(tk.END, '\n')
        self.scan_result_text.config(state='disabled')

    def format_vt_details(self, vt_details):
        if not vt_details:
            return ''
        engines = ', '.join(vt_details.get('engines', [])[:5])
        all_names = ', '.join(vt_details.get('all_names', []))
        return (f"Detection Ratio: {vt_details.get('detection_ratio','')}, Engines: {engines}\nScan Date: {vt_details.get('scan_date','')}\nVirusTotal Link: {vt_details.get('permalink','')}\nAll Names: {all_names}")

    def format_professional_report(self, scan_type, target, start_time, end_time, file_results, infected_files, file_count, threat_count):
        lines = []
        lines.append('='*60)
        lines.append('                 Antivirus Scan Report')
        lines.append('='*60)
        lines.append(f'Scan Type    : {scan_type}')
        lines.append(f'Target       : {target}')
        lines.append(f'Start Time   : {start_time.strftime("%Y-%m-%d %H:%M:%S")}')
        lines.append(f'End Time     : {end_time.strftime("%Y-%m-%d %H:%M:%S")}')
        lines.append(f'Files Scanned: {file_count}')
        lines.append(f'Threats Found: {threat_count}')
        lines.append('')
        lines.append('-'*30 + ' Infected Files ' + '-'*30)
        if infected_files:
            for file_path, virus_name, vt_details in infected_files:
                lines.append(f'{file_path}\n  Virus Type: {virus_name}')
                if vt_details:
                    lines.append(f'  [VirusTotal] Detection Ratio: {vt_details.get("detection_ratio","")}, Engines: {", ".join(vt_details.get("engines",[])[:5])}')
                    lines.append(f'  Scan Date: {vt_details.get("scan_date","")}, Link: {vt_details.get("permalink","")}')
                    lines.append(f'  All Names: {", ".join(vt_details.get("all_names",[]))}')
        else:
            lines.append('None')
        lines.append('')
        lines.append('-'*27 + ' All Results ' + '-'*27)
        lines.append(self.format_scan_table_header())
        for file_path, file_hash, result, virus_name, file_info, vt_details in file_results:
            lines.append(self.format_scan_table_row(file_path, file_hash, result, virus_name, file_info, vt_details))
        lines.append('='*60)
        return '\n'.join(lines)

    def format_scan_log(self, file_path, file_hash, result, file_info, virus_name, vt_details=None):
        size_str = f"{file_info['size']} bytes"
        if isinstance(file_info['size'], int):
            if file_info['size'] > 1024*1024:
                size_str = f"{file_info['size']/1024/1024:.2f} MB"
            elif file_info['size'] > 1024:
                size_str = f"{file_info['size']/1024:.2f} KB"
        virus_str = f"\n  Virus Type: {virus_name}" if result == 'Infected' else ''
        vt_str = ''
        if result == 'Infected' and vt_details:
            vt_str = f"\n  [VirusTotal] Detection Ratio: {vt_details.get('detection_ratio','')}, Engines: {', '.join(vt_details.get('engines',[])[:5])}\n  Scan Date: {vt_details.get('scan_date','')}, Link: {vt_details.get('permalink','')}\n  All Names: {', '.join(vt_details.get('all_names',[]))}"
        return (f"{file_path}\n  Hash: {file_hash}\n  Result: {result}{virus_str}\n  Size: {size_str}\n  Type: {file_info['type']}\n  Last Modified: {file_info['mtime']}{vt_str}")

    def get_file_info(self, file_path):
        try:
            stat = os.stat(file_path)
            size = stat.st_size
            ext = os.path.splitext(file_path)[1][1:].lower() or 'unknown'
            mtime = datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            return {'size': size, 'type': ext, 'mtime': mtime}
        except Exception:
            return {'size': 'N/A', 'type': 'N/A', 'mtime': 'N/A'}

    def display_scan_result_full(self, file_path, file_hash, result, file_info, virus_name):
        size_str = f"{file_info['size']} bytes"
        if isinstance(file_info['size'], int):
            if file_info['size'] > 1024*1024:
                size_str = f"{file_info['size']/1024/1024:.2f} MB"
            elif file_info['size'] > 1024:
                size_str = f"{file_info['size']/1024:.2f} KB"
        virus_str = f"\n  Virus Type: {virus_name}" if result == 'Infected' else ''
        self.scan_result_text.config(state='normal')
        self.scan_result_text.insert(tk.END, f'{file_path}\n  Hash: {file_hash}\n  Result: {result}{virus_str}\n  Size: {size_str}\n  Type: {file_info["type"]}\n  Last Modified: {file_info["mtime"]}\n')
        self.scan_result_text.config(state='disabled')

    def log_action(self, message):
        self.logs.append(message)
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + '\n', 'log_green')
        self.log_text.config(state='disabled')
        # Also update the Logs tab
        self.logs_text.config(state='normal')
        self.logs_text.insert(tk.END, message + '\n')
        self.logs_text.see(tk.END)
        self.logs_text.config(state='disabled')

    def _show_fw_tree(self):
        if self.fw_rule_view.get() == 'inbound':
            self.outbound_tree.pack_forget()
            self.inbound_tree.pack(fill='both', expand=True, padx=10, pady=10)
        else:
            self.inbound_tree.pack_forget()
            self.outbound_tree.pack(fill='both', expand=True, padx=10, pady=10)

    def refresh_rules(self):
        for tree in [self.inbound_tree, self.outbound_tree]:
            for i in tree.get_children():
                tree.delete(i)
        rules = self.fw_rules.list_rules()
        for rule in rules:
            parts = rule.split('|')
            if len(parts) >= 7:
                name, action, direction, localip, remoteip, localport, remoteport = [p.strip() for p in parts[:7]]
                tag = 'allow' if action.lower() == 'allow' else 'block'
                values = (name, action, localip, remoteip, localport, remoteport)
                if direction.lower() == 'in':
                    self.inbound_tree.insert('', 'end', values=values, tags=(tag,))
                elif direction.lower() == 'out':
                    self.outbound_tree.insert('', 'end', values=values, tags=(tag,))
        self.status_var.set('Firewall rules refreshed')

    def add_rule(self):
        # Show dialog to enter all rule details (no program path)
        dialog = tk.Toplevel(self)
        dialog.title('Add Firewall Rule')
        dialog.geometry('400x350')
        dialog.resizable(False, False)
        fields = {}
        labels = [
            ('Rule Name', 'name'),
            ('Direction (in/out)', 'direction'),
            ('Action (allow/block)', 'action'),
            ('Local IP', 'localip'),
            ('Remote IP', 'remoteip'),
            ('Local Port', 'localport'),
            ('Remote Port', 'remoteport'),
        ]
        for i, (label, key) in enumerate(labels):
            ttk.Label(dialog, text=label+':').grid(row=i, column=0, sticky='w', padx=10, pady=5)
            entry = ttk.Entry(dialog, width=30)
            entry.grid(row=i, column=1, padx=10, pady=5)
            fields[key] = entry
        def submit():
            vals = {k: v.get().strip() for k, v in fields.items()}
            if not vals['name'] or not vals['direction'] or not vals['action']:
                messagebox.showerror('Error', 'Name, Direction, and Action are required.')
                return
            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            status = self.fw_rules.add_rule(
                vals['name'], vals['direction'], vals['action'],
                vals['localip'], vals['remoteip'], vals['localport'], vals['remoteport']
            )
            self.refresh_rules()
            log_msg = (f"--- Firewall Rule Added ---\nName: {vals['name']}\nDirection: {vals['direction']}\nAction: {vals['action']}\n"
                       f"Local IP: {vals['localip']}\nRemote IP: {vals['remoteip']}\nLocal Port: {vals['localport']}\nRemote Port: {vals['remoteport']}\nTime: {now}\nStatus: {'Success' if status else 'Failed'}\n")
            self.log_action(log_msg)
            self.status_var.set(f"Rule added for {vals['name']}")
            dialog.destroy()
        submit_btn = ttk.Button(dialog, text='Add Rule', command=submit)
        submit_btn.grid(row=len(labels), column=0, columnspan=2, pady=15)

    def remove_rule(self):
        tree = self.inbound_tree if self.fw_rule_view.get() == 'inbound' else self.outbound_tree
        selected = tree.selection()
        if selected:
            item = tree.item(selected[0])
            rule_name = item['values'][0]
            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            status = self.fw_rules.remove_rule(rule_name)
            self.refresh_rules()
            log_msg = (f"--- Firewall Rule Removed ---\nName: {rule_name}\nTime: {now}\nStatus: {'Success' if status else 'Failed'}\n")
            self.log_action(log_msg)
            self.status_var.set(f'Rule removed: {rule_name}')

    def view_rule_details(self):
        tree = self.inbound_tree if self.fw_rule_view.get() == 'inbound' else self.outbound_tree
        selected = tree.selection()
        if selected:
            item = tree.item(selected[0])
            vals = item['values']
            details = (
                f"Rule Name: {vals[0]}\nAction: {vals[1]}\n"
                f"Local IP: {vals[2]}\nRemote IP: {vals[3]}\nLocal Port: {vals[4]}\nRemote Port: {vals[5]}"
            )
            messagebox.showinfo('Rule Details', details)

    def block_app(self):
        app_path = filedialog.askopenfilename(title='Select Application to Block')
        if app_path:
            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            status = self.fw_rules.block_app(app_path)
            self.refresh_rules()
            log_msg = (f"--- Firewall Block App ---\nApp: {app_path}\nTime: {now}\nStatus: {'Success' if status else 'Failed'}\n")
            self.log_action(log_msg)
            self.status_var.set(f'Blocked: {app_path}')

    def unblock_app(self):
        app_path = filedialog.askopenfilename(title='Select Application to Unblock')
        if app_path:
            now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            status = self.fw_rules.unblock_app(app_path)
            self.refresh_rules()
            log_msg = (f"--- Firewall Unblock App ---\nApp: {app_path}\nTime: {now}\nStatus: {'Success' if status else 'Failed'}\n")
            self.log_action(log_msg)
            self.status_var.set(f'Unblocked: {app_path}')

    def refresh_connections(self):
        self.conn_text.config(state='normal')
        self.conn_text.delete(1.0, tk.END)
        for conn in psutil.net_connections(kind='inet'):
            laddr = f'{conn.laddr.ip}:{conn.laddr.port}' if conn.laddr else ''
            raddr = f'{conn.raddr.ip}:{conn.raddr.port}' if conn.raddr else ''
            status = conn.status
            pid = conn.pid
            # Get process name
            try:
                proc_name = psutil.Process(pid).name() if pid else 'System'
            except Exception:
                proc_name = 'Unknown'
            # Color code by status
            if status == 'ESTABLISHED':
                tag = 'established'
            elif status == 'LISTEN':
                tag = 'listen'
            else:
                tag = 'other'
            line = f'{laddr} -> {raddr} | {status} | PID: {pid} | {proc_name}\n'
            self.conn_text.insert(tk.END, line, tag)
        # Tag config for colors
        self.conn_text.tag_config('established', foreground='green')
        self.conn_text.tag_config('listen', foreground='orange')
        self.conn_text.tag_config('other', foreground='gray')
        self.conn_text.config(state='disabled')

    def refresh_connections_periodically(self):
        self.refresh_connections()
        self.after(5000, self.refresh_connections_periodically)

    def update_signatures(self):
        # Placeholder for signature update logic
        self.update_status.set('Signatures updated (placeholder).')
        self.status_var.set('Signatures updated.')

    def clear_logs(self):
        self.logs.clear()
        self.log_text.config(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state='disabled')
        self.logs_text.config(state='normal')
        self.logs_text.delete(1.0, tk.END)
        self.logs_text.config(state='disabled')

    def save_report(self):
        if not self.last_report:
            messagebox.showinfo('No Report', 'No scan report to save.')
            return
        file_path = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Text Files', '*.txt')], title='Save Scan Report')
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(self.last_report)
            messagebox.showinfo('Report Saved', f'Report saved to:\n{file_path}')

    def save_report_pdf(self):
        if not self.last_report_data:
            messagebox.showinfo('No Report', 'No scan report to save.')
            return
        file_path = filedialog.asksaveasfilename(defaultextension='.pdf', filetypes=[('PDF Files', '*.pdf')], title='Save Scan Report as PDF')
        if not file_path:
            return
        data = self.last_report_data
        doc = SimpleDocTemplate(file_path, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []
        # Header
        elements.append(Paragraph('<para align=center><font size=20 color="#ff8800"><b>PROSECURELABS</b></font></para>', styles['Title']))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph('<b>Antivirus Scan Report</b>', styles['Heading2']))
        elements.append(Spacer(1, 12))
        # Scan summary
        summary = f'''
        <b>Scan Type:</b> {data['scan_type']}<br/>
        <b>Target:</b> {data['target']}<br/>
        <b>Start Time:</b> {data['start_time'].strftime('%Y-%m-%d %H:%M:%S')}<br/>
        <b>End Time:</b> {data['end_time'].strftime('%Y-%m-%d %H:%M:%S')}<br/>
        <b>Files Scanned:</b> {data['file_count']}<br/>
        <b>Threats Found:</b> {data['threat_count']}<br/>
        '''
        elements.append(Paragraph(summary, styles['Normal']))
        elements.append(Spacer(1, 12))
        # Infected files
        elements.append(Paragraph('<b>Infected Files</b>', styles['Heading3']))
        if data['infected_files']:
            for file_path, virus_name, vt_details in data['infected_files']:
                elements.append(Paragraph(f'<font color="red">{file_path}</font><br/><b>Virus Type:</b> {virus_name}', styles['Normal']))
        else:
            elements.append(Paragraph('None', styles['Normal']))
        elements.append(Spacer(1, 12))
        # All results table
        elements.append(Paragraph('<b>All Results</b>', styles['Heading3']))
        table_data = [[
            'File', 'Result', 'Virus Type', 'Size', 'Type', 'Modified'
        ]]
        for file_path, file_hash, result, virus_name, file_info, vt_details in data['file_results']:
            size_str = f"{file_info['size']} bytes"
            if isinstance(file_info['size'], int):
                if file_info['size'] > 1024*1024:
                    size_str = f"{file_info['size']/1024/1024:.2f} MB"
                elif file_info['size'] > 1024:
                    size_str = f"{file_info['size']/1024:.2f} KB"
            table_data.append([
                file_path,
                result,
                virus_name if result == 'Infected' else '',
                size_str,
                file_info['type'],
                file_info['mtime']
            ])
        t = Table(table_data, repeatRows=1, colWidths=[180, 60, 90, 60, 40, 90])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.orange),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 12),
            ('BOTTOMPADDING', (0,0), (-1,0), 8),
            ('BACKGROUND', (0,1), (-1,-1), colors.whitesmoke),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 24))
        # Footer
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        elements.append(Paragraph(f'<para align=center><font size=10>Generated by PROSECURELABS | {now}</font></para>', styles['Normal']))
        doc.build(elements)
        messagebox.showinfo('PDF Saved', f'Report saved to:\n{file_path}')

    def full_system_scan(self):
        def scan_all_drives():
            drives = [f'{d}:\\' for d in string.ascii_uppercase if os.path.exists(f'{d}:\\')]
            total_files = 0
            total_threats = 0
            all_file_results = []
            all_infected_files = []
            start_time = datetime.datetime.now()
            self.status_var.set('Scanning all drives...')
            self.av_progress.start(20)
            for drive in drives:
                self.log_action(f"--- Scan Started: Full System Scan ---\nTarget: {drive}\nStart Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                try:
                    for root, dirs, files in os.walk(drive):
                        for name in files:
                            file_path = os.path.join(root, name)
                            self.log_action(f"Scanning: {file_path}")
                            try:
                                result, file_hash, virus_name, vt_details = self.scanner.scan_file(file_path), self.scanner.hash_file(file_path), '', None
                                if isinstance(result, tuple) and len(result) == 3:
                                    result, virus_name, vt_details = result
                                file_info = self.get_file_info(file_path)
                                all_file_results.append((file_path, file_hash, result, virus_name, file_info, vt_details))
                                self.log_action(self.format_scan_log(file_path, file_hash, result, file_info, virus_name, vt_details))
                                total_files += 1
                                if result == 'Infected':
                                    total_threats += 1
                                    all_infected_files.append((file_path, virus_name, vt_details))
                                    vt_msg = self.format_vt_details(vt_details) if vt_details else ''
                                    self.show_hacker_alert(file_path, virus_name, vt_msg)
                            except Exception as e:
                                self.log_action(f"Error scanning file {file_path}: {e}")
                except Exception as e:
                    self.log_action(f"Error scanning drive {drive}: {e}")
            end_time = datetime.datetime.now()
            result_lines = [self.format_scan_table_header()]
            for file_path, file_hash, result, virus_name, file_info, vt_details in all_file_results:
                result_lines.append(self.format_scan_table_row(file_path, file_hash, result, virus_name, file_info, vt_details))
            self.display_scan_result_table(result_lines)
            self.last_report_data = dict(
                scan_type='Full System Scan',
                target='All Drives',
                start_time=start_time,
                end_time=end_time,
                file_results=all_file_results,
                infected_files=all_infected_files,
                file_count=total_files,
                threat_count=total_threats
            )
            self.save_pdf_btn.config(state='normal')
            report = self.format_professional_report(
                scan_type='Full System Scan',
                target='All Drives',
                start_time=start_time,
                end_time=end_time,
                file_results=all_file_results,
                infected_files=all_infected_files,
                file_count=total_files,
                threat_count=total_threats
            )
            self.last_report = report
            self.save_report_btn.config(state='normal')
            messagebox.showinfo('Scan Report', report)
            self.log_action(f"--- Scan Complete ---\nEnd Time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\nFiles Scanned: {total_files}\nThreats Found: {total_threats}\n")
            self.status_var.set('Ready')
            self.av_progress.stop()
        threading.Thread(target=scan_all_drives, daemon=True).start()

    def show_hacker_alert(self, file_path, virus_name, vt_msg=None):
        alert = tk.Toplevel(self)
        alert.title('THREAT DETECTED!')
        alert.geometry('500x320')
        alert.configure(bg='#101820')
        alert.resizable(False, False)
        # Neon border effect
        border = tk.Frame(alert, bg='#39ff14', height=8)
        border.pack(fill='x', side='top')
        border2 = tk.Frame(alert, bg='#39ff14', height=8)
        border2.pack(fill='x', side='bottom')
        border3 = tk.Frame(alert, bg='#39ff14', width=8)
        border3.pack(fill='y', side='left')
        border4 = tk.Frame(alert, bg='#39ff14', width=8)
        border4.pack(fill='y', side='right')
        # Main content
        icon = tk.Label(alert, text='⚠️', font=('Arial', 48, 'bold'), fg='#ff1744', bg='#101820')
        icon.pack(pady=(20, 10))
        title = tk.Label(alert, text='THREAT DETECTED!', font=('Arial', 22, 'bold'), fg='#39ff14', bg='#101820')
        title.pack()
        file_label = tk.Label(alert, text=f'File: {file_path}', font=('Consolas', 12), fg='#00e6ff', bg='#101820', wraplength=440)
        file_label.pack(pady=(10, 0))
        virus_label = tk.Label(alert, text=f'Virus Type: {virus_name}', font=('Arial', 14, 'bold'), fg='#ff1744', bg='#101820')
        virus_label.pack(pady=(5, 0))
        if vt_msg:
            vt_label = tk.Label(alert, text=vt_msg, font=('Consolas', 10), fg='#39ff14', bg='#101820', wraplength=440, justify='left')
            vt_label.pack(pady=(10, 0))
        close_btn = tk.Button(alert, text='CLOSE', command=alert.destroy, font=('Arial', 12, 'bold'), bg='#39ff14', fg='#101820', activebackground='#00e6ff', activeforeground='#101820', relief='raised', bd=3)
        close_btn.pack(pady=20)
        alert.grab_set()
        alert.focus_set()
        alert.transient(self)

if __name__ == '__main__':
    app = FirewallAntivirusApp()
    app.mainloop() 