import ttkbootstrap as tb
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk
import threading
import time
import os
import random
import string
from tkinter import font as tkfont
import tkinter.filedialog as filedialog
from antivirus.scanner import Scanner

# --- Load Custom Fonts ---
def load_custom_fonts(root):
    font_dir = os.path.join(os.path.dirname(__file__), 'assets')
    try:
        tkfont.Font(root=root, name='Orbitron', file=os.path.join(font_dir, 'Orbitron-Bold.ttf'))
        tkfont.Font(root=root, name='RobotoMono', file=os.path.join(font_dir, 'RobotoMono-Regular.ttf'))
    except Exception:
        pass  # fallback to system fonts if not available

# --- Matrix Rain Animation ---
class MatrixRain(tk.Canvas):
    def __init__(self, master, width, height, **kwargs):
        super().__init__(master, width=width, height=height, bg='#0a0f1a', highlightthickness=0, **kwargs)
        self.width = width
        self.height = height
        self.font = ('RobotoMono', 16, 'bold')
        self.chars = string.ascii_letters + string.digits + '@#$%&*'
        self.columns = int(width / 18)
        self.drops = [random.randint(0, height // 18) for _ in range(self.columns)]
        self.running = True
        self.after(50, self.draw)

    def draw(self):
        if not self.running:
            return
        self.delete('all')
        for i in range(self.columns):
            char = random.choice(self.chars)
            x = i * 18
            y = self.drops[i] * 18
            self.create_text(x, y, text=char, fill='#39ff14', font=self.font)
            if random.random() > 0.975:
                self.drops[i] = 0
            else:
                self.drops[i] += 1
            if self.drops[i] * 18 > self.height:
                self.drops[i] = 0
        self.after(50, self.draw)

    def stop(self):
        self.running = False

# --- Glassmorphic Card ---
class GlassCard(tk.Frame):
    def __init__(self, master, width=320, height=160, border_color='#00fff7', **kwargs):
        super().__init__(master, bg='#0a0f1a', bd=0, highlightthickness=0, **kwargs)
        self.config(width=width, height=height)
        self['highlightbackground'] = border_color
        self['highlightcolor'] = border_color
        self['highlightthickness'] = 4
        self['bd'] = 0
        self['relief'] = 'ridge'
        self.place_card()
    def place_card(self):
        self.pack_propagate(False)
        self.grid_propagate(False)

# --- Splash Screen ---
def show_splash(root):
    splash = tk.Toplevel(root)
    splash.overrideredirect(True)
    splash.geometry('500x300+500+250')
    splash.configure(bg='#0a0f1a')
    logo = tk.Label(splash, text='🛡️', font=('Orbitron', 64, 'bold'), fg='#00fff7', bg='#0a0f1a')
    logo.pack(pady=(40, 10))
    title = tk.Label(splash, text='PROSECURELABS', font=('Orbitron', 28, 'bold'), fg='#ff00c8', bg='#0a0f1a')
    title.pack()
    subtitle = tk.Label(splash, text='Cybersecurity Suite', font=('RobotoMono', 16), fg='#ffe600', bg='#0a0f1a')
    subtitle.pack(pady=(10, 0))
    loading = tk.Label(splash, text='Loading...', font=('RobotoMono', 12), fg='#39ff14', bg='#0a0f1a')
    loading.pack(pady=(30, 0))
    root.after(2200, splash.destroy)

# --- Neon Alert ---
def show_neon_alert(root, message):
    alert = tk.Toplevel(root)
    alert.title('THREAT DETECTED!')
    alert.geometry('420x220')
    alert.configure(bg='#181c20')
    alert.resizable(False, False)
    border = tk.Frame(alert, bg='#ff1744', height=8)
    border.pack(fill='x', side='top')
    border2 = tk.Frame(alert, bg='#ff1744', height=8)
    border2.pack(fill='x', side='bottom')
    border3 = tk.Frame(alert, bg='#ff1744', width=8)
    border3.pack(fill='y', side='left')
    border4 = tk.Frame(alert, bg='#ff1744', width=8)
    border4.pack(fill='y', side='right')
    icon = tk.Label(alert, text='⚠️', font=('Orbitron', 40, 'bold'), fg='#ff1744', bg='#181c20')
    icon.pack(pady=(20, 10))
    title = tk.Label(alert, text='THREAT DETECTED!', font=('Orbitron', 18, 'bold'), fg='#ff1744', bg='#181c20')
    title.pack()
    msg = tk.Label(alert, text=message, font=('RobotoMono', 12), fg='#fff', bg='#181c20', wraplength=360)
    msg.pack(pady=(10, 0))
    close_btn = tk.Button(alert, text='CLOSE', command=alert.destroy, font=('Orbitron', 12, 'bold'), bg='#ff1744', fg='#fff', activebackground='#00fff7', activeforeground='#0a0f1a', relief='raised', bd=3)
    close_btn.pack(pady=16)
    alert.grab_set()
    alert.focus_set()
    alert.transient(root)

# --- Main App ---
class ProsecureLabsApp(tb.Window):
    def __init__(self):
        super().__init__(themename='darkly')
        self.title('PROSECURELABS Cybersecurity Suite')
        self.geometry('1200x800')
        self.minsize(1000, 700)
        self.style = tb.Style()
        self.configure(bg='#0a0f1a')
        load_custom_fonts(self)
        # --- Matrix Rain Background ---
        self.bg_canvas = MatrixRain(self, width=1200, height=800)
        self.bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        # --- Overlay Main UI ---
        self.ui_frame = tk.Frame(self, bg='', highlightthickness=0)
        self.ui_frame.place(relx=0, rely=0, relwidth=1, relheight=1)
        # --- Header ---
        header = tk.Frame(self.ui_frame, bg='#0a0f1a')
        header.pack(fill='x')
        logo = tk.Label(header, text='🛡️', font=('Orbitron', 36, 'bold'), fg='#00fff7', bg='#0a0f1a')
        logo.pack(side='left', padx=(30, 10), pady=20)
        title = tk.Label(header, text='PROSECURELABS', font=('Orbitron', 32, 'bold'), fg='#ff00c8', bg='#0a0f1a')
        title.pack(side='left', pady=20)
        # --- Load Tab Icons ---
        icon_files = [
            'dashboard.png',
            'antivirus.png',
            'firewall.png',
            'logs.png',
            'settings.png',
        ]
        icon_images = []
        for fname in icon_files:
            path = os.path.join(os.path.dirname(__file__), 'assets', fname)
            try:
                img = Image.open(path).convert('RGBA').resize((28, 28))
                icon_images.append(ImageTk.PhotoImage(img))
            except Exception:
                icon_images.append(None)
        # --- Custom Glassmorphic Horizontal Row Tab Bar at Bottom of Left Sidebar ---
        main_container = tk.Frame(self, bg='#0a0f1a')
        main_container.pack(fill='both', expand=True)
        sidebar = tk.Frame(main_container, bg='#181c20', width=80, highlightthickness=0)
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)
        # Add a spacer to push the tab bar to the bottom
        sidebar_spacer = tk.Frame(sidebar, bg='#181c20')
        sidebar_spacer.pack(side='top', fill='both', expand=True)
        tabbar = tk.Frame(sidebar, bg='#181c20')
        tabbar.pack(side='bottom', fill='x', pady=16)
        content_frame = tk.Frame(main_container, bg='#0a0f1a')
        content_frame.pack(side='left', fill='both', expand=True)
        tab_names = [
            ('Dashboard', '#00fff7'),
            ('Antivirus', '#39ff14'),
            ('Firewall', '#ff1744'),
            ('Logs', '#ffe600'),
            ('Settings', '#7c3aed'),
        ]
        self.tabs = []
        self.tab_frames = []
        self.active_tab_idx = 0
        num_tabs = len(tab_names)
        for i, (name, color) in enumerate(tab_names):
            frame = tk.Frame(tabbar, bg='#181c20', bd=0, highlightthickness=0)
            frame.pack(side='left', padx=4, pady=0)
            frame.config(width=64, height=64)
            frame.pack_propagate(False)
            inner = tk.Frame(frame, bg='#181c20', bd=0, highlightthickness=0)
            inner.pack(expand=True, fill='both')
            if icon_images[i]:
                icon_label = tk.Label(inner, image=icon_images[i], bg='#181c20')
                icon_label.pack(side='top', pady=(8, 2))
            btn = tk.Label(
                inner, text=name, font=('Orbitron', 14, 'bold'), fg=color, bg='#181c20',
                padx=2, pady=2, cursor='hand2', bd=0, relief='flat', highlightthickness=0
            )
            btn.pack(side='top', pady=(0, 4))
            self.tabs.append(btn)
            self.tab_frames.append(frame)
        # Neon bar for active tab (now at the bottom of the tab frame)
        self.neon_bar = tk.Frame(tabbar, bg=tab_names[0][1], width=64, height=6)
        self.neon_bar.place(x=0, y=64)  # Initial placement
        notebook = ttk.Notebook(content_frame, style='TNotebook')
        notebook.pack(fill='both', expand=True, padx=20, pady=20)
        dash_tab = tk.Frame(notebook, bg='#0a0f1a')
        av_tab = tk.Frame(notebook, bg='#0a0f1a')
        fw_tab = tk.Frame(notebook, bg='#0a0f1a')
        logs_tab = tk.Frame(notebook, bg='#0a0f1a')
        settings_tab = tk.Frame(notebook, bg='#0a0f1a')
        notebook.add(dash_tab, text='Dashboard')
        notebook.add(av_tab, text='Antivirus')
        notebook.add(fw_tab, text='Firewall')
        notebook.add(logs_tab, text='Logs')
        notebook.add(settings_tab, text='Settings')
        def update_neon_bar(idx):
            tabbar.update_idletasks()  # Force geometry update
            frame = self.tab_frames[idx]
            x = frame.winfo_x()
            w = frame.winfo_width()
            self.neon_bar.config(bg=tab_names[idx][1], width=w)
            self.neon_bar.place(x=x, y=64)
        def switch_tab(idx):
            notebook.select(idx)
            self.set_active_tab(idx)
            update_neon_bar(idx)
            self.after(50, lambda: update_neon_bar(idx))  # Fallback to ensure correct placement
        def on_tab_hover(event, idx):
            if idx != self.active_tab_idx:
                self.tab_frames[idx].config(bg='#23272b')
        def on_tab_leave(event, idx):
            if idx != self.active_tab_idx:
                self.tab_frames[idx].config(bg='#181c20')
        def on_tab_press(event, idx):
            self.tab_frames[idx].config(bg='#222')
        def on_tab_release(event, idx):
            switch_tab(idx)
        def on_tab_changed(event):
            idx = notebook.index(notebook.select())
            self.set_active_tab(idx)
            update_neon_bar(idx)
            self.after(50, lambda: update_neon_bar(idx))
        notebook.bind('<<NotebookTabChanged>>', on_tab_changed)
        # Now bind the events after the functions are defined and widgets are packed
        self.after(100, lambda: [
            widget.bind('<Button-1>', lambda e, idx=i: switch_tab(idx)) or
            widget.bind('<Enter>', lambda e, idx=i: on_tab_hover(e, idx)) or
            widget.bind('<Leave>', lambda e, idx=i: on_tab_leave(e, idx)) or
            widget.bind('<ButtonPress-1>', lambda e, idx=i: on_tab_press(e, idx)) or
            widget.bind('<ButtonRelease-1>', lambda e, idx=i: on_tab_release(e, idx))
            for i in range(len(tab_names))
            for widget in ([self.tab_frames[i], self.tab_frames[i].winfo_children()[0], self.tabs[i]] + ([self.tab_frames[i].winfo_children()[0].winfo_children()[0]] if icon_images[i] else []))
        ])
        def set_active_tab(idx):
            for j, frame in enumerate(self.tab_frames):
                if j == idx:
                    frame.config(bg='#23272b', highlightbackground=tab_names[j][1], highlightcolor=tab_names[j][1], highlightthickness=3, bd=0)
                    self.tabs[j].config(fg=tab_names[j][1], font=('Orbitron', 15, 'bold'))
                else:
                    frame.config(bg='#181c20', highlightthickness=0, bd=0)
                    self.tabs[j].config(fg='#888', font=('Orbitron', 14, 'bold'))
            self.active_tab_idx = idx
        self.set_active_tab = set_active_tab
        self.set_active_tab(0)
        self.after(100, lambda: update_neon_bar(0))
        # Keyboard navigation
        def on_key(event):
            idx = self.active_tab_idx
            if event.keysym == 'Right':
                idx = (idx + 1) % len(self.tabs)
                switch_tab(idx)
            elif event.keysym == 'Left':
                idx = (idx - 1) % len(self.tabs)
                switch_tab(idx)
        self.bind_all('<Left>', on_key)
        self.bind_all('<Right>', on_key)
        # --- Dashboard Card Example ---
        dash_card = GlassCard(dash_tab, width=340, height=180, border_color='#00fff7')
        dash_card.place(x=80, y=80)
        card_title = tk.Label(dash_card, text='Total Scans', font=('Orbitron', 18, 'bold'), fg='#00fff7', bg='#0a0f1a')
        card_title.pack(pady=(24, 0))
        card_value = tk.Label(dash_card, text='128', font=('Orbitron', 48, 'bold'), fg='#ffe600', bg='#0a0f1a')
        card_value.pack(pady=(10, 0))
        card_sub = tk.Label(dash_card, text='(Last 30 days)', font=('RobotoMono', 12), fg='#39ff14', bg='#0a0f1a')
        card_sub.pack(pady=(8, 0))
        # --- Antivirus Tab Professional Card ---
        av_card = GlassCard(av_tab, width=420, height=260, border_color='#39ff14')
        av_card.place(x=120, y=80)
        av_header = tk.Label(av_card, text='Antivirus Scanner', font=('Orbitron', 22, 'bold'), fg='#39ff14', bg='#0a0f1a')
        av_header.pack(pady=(24, 0))
        av_desc = tk.Label(av_card, text='Scan files, folders, or your full system for threats.', font=('RobotoMono', 13), fg='#fff', bg='#0a0f1a')
        av_desc.pack(pady=(10, 0))
        av_result = tk.Label(av_card, text='', font=('RobotoMono', 12), fg='#fff', bg='#0a0f1a', wraplength=380, justify='left')
        av_result.pack(pady=(10, 0))
        self.scanner = Scanner(signature_db_path=os.path.join(os.path.dirname(__file__), '../antivirus/signatures.db'))
        def do_scan():
            file_path = filedialog.askopenfilename()
            if not file_path:
                return
            av_result.config(text='Scanning...')
            self.update()
            result, virus_name, vt_details = self.scanner.scan_file(file_path)
            if result == 'Error':
                av_result.config(text='Error reading file.')
                return
            if result == 'Clean':
                av_result.config(text=f'File: {file_path}\nStatus: CLEAN\nNo threats detected.')
            elif result == 'Infected':
                vt_str = ''
                if vt_details:
                    vt_str = f"\nVirusTotal: {vt_details.get('virus_name','')}\nDetection Ratio: {vt_details.get('detection_ratio','')}\nEngines: {', '.join(vt_details.get('engines', [])[:5])}\nScan Date: {vt_details.get('scan_date','')}\nLink: {vt_details.get('permalink','')}\nAll Names: {', '.join(vt_details.get('all_names', []))}"
                av_result.config(text=f'File: {file_path}\nStatus: INFECTED\nVirus: {virus_name}{vt_str}', fg='#ff1744')
                show_neon_alert(self, f'THREAT DETECTED!\n{file_path}\nVirus: {virus_name}')
            else:
                av_result.config(text=f'File: {file_path}\nStatus: UNKNOWN')
        av_btn = tk.Button(av_card, text='START SCAN', font=('Orbitron', 14, 'bold'), fg='#0a0f1a', bg='#39ff14', activebackground='#00fff7', activeforeground='#0a0f1a', bd=0, relief='ridge', padx=24, pady=8, cursor='hand2', command=do_scan)
        av_btn.pack(pady=(24, 0))
        # --- Firewall Tab Professional Card ---
        fw_card = GlassCard(fw_tab, width=420, height=220, border_color='#ff1744')
        fw_card.place(x=120, y=80)
        fw_header = tk.Label(fw_card, text='Firewall Control', font=('Orbitron', 22, 'bold'), fg='#ff1744', bg='#0a0f1a')
        fw_header.pack(pady=(24, 0))
        fw_desc = tk.Label(fw_card, text='Manage rules, monitor network, and block threats.', font=('RobotoMono', 13), fg='#fff', bg='#0a0f1a')
        fw_desc.pack(pady=(10, 0))
        fw_btn = tk.Button(fw_card, text='VIEW RULES', font=('Orbitron', 14, 'bold'), fg='#0a0f1a', bg='#ff1744', activebackground='#ffe600', activeforeground='#0a0f1a', bd=0, relief='ridge', padx=24, pady=8, cursor='hand2')
        fw_btn.pack(pady=(24, 0))
        # --- Logs Tab Professional Card ---
        logs_card = GlassCard(logs_tab, width=420, height=220, border_color='#ffe600')
        logs_card.place(x=120, y=80)
        logs_header = tk.Label(logs_card, text='Security Logs', font=('Orbitron', 22, 'bold'), fg='#ffe600', bg='#0a0f1a')
        logs_header.pack(pady=(24, 0))
        logs_desc = tk.Label(logs_card, text='View, search, and export all security events.', font=('RobotoMono', 13), fg='#fff', bg='#0a0f1a')
        logs_desc.pack(pady=(10, 0))
        logs_btn = tk.Button(logs_card, text='VIEW LOGS', font=('Orbitron', 14, 'bold'), fg='#0a0f1a', bg='#ffe600', activebackground='#39ff14', activeforeground='#0a0f1a', bd=0, relief='ridge', padx=24, pady=8, cursor='hand2')
        logs_btn.pack(pady=(24, 0))
        # --- Settings Tab Professional Card ---
        settings_card = GlassCard(settings_tab, width=420, height=220, border_color='#7c3aed')
        settings_card.place(x=120, y=80)
        settings_header = tk.Label(settings_card, text='Settings', font=('Orbitron', 22, 'bold'), fg='#7c3aed', bg='#0a0f1a')
        settings_header.pack(pady=(24, 0))
        settings_desc = tk.Label(settings_card, text='Theme, profile, and advanced configuration.', font=('RobotoMono', 13), fg='#fff', bg='#0a0f1a')
        settings_desc.pack(pady=(10, 0))
        settings_btn = tk.Button(settings_card, text='OPEN SETTINGS', font=('Orbitron', 14, 'bold'), fg='#0a0f1a', bg='#7c3aed', activebackground='#00fff7', activeforeground='#0a0f1a', bd=0, relief='ridge', padx=24, pady=8, cursor='hand2')
        settings_btn.pack(pady=(24, 0))
        # --- Footer ---
        footer = tk.Frame(self.ui_frame, bg='#0a0f1a')
        footer.pack(fill='x', side='bottom')
        footer_label = tk.Label(footer, text='© 2024 PROSECURELABS | Professional Cybersecurity Suite', font=('RobotoMono', 10, 'italic'), fg='#7c3aed', bg='#0a0f1a')
        footer_label.pack(side='right', padx=20, pady=5)
        # --- Set Custom Window Icon ---
        try:
            icon_path = os.path.join(os.path.dirname(__file__), 'assets', '3064197.png')
            icon_img = Image.open(icon_path).resize((64, 64))
            icon_tk = ImageTk.PhotoImage(icon_img)
            self.iconphoto(True, icon_tk)
            self._icon_tk = icon_tk  # prevent garbage collection
        except Exception:
            pass

if __name__ == '__main__':
    root = ProsecureLabsApp()
    show_splash(root)
    root.mainloop() 