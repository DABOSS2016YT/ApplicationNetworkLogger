import tkinter as tk
from tkinter import filedialog
import customtkinter as ctk
import psutil
from scapy.all import sniff, IP, TCP, UDP, Raw, ICMP, ARP, DNS
import threading
import binascii
# made by https://github.com/DABOSS2016YT
class NetworkLoggerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Logger")
        self.root.configure(bg='#1a1a1a')

        self.root.geometry("800x600")
        self.root.resizable(False, False)

        self.processes = []
        self.selected_process = None
        self.logging = False
        self.selected_protocol = "None"
        self.captured_packets = []
        self.stop_event = threading.Event()

        self.setup_gui()
    
    def setup_gui(self):
        ctk.set_appearance_mode("dark")

        self.search_frame = ctk.CTkFrame(self.root, fg_color='#1a1a1a', corner_radius=10)
        self.search_frame.grid(row=0, column=0, columnspan=4, sticky='ew', pady=10, padx=20)

        self.search_label = ctk.CTkLabel(self.search_frame, text="Search Process:", fg_color='#1a1a1a', text_color='#ffffff')
        self.search_label.grid(row=0, column=0, padx=10)

        self.search_entry = ctk.CTkEntry(self.search_frame, width=300, fg_color='#333333', text_color='#ffffff')
        self.search_entry.grid(row=0, column=1, padx=5)

        self.search_button = ctk.CTkButton(self.search_frame, text="Search", command=self.filter_processes, fg_color='#333333', text_color='#ffffff')
        self.search_button.grid(row=0, column=2, padx=5)

        self.refresh_button = ctk.CTkButton(self.search_frame, text="Refresh Programs", command=self.fetch_processes, fg_color='#333333', text_color='#ffffff')
        self.refresh_button.grid(row=0, column=3, padx=5)

        self.process_list_label = ctk.CTkLabel(self.root, text="Select a Process:", fg_color=None, text_color='#ffffff')
        self.process_list_label.grid(row=1, column=0, columnspan=4, pady=10)

        self.process_listbox = tk.Listbox(self.root, width=50, height=10, bg='#333333', fg='#ffffff', selectbackground='#555555')
        self.process_listbox.grid(row=2, column=0, columnspan=4, pady=10)
        self.process_listbox.bind('<<ListboxSelect>>', self.on_process_select)

        self.protocol_frame = ctk.CTkFrame(self.root, fg_color='#1a1a1a', corner_radius=10)
        self.protocol_frame.grid(row=3, column=0, columnspan=4, sticky='ew', pady=10, padx=10)

        self.protocol_label = ctk.CTkLabel(self.protocol_frame, text="Select Protocol (optional):", fg_color='#1a1a1a', text_color='#ffffff')
        self.protocol_label.grid(row=0, column=0, padx=10)

        self.protocol_options = ["None", "TCP", "UDP", "HTTP", "HTTPS", "FTP", "SMTP", "DNS", "ICMP", "ARP"]
        self.protocol_menu = ctk.CTkOptionMenu(self.protocol_frame, values=self.protocol_options, command=self.on_protocol_select, fg_color='#1a1a1a', text_color='#ffffff')
        self.protocol_menu.grid(row=0, column=1, padx=10)

        self.start_button = ctk.CTkButton(self.root, text="Start Logging", command=self.start_logging, fg_color='#333333', text_color='#ffffff')
        self.start_button.grid(row=4, column=0, padx=5, pady=5)

        self.stop_button = ctk.CTkButton(self.root, text="Stop Logging", command=self.stop_logging, fg_color='#333333', text_color='#ffffff')
        self.stop_button.grid(row=4, column=1, padx=5, pady=5)

        self.save_button = ctk.CTkButton(self.root, text="Save Network Activity", command=self.save_log, fg_color='#333333', text_color='#ffffff')
        self.save_button.grid(row=4, column=2, padx=5, pady=5)

        self.log_frame = ctk.CTkFrame(self.root, fg_color='#1a1a1a', corner_radius=10)
        self.log_frame.grid(row=5, column=0, columnspan=4, sticky='nsew', pady=10, padx=10)

        self.log_text = ctk.CTkTextbox(self.log_frame, height=30, width=80, fg_color='#242424', text_color='#ffffff', font=('Courier', 10))
        self.log_text.pack(side='left', fill='both', expand=True)

        self.text_scrollbar = ctk.CTkScrollbar(self.log_frame, command=self.log_text.yview)
        self.text_scrollbar.pack(side='right', fill='y')

        self.log_text.configure(yscrollcommand=self.text_scrollbar.set)

        self.log_text.bind("<MouseWheel>", lambda e: "break")

        self.collapsible_frame = ctk.CTkFrame(self.root, fg_color='#1a1a1a', corner_radius=10)
        self.collapsible_frame.grid(row=6, column=0, columnspan=4, sticky='ew', pady=10, padx=10)

        self.toggle_button = ctk.CTkButton(self.collapsible_frame, text=">", command=self.toggle_section, fg_color='#333333', text_color='#ffffff', width=3)
        self.toggle_button.grid(row=0, column=0, padx=10, pady=5)

        self.collapsible_content = ctk.CTkFrame(self.collapsible_frame, fg_color='#1a1a1a', corner_radius=10)
        self.collapsible_content.grid(row=1, column=0, columnspan=4, sticky='ew')

        self.request_sender_label = ctk.CTkLabel(self.collapsible_content, text="Request Sender", fg_color='#1a1a1a', text_color='#ffffff')
        self.request_sender_label.grid(row=0, column=0, padx=10, pady=5)

        self.ip_lookup_label = ctk.CTkLabel(self.collapsible_content, text="IP Lookup", fg_color='#1a1a1a', text_color='#ffffff')
        self.ip_lookup_label.grid(row=1, column=0, padx=10, pady=5)


        self.collapsible_content.grid_forget()

        self.fetch_processes()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def toggle_section(self):
        if self.collapsible_content.winfo_ismapped():
            self.collapsible_content.grid_forget()
            self.toggle_button.configure(text=">")
        else:
            self.collapsible_content.grid(row=1, column=0, columnspan=4, sticky='ew')
            self.toggle_button.configure(text="^")

    def fetch_processes(self):
        self.process_listbox.delete(0, tk.END)
        self.processes = []
        for proc in psutil.process_iter(['pid', 'name']):
            self.process_listbox.insert(tk.END, f"{proc.info['pid']} - {proc.info['name']}")
            self.processes.append(proc.info['pid'])

    def filter_processes(self):
        search_term = self.search_entry.get().lower()
        self.process_listbox.delete(0, tk.END)
        self.processes = []
        for proc in psutil.process_iter(['pid', 'name']):
            if search_term in proc.info['name'].lower():
                self.process_listbox.insert(tk.END, f"{proc.info['pid']} - {proc.info['name']}")
                self.processes.append(proc.info['pid'])
        if not self.process_listbox.size():
            self.process_listbox.insert(tk.END, "No matching processes found")

    def on_process_select(self, event):
        selected_idx = self.process_listbox.curselection()
        if selected_idx:
            process_info = self.process_listbox.get(selected_idx[0])
            self.selected_process = int(process_info.split(' - ')[0])

    def on_protocol_select(self, value):
        self.selected_protocol = value

    def start_logging(self):
        if not self.selected_process:
            return
        
        self.logging = True
        self.captured_packets = []
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.stop_event.clear()
        threading.Thread(target=self.sniff_packets).start()

    def stop_logging(self):
        self.logging = False
        self.stop_event.set()

    def save_log(self):
        log_data = self.log_text.get(1.0, tk.END).strip()
        if not log_data:
            return
        
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                               filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(log_data)

    def sniff_packets(self):
        protocols = {
            "TCP": "tcp",
            "UDP": "udp",
            "HTTP": "tcp port 80",
            "HTTPS": "tcp port 443",
            "FTP": "tcp port 21",
            "SMTP": "tcp port 25",
            "DNS": "udp port 53",
            "ICMP": "icmp",
            "ARP": "arp",
        }

        filter_expr = protocols.get(self.selected_protocol, "")

        while not self.stop_event.is_set():
            sniff(prn=self.process_packet, filter=filter_expr, timeout=1)

    def process_packet(self, packet):
        if not self.logging:
            return
        
        if IP in packet:
            src_ip = packet[IP].src
            dest_ip = packet[IP].dst
            protocol = self.get_protocol(packet)
            headers = self.get_headers(packet)
            body = self.get_body(packet)

            log_entry = f"Protocol: {protocol}, Source: {src_ip}, Destination: {dest_ip}, Headers: {headers}, Body: {body}\n"
            self.log_text.insert(tk.END, log_entry)
            self.log_text.see(tk.END)

    def get_protocol(self, packet):
        if TCP in packet:
            return "TCP"
        elif UDP in packet:
            return "UDP"
        elif DNS in packet:
            return "DNS"
        elif ARP in packet:
            return "ARP"
        elif ICMP in packet:
            return "ICMP"
        else:
            return "Unknown"

    def get_headers(self, packet):
        if TCP in packet:
            return str(packet[TCP].fields)
        elif UDP in packet:
            return str(packet[UDP].fields)
        elif DNS in packet:
            return str(packet[DNS].fields)
        elif ARP in packet:
            return str(packet[ARP].fields)
        elif ICMP in packet:
            return str(packet[ICMP].fields)
        else:
            return "(unknown)"

    def get_body(self, packet):
        if Raw in packet:
            return binascii.hexlify(packet[Raw].load).decode()
        return "(no body)"

    def on_closing(self):
        self.stop_logging()
        self.root.destroy()

if __name__ == "__main__":
    root = ctk.CTk()
    app = NetworkLoggerApp(root)
    root.mainloop()
# made by https://github.com/DABOSS2016YT