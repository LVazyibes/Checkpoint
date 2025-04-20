import os
import paramiko
from paramiko import SSHClient, SFTPClient
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from threading import Thread, Event
from queue import Queue
import time
from datetime import datetime

class CheckpointLogExporter:
    def __init__(self, root):
        self.root = root
        self.root.title("Checkpoint Log Exporter v1.0 alfa")
        self.root.geometry("1400x800")
        
        # SSH ve SFTP bilgileri
        self.ssh_host = tk.StringVar()
        self.ssh_port = tk.StringVar(value="22")
        self.ssh_username = tk.StringVar()
        self.ssh_password = tk.StringVar()
        self.remote_log_path = tk.StringVar(value="/var/log/opt/CPsuite-R81.10/fw1/log")
        self.local_save_path = tk.StringVar()
        
        # Thread kontrolü
        self.disk_monitor_thread = None
        self.disk_monitor_event = Event()
        
        # UI elemanları
        self.create_widgets()
        
        # Thread ve queue için
        self.queue = Queue()
        self.process_thread = None
        self.stop_flag = False
        
        # Progress bar değerleri
        self.export_progress = 0
        self.transfer_progress = 0
        
        # Seçili dosyalar
        self.selected_files = []
        
        # UI güncellemelerini kontrol et
        self.root.after(100, self.process_queue)
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Connection frame
        conn_frame = ttk.Frame(main_frame)
        conn_frame.pack(fill=tk.X, pady=5)
        
        # SSH Connection Settings
        ssh_frame = ttk.LabelFrame(conn_frame, text="SSH Connection Settings", padding="10")
        ssh_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        ttk.Label(ssh_frame, text="Host:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(ssh_frame, textvariable=self.ssh_host, width=25).grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(ssh_frame, text="Port:").grid(row=0, column=2, sticky=tk.W)
        ttk.Entry(ssh_frame, textvariable=self.ssh_port, width=5).grid(row=0, column=3, sticky=tk.W)
        
        ttk.Label(ssh_frame, text="Username:").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(ssh_frame, textvariable=self.ssh_username, width=25).grid(row=1, column=1, sticky=tk.W)
        
        ttk.Label(ssh_frame, text="Password:").grid(row=1, column=2, sticky=tk.W)
        ttk.Entry(ssh_frame, textvariable=self.ssh_password, show="*", width=15).grid(row=1, column=3, sticky=tk.W)
        
        ttk.Label(ssh_frame, text="Remote Log Path:").grid(row=2, column=0, sticky=tk.W)
        ttk.Entry(ssh_frame, textvariable=self.remote_log_path, width=40).grid(row=2, column=1, columnspan=3, sticky=tk.W)
        
        # Disk Usage Monitor
        disk_frame = ttk.LabelFrame(conn_frame, text="Real-time Disk Usage", padding="10")
        disk_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=5)
        
        self.disk_usage = scrolledtext.ScrolledText(
            disk_frame, 
            height=12, 
            width=80,
            state='disabled',
            font=('Courier', 9)
        )
        self.disk_usage.pack(fill=tk.BOTH, expand=True)
        
        # Local save path
        local_frame = ttk.Frame(main_frame)
        local_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(local_frame, text="Local Save Path:").pack(side=tk.LEFT)
        ttk.Entry(local_frame, textvariable=self.local_save_path, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(local_frame, text="Browse", command=self.browse_local_path).pack(side=tk.LEFT)
        
        # Buttons frame
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="Connect & List Logs", command=self.connect_and_list_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Start Disk Monitor", command=self.start_disk_monitor).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Stop Disk Monitor", command=self.stop_disk_monitor).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Start Export", command=self.start_export_process).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Stop", command=self.stop_process).pack(side=tk.LEFT, padx=5)
        # About button
        ttk.Button(
            btn_frame, 
            text="About", 
            command=lambda: messagebox.showinfo(
                "About Checkpoint Log Exporter",
                "Checkpoint Log Exporter v1.0 alfa\n\n"
                "Developed by: betterdisc@hotmail.com\n"
                "GitHub: 404Effort\n\n"
                "A tool to export and transfer Checkpoint firewall logs with ease!"
            )
        ).pack(side=tk.LEFT, padx=5)
        
        # Progress bars
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(progress_frame, text="Export Progress:").pack(anchor=tk.W)
        self.export_pb = ttk.Progressbar(progress_frame, length=400, mode='determinate')
        self.export_pb.pack(fill=tk.X, pady=5)
        
        ttk.Label(progress_frame, text="Transfer Progress:").pack(anchor=tk.W)
        self.transfer_pb = ttk.Progressbar(progress_frame, length=400, mode='determinate')
        self.transfer_pb.pack(fill=tk.X, pady=5)
        
        # Log files list
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Available logs
        avail_frame = ttk.LabelFrame(list_frame, text="Available Log Files", padding="5")
        avail_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # Treeview for available logs with size column
        self.avail_logs_tree = ttk.Treeview(avail_frame, columns=('size', 'modified'), selectmode='extended')
        self.avail_logs_tree.heading('#0', text='File Name')
        self.avail_logs_tree.heading('size', text='Size (GB)')
        self.avail_logs_tree.heading('modified', text='Modified')
        self.avail_logs_tree.column('#0', width=300)
        self.avail_logs_tree.column('size', width=100, anchor='e')
        self.avail_logs_tree.column('modified', width=150)
        
        vsb = ttk.Scrollbar(avail_frame, orient="vertical", command=self.avail_logs_tree.yview)
        hsb = ttk.Scrollbar(avail_frame, orient="horizontal", command=self.avail_logs_tree.xview)
        self.avail_logs_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.avail_logs_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        avail_frame.grid_rowconfigure(0, weight=1)
        avail_frame.grid_columnconfigure(0, weight=1)
        
        # Selected logs
        selected_frame = ttk.LabelFrame(list_frame, text="Selected Log Files", padding="5")
        selected_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # Treeview for selected logs with size column
        self.selected_logs_tree = ttk.Treeview(selected_frame, columns=('size', 'modified'), selectmode='extended')
        self.selected_logs_tree.heading('#0', text='File Name')
        self.selected_logs_tree.heading('size', text='Size (GB)')
        self.selected_logs_tree.heading('modified', text='Modified')
        self.selected_logs_tree.column('#0', width=300)
        self.selected_logs_tree.column('size', width=100, anchor='e')
        self.selected_logs_tree.column('modified', width=150)
        
        vsb2 = ttk.Scrollbar(selected_frame, orient="vertical", command=self.selected_logs_tree.yview)
        hsb2 = ttk.Scrollbar(selected_frame, orient="horizontal", command=self.selected_logs_tree.xview)
        self.selected_logs_tree.configure(yscrollcommand=vsb2.set, xscrollcommand=hsb2.set)
        
        self.selected_logs_tree.grid(row=0, column=0, sticky='nsew')
        vsb2.grid(row=0, column=1, sticky='ns')
        hsb2.grid(row=1, column=0, sticky='ew')
        
        selected_frame.grid_rowconfigure(0, weight=1)
        selected_frame.grid_columnconfigure(0, weight=1)
        
        # Add/Remove buttons
        btn_frame2 = ttk.Frame(list_frame)
        btn_frame2.pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        ttk.Button(btn_frame2, text="Add >>", command=self.add_selected_files).pack(pady=10)
        ttk.Button(btn_frame2, text="<< Remove", command=self.remove_selected_files).pack(pady=10)
        
        # Log console
        console_frame = ttk.LabelFrame(main_frame, text="Console Output", padding="5")
        console_frame.pack(fill=tk.BOTH, expand=True)
        
        self.console = scrolledtext.ScrolledText(console_frame, height=10, state='disabled')
        self.console.pack(fill=tk.BOTH, expand=True)
    
    def browse_local_path(self):
        folder = filedialog.askdirectory()
        if folder:
            self.local_save_path.set(folder)
    
    def start_disk_monitor(self):
        if not self.ssh_host.get() or not self.ssh_username.get() or not self.ssh_password.get():
            messagebox.showerror("Error", "Please fill all SSH connection fields")
            return
        
        if self.disk_monitor_thread and self.disk_monitor_thread.is_alive():
            self.stop_disk_monitor()
            time.sleep(1)
        
        self.disk_monitor_event.clear()
        self.disk_monitor_thread = Thread(target=self._disk_monitor_thread, daemon=True)
        self.disk_monitor_thread.start()
        self.log_message("Disk monitoring started...")
    
    def stop_disk_monitor(self):
        if self.disk_monitor_thread and self.disk_monitor_thread.is_alive():
            self.disk_monitor_event.set()
            self.disk_monitor_thread.join(timeout=2)
            self.log_message("Disk monitoring stopped")
    
    def _disk_monitor_thread(self):
        try:
            ssh = SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=self.ssh_host.get(),
                port=int(self.ssh_port.get()),
                username=self.ssh_username.get(),
                password=self.ssh_password.get(),
                timeout=10
            )
            
            while not self.disk_monitor_event.is_set():
                stdin, stdout, stderr = ssh.exec_command("df -h")
                disk_info = stdout.read().decode()
                
                # Clear and update disk usage display
                self.queue.put(lambda: self._update_disk_usage(disk_info))
                
                # Wait before next update
                self.disk_monitor_event.wait(5)
            
            ssh.close()
            
        except Exception as e:
            self.log_message(f"Disk monitor error: {str(e)}")
            self.queue.put(lambda: self._update_disk_usage(f"Error: {str(e)}"))
    
    def _update_disk_usage(self, text):
        self.disk_usage.configure(state='normal')
        self.disk_usage.delete(1.0, tk.END)
        self.disk_usage.insert(tk.END, text)
        self.disk_usage.configure(state='disabled')
    
    def connect_and_list_logs(self):
        if not self.ssh_host.get() or not self.ssh_username.get() or not self.ssh_password.get():
            messagebox.showerror("Error", "Please fill all SSH connection fields")
            return
        
        Thread(target=self._connect_and_list_logs_thread, daemon=True).start()
    
    def _connect_and_list_logs_thread(self):
        self.log_message("Connecting to SSH server...")
        
        try:
            ssh = SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=self.ssh_host.get(),
                port=int(self.ssh_port.get()),
                username=self.ssh_username.get(),
                password=self.ssh_password.get(),
                timeout=30
            )
            
            self.log_message("Connected. Listing log files...")
            
            # Log dosyalarını ve boyutlarını listele
            stdin, stdout, stderr = ssh.exec_command(
                f'ls -lh {self.remote_log_path.get()}/*.log | awk \'{{print $9 "|" $5 "|" $6 " " $7 " " $8}}\''
            )
            
            files_info = []
            for line in stdout.read().decode().splitlines():
                if line.strip():
                    parts = line.split('|')
                    if len(parts) >= 3:
                        file_path = parts[0]
                        size = parts[1]
                        modified = parts[2] if len(parts) > 2 else ''
                        
                        file_name = os.path.basename(file_path)
                        
                        # Boyutu GB'ye çevir
                        size_gb = 0
                        try:
                            if 'G' in size:
                                size_gb = float(size.replace('G', ''))
                            elif 'M' in size:
                                size_gb = float(size.replace('M', '')) / 1024
                            elif 'K' in size:
                                size_gb = float(size.replace('K', '')) / (1024*1024)
                            else:  # bytes
                                size_gb = float(size) / (1024*1024*1024)
                        except ValueError:
                            size_gb = 0
                        
                        files_info.append({
                            'name': file_name,
                            'size': size_gb,
                            'size_str': size,
                            'modified': modified,
                            'full_path': file_path
                        })
            
            # UI'da listele
            self.queue.put(lambda: self.update_avail_logs_tree(files_info))
            self.log_message(f"Found {len(files_info)} log files.")
            
            ssh.close()
            
        except Exception as e:
            self.log_message(f"Error: {str(e)}")
            self.queue.put(lambda: messagebox.showerror("Error", str(e)))
    
    def update_avail_logs_tree(self, files_info):
        self.avail_logs_tree.delete(*self.avail_logs_tree.get_children())
        for file_info in sorted(files_info, key=lambda x: x['name']):
            self.avail_logs_tree.insert(
                '', 
                'end', 
                text=file_info['name'],
                values=(f"{file_info['size']:.3f}", file_info['modified']),
                tags=(file_info['full_path'],)
            )
    
    def add_selected_files(self):
        selected_items = self.avail_logs_tree.selection()
        for item in selected_items:
            file_name = self.avail_logs_tree.item(item, 'text')
            file_size = self.avail_logs_tree.item(item, 'values')[0]
            file_modified = self.avail_logs_tree.item(item, 'values')[1]
            file_full_path = self.avail_logs_tree.item(item, 'tags')[0]
            
            # Check if already selected
            already_exists = False
            for child in self.selected_logs_tree.get_children():
                if self.selected_logs_tree.item(child, 'text') == file_name:
                    already_exists = True
                    break
            
            if not already_exists:
                self.selected_logs_tree.insert(
                    '', 
                    'end', 
                    text=file_name,
                    values=(file_size, file_modified),
                    tags=(file_full_path,)
                )
                self.selected_files.append({
                    'name': file_name,
                    'full_path': file_full_path,
                    'size': file_size,
                    'modified': file_modified
                })
    
    def remove_selected_files(self):
        selected_items = self.selected_logs_tree.selection()
        for item in reversed(selected_items):
            file_name = self.selected_logs_tree.item(item, 'text')
            self.selected_logs_tree.delete(item)
            
            # Remove from selected_files list
            for i, f in enumerate(self.selected_files):
                if f['name'] == file_name:
                    self.selected_files.pop(i)
                    break
    
    def start_export_process(self):
        if not self.selected_files:
            messagebox.showwarning("Warning", "Please select at least one log file")
            return
        
        if not self.local_save_path.get():
            messagebox.showwarning("Warning", "Please select a local save path")
            return
        
        self.stop_flag = False
        self.process_thread = Thread(target=self._export_process_thread, daemon=True)
        self.process_thread.start()
    
    def _export_process_thread(self):
        total_files = len(self.selected_files)
        
        try:
            ssh = SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=self.ssh_host.get(),
                port=int(self.ssh_port.get()),
                username=self.ssh_username.get(),
                password=self.ssh_password.get(),
                timeout=60
            )
            
            sftp = ssh.open_sftp()
            
            for i, log_info in enumerate(self.selected_files):
                if self.stop_flag:
                    break
                
                log_file = log_info['name']
                remote_file = log_info['full_path']
                file_size_gb = float(log_info['size'])
                temp_file = f"/tmp/{log_file}.csv.gz"
                local_file = os.path.join(self.local_save_path.get(), f"{log_file}.csv.gz")
                
                # Export işlemi
                self.log_message(f"Exporting {log_file} ({i+1}/{total_files}, Size: {file_size_gb:.3f} GB)...")
                
                # Yeni export yöntemi - doğrudan pipe yerine geçici dosya kullanımı
                export_cmd = f"""
                tmp_file="{temp_file}.tmp"
                fwm logexport -i {remote_file} -p -n -d '\\\\' > "$tmp_file" && 
                gzip -c -f "$tmp_file" > "{temp_file}" && 
                rm -f "$tmp_file"
                """
                
                # Komutu çalıştır ve çıktıyı bekle
                stdin, stdout, stderr = ssh.exec_command(export_cmd, get_pty=True)
                
                # Çıktıyı oku ve beklemeyi zorla
                stdout.channel.recv_exit_status()
                
                # Export tamamlandı, dosya boyutunu kontrol et
                stdin, stdout, stderr = ssh.exec_command(f"ls -lh {temp_file} | awk '{{print $5}}'")
                exported_size = stdout.read().decode().strip()
                self.log_message(f"Export completed. Exported size: {exported_size}")
                
                # Progress bar'ı tamamla
                self.export_progress = 100
                self.queue.put(lambda: self.export_pb.configure(value=self.export_progress))
                
                if self.stop_flag:
                    break
                
                # SFTP ile transfer
                self.log_message(f"Transferring {temp_file} to local...")
                
                try:
                    with sftp.file(temp_file, 'rb') as remote_file_obj:
                        file_size = remote_file_obj.stat().st_size
                        transferred = 0
                        chunk_size = 32768  # 32KB chunk'lar halinde transfer
                        
                        with open(local_file, 'wb') as local_file_obj:
                            while True:
                                if self.stop_flag:
                                    break
                                
                                chunk = remote_file_obj.read(chunk_size)
                                if not chunk:
                                    break
                                
                                local_file_obj.write(chunk)
                                transferred += len(chunk)
                                progress = int((transferred / file_size) * 100)
                                self.transfer_progress = progress
                                self.queue.put(lambda: self.transfer_pb.configure(value=self.transfer_progress))
                    
                    if not self.stop_flag:
                        # Transfer tamamlandı, temp dosyayı sil
                        ssh.exec_command(f"rm -f {temp_file}")
                        self.log_message(f"Successfully transferred {log_file}")
                        
                        # Dosya bütünlüğünü kontrol et
                        local_size = os.path.getsize(local_file)
                        if local_size > 0:
                            self.log_message(f"Transfer verified. Local file size: {local_size/1024/1024:.2f} MB")
                        else:
                            self.log_message("Warning: Transferred file size is 0 bytes!")
                
                except Exception as e:
                    self.log_message(f"Transfer error for {log_file}: {str(e)}")
                    continue
            
            sftp.close()
            ssh.close()
            
            if not self.stop_flag:
                self.log_message("All operations completed successfully!")
                self.queue.put(lambda: messagebox.showinfo("Success", "All operations completed successfully!"))
            
        except Exception as e:
            self.log_message(f"Error: {str(e)}")
            self.queue.put(lambda: messagebox.showerror("Error", str(e)))
    
    def stop_process(self):
        self.stop_flag = True
        self.log_message("Process stopped by user")
    
    def log_message(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.queue.put(lambda: self._log_message(f"[{timestamp}] {message}"))
    
    def _log_message(self, message):
        self.console.configure(state='normal')
        self.console.insert(tk.END, f"{message}\n")
        self.console.configure(state='disabled')
        self.console.see(tk.END)
    
    def process_queue(self):
        while not self.queue.empty():
            try:
                task = self.queue.get_nowait()
                task()
            except:
                pass
        self.root.after(100, self.process_queue)

if __name__ == "__main__":
    root = tk.Tk()
    app = CheckpointLogExporter(root)
    root.mainloop()
