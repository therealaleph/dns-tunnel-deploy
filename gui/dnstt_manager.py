import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import paramiko
import threading
import random
import string
import json
import base64
import re
import time


class DNSTTManager:
    def __init__(self, root):
        self.root = root
        self.root.title("DNSTT Server Manager")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        self.ssh_client = None
        self.nologin_user = None
        self.nologin_pass = None
        self.pubkey = None
        self.ns_domain = None
        self.server_ip = None
        
        self.setup_ui()
        
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        conn_frame = ttk.LabelFrame(main_frame, text="SSH Connection", padding="10")
        conn_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(conn_frame, text="Server IP:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.ip_entry = ttk.Entry(conn_frame, width=30)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(conn_frame, text="Username:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.user_entry = ttk.Entry(conn_frame, width=20)
        self.user_entry.grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Label(conn_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.pass_entry = ttk.Entry(conn_frame, width=30, show="*")
        self.pass_entry.grid(row=1, column=1, padx=5, pady=5)
        
        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self.connect_ssh)
        self.connect_btn.grid(row=1, column=2, columnspan=2, padx=5, pady=5)
        
        config_frame = ttk.LabelFrame(main_frame, text="DNSTT Configuration", padding="10")
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(config_frame, text="NS Domain (e.g., t.example.com):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.ns_entry = ttk.Entry(config_frame, width=40)
        self.ns_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(config_frame, text="Profile Name:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.profile_entry = ttk.Entry(config_frame, width=40)
        self.profile_entry.grid(row=1, column=1, padx=5, pady=5)
        self.profile_entry.insert(0, "flare")
        
        self.deploy_btn = ttk.Button(config_frame, text="Deploy DNSTT", command=self.start_deployment, state=tk.DISABLED)
        self.deploy_btn.grid(row=2, column=0, columnspan=2, pady=10)
        
        log_frame = ttk.LabelFrame(main_frame, text="Logs", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15, font=("Consolas", 10))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.tag_config("info", foreground="blue")
        self.log_text.tag_config("success", foreground="green")
        self.log_text.tag_config("error", foreground="red")
        self.log_text.tag_config("warning", foreground="orange")
        
        result_frame = ttk.LabelFrame(main_frame, text="Result", padding="10")
        result_frame.pack(fill=tk.X)
        
        ttk.Label(result_frame, text="DNS URI:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.uri_entry = ttk.Entry(result_frame, width=80)
        self.uri_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        self.copy_btn = ttk.Button(result_frame, text="Copy URI", command=self.copy_uri, state=tk.DISABLED)
        self.copy_btn.grid(row=0, column=2, padx=5, pady=5)
        
        result_frame.columnconfigure(1, weight=1)
        
        details_frame = ttk.Frame(result_frame)
        details_frame.grid(row=1, column=0, columnspan=3, sticky=tk.EW, pady=5)
        
        ttk.Label(details_frame, text="NoLogin User:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.nologin_user_label = ttk.Label(details_frame, text="-")
        self.nologin_user_label.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(details_frame, text="NoLogin Pass:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.nologin_pass_label = ttk.Label(details_frame, text="-")
        self.nologin_pass_label.grid(row=0, column=3, sticky=tk.W, padx=5)
        
        ttk.Label(details_frame, text="Public Key:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.pubkey_label = ttk.Label(details_frame, text="-", wraplength=600)
        self.pubkey_label.grid(row=1, column=1, columnspan=3, sticky=tk.W, padx=5)
        
    def log(self, message, level="info"):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] ", level)
        self.log_text.insert(tk.END, f"{message}\n", level)
        self.log_text.see(tk.END)
        self.root.update_idletasks()
        
    def connect_ssh(self):
        ip = self.ip_entry.get().strip()
        user = self.user_entry.get().strip()
        password = self.pass_entry.get().strip()
        
        if not all([ip, user, password]):
            messagebox.showerror("Error", "Please fill all SSH connection fields")
            return
            
        self.server_ip = ip
        self.connect_btn.config(state=tk.DISABLED)
        threading.Thread(target=self._connect_ssh_thread, args=(ip, user, password), daemon=True).start()
        
    def _connect_ssh_thread(self, ip, user, password):
        try:
            self.log(f"Connecting to {ip} as {user}...", "info")
            
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(ip, username=user, password=password, timeout=30)
            
            self.log(f"Successfully connected to {ip}", "success")
            self.root.after(0, lambda: self.deploy_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.connect_btn.config(text="Connected", state=tk.DISABLED))
            
        except Exception as e:
            self.log(f"SSH connection failed: {str(e)}", "error")
            self.root.after(0, lambda: self.connect_btn.config(state=tk.NORMAL))
            
    def generate_random_string(self, length=8):
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
        
    def generate_random_password(self, length=15):
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
        
    def exec_command(self, command, timeout=60):
        self.log(f"Executing: {command}", "info")
        stdin, stdout, stderr = self.ssh_client.exec_command(command, timeout=timeout)
        output = stdout.read().decode('utf-8', errors='ignore')
        error = stderr.read().decode('utf-8', errors='ignore')
        exit_code = stdout.channel.recv_exit_status()
        
        if output:
            for line in output.strip().split('\n'):
                if line.strip():
                    self.log(f"  {line}", "info")
                    
        if error:
            for line in error.strip().split('\n'):
                if line.strip():
                    self.log(f"  {line}", "warning")
                    
        return output, error, exit_code
        
    def start_deployment(self):
        ns_domain = self.ns_entry.get().strip()
        
        if not ns_domain:
            messagebox.showerror("Error", "Please enter the NS domain")
            return
            
        self.ns_domain = ns_domain
        self.deploy_btn.config(state=tk.DISABLED)
        threading.Thread(target=self._deploy_thread, daemon=True).start()
        
    def _deploy_thread(self):
        try:
            self.log("=" * 60, "info")
            self.log("Starting DNSTT deployment...", "info")
            self.log("=" * 60, "info")
            
            self.log("Step 1: Creating no-login user with random credentials...", "info")
            self.nologin_user = "dns" + self.generate_random_string(6)
            self.nologin_pass = self.generate_random_password(15)
            
            self.log(f"Generated username: {self.nologin_user}", "success")
            self.log(f"Generated password: {self.nologin_pass}", "success")
            
            check_cmd = f"id {self.nologin_user} 2>/dev/null && echo EXISTS || echo NOTEXISTS"
            output, _, _ = self.exec_command(check_cmd)
            
            if "EXISTS" in output:
                self.log(f"User {self.nologin_user} already exists, deleting...", "warning")
                self.exec_command(f"userdel {self.nologin_user}")
                
            create_user_cmd = f"useradd -m -s /usr/sbin/nologin {self.nologin_user}"
            output, error, exit_code = self.exec_command(create_user_cmd)
            
            if exit_code != 0:
                create_user_cmd = f"useradd -m -s /bin/false {self.nologin_user}"
                output, error, exit_code = self.exec_command(create_user_cmd)
                
            if exit_code != 0:
                raise Exception(f"Failed to create user: {error}")
                
            self.log(f"User {self.nologin_user} created successfully", "success")
            
            set_pass_cmd = f"echo '{self.nologin_user}:{self.nologin_pass}' | chpasswd"
            output, error, exit_code = self.exec_command(set_pass_cmd)
            
            if exit_code != 0:
                raise Exception(f"Failed to set password: {error}")
                
            self.log(f"Password set for user {self.nologin_user}", "success")
            
            self.root.after(0, lambda: self.nologin_user_label.config(text=self.nologin_user))
            self.root.after(0, lambda: self.nologin_pass_label.config(text=self.nologin_pass))
            
            self.log("Step 2: Downloading and running dnstt-deploy script...", "info")
            
            download_cmd = "curl -Ls https://raw.githubusercontent.com/net2share/dnstt-deploy/main/dnstt-deploy.sh -o /tmp/dnstt-deploy.sh && chmod +x /tmp/dnstt-deploy.sh"
            output, error, exit_code = self.exec_command(download_cmd)
            
            if exit_code != 0:
                raise Exception(f"Failed to download script: {error}")
                
            self.log("Script downloaded successfully", "success")
            
            self.log(f"Step 3: Running dnstt-deploy with NS domain: {self.ns_domain}", "info")
            
            deploy_cmd = f"echo -e '{self.ns_domain}\\n\\n2\\n' | bash /tmp/dnstt-deploy.sh 2>&1"
            
            self.log("Executing deployment script (this may take a minute)...", "info")
            
            channel = self.ssh_client.get_transport().open_session()
            channel.exec_command(deploy_cmd)
            channel.settimeout(180)
            
            full_output = ""
            while True:
                if channel.recv_ready():
                    chunk = channel.recv(4096).decode('utf-8', errors='ignore')
                    full_output += chunk
                    for line in chunk.split('\n'):
                        if line.strip():
                            self.log(f"  {line}", "info")
                if channel.exit_status_ready():
                    while channel.recv_ready():
                        chunk = channel.recv(4096).decode('utf-8', errors='ignore')
                        full_output += chunk
                    break
                time.sleep(0.1)
                
            exit_code = channel.recv_exit_status()
            
            if "SETUP COMPLETED SUCCESSFULLY" not in full_output and exit_code != 0:
                self.log("Deployment may have encountered issues, checking status...", "warning")
                
            self.log("Step 4: Extracting public key...", "info")
            
            pubkey_match = re.search(r'Public Key Content:\s*\n\s*([a-f0-9]{64})', full_output)
            
            if not pubkey_match:
                pubkey_match = re.search(r'pubkey\s+written to\s+.*\n([a-f0-9]{64})', full_output)
                
            if not pubkey_match:
                pubkey_match = re.search(r'([a-f0-9]{64})', full_output)
                
            if pubkey_match:
                self.pubkey = pubkey_match.group(1)
                self.log(f"Public key extracted: {self.pubkey}", "success")
            else:
                self.log("Could not extract pubkey from output, trying to read from file...", "warning")
                ns_file = self.ns_domain.replace('.', '_')
                read_pubkey_cmd = f"cat /etc/dnstt/{ns_file}_server.pub 2>/dev/null || cat /etc/dnstt/*.pub 2>/dev/null | head -1"
                output, _, _ = self.exec_command(read_pubkey_cmd)
                pubkey_match = re.search(r'([a-f0-9]{64})', output)
                if pubkey_match:
                    self.pubkey = pubkey_match.group(1)
                    self.log(f"Public key read from file: {self.pubkey}", "success")
                else:
                    raise Exception("Could not extract public key")
                    
            self.root.after(0, lambda: self.pubkey_label.config(text=self.pubkey))
            
            self.log("Step 5: Verifying dnstt-server service...", "info")
            status_cmd = "systemctl status dnstt-server --no-pager"
            output, _, _ = self.exec_command(status_cmd)
            
            if "active (running)" in output:
                self.log("dnstt-server is running!", "success")
            else:
                self.log("dnstt-server may not be running, checking...", "warning")
                self.exec_command("systemctl start dnstt-server")
                
            self.log("Step 6: Generating DNS URI...", "info")
            self.generate_dns_uri()
            
            self.log("=" * 60, "success")
            self.log("DEPLOYMENT COMPLETED SUCCESSFULLY!", "success")
            self.log("=" * 60, "success")
            
        except Exception as e:
            self.log(f"Deployment failed: {str(e)}", "error")
            import traceback
            self.log(traceback.format_exc(), "error")
            self.root.after(0, lambda: self.deploy_btn.config(state=tk.NORMAL))
            
    def generate_dns_uri(self):
        profile_name = self.profile_entry.get().strip() or "flare"
        
        config = {
            "ps": profile_name,
            "addr": "8.8.4.4:53",
            "ns": self.ns_domain,
            "pubkey": self.pubkey,
            "user": self.nologin_user,
            "pass": self.nologin_pass
        }
        
        self.log(f"Config JSON: {json.dumps(config, indent=2)}", "info")
        
        json_str = json.dumps(config, separators=(',', ':'))
        base64_str = base64.b64encode(json_str.encode()).decode()
        dns_uri = f"dns://{base64_str}"
        
        self.log(f"Generated DNS URI: {dns_uri}", "success")
        
        self.root.after(0, lambda: self._update_uri(dns_uri))
        
    def _update_uri(self, uri):
        self.uri_entry.delete(0, tk.END)
        self.uri_entry.insert(0, uri)
        self.copy_btn.config(state=tk.NORMAL)
        
    def copy_uri(self):
        uri = self.uri_entry.get()
        if uri:
            self.root.clipboard_clear()
            self.root.clipboard_append(uri)
            self.log("DNS URI copied to clipboard!", "success")
            messagebox.showinfo("Copied", "DNS URI copied to clipboard!")


def main():
    root = tk.Tk()
    app = DNSTTManager(root)
    root.mainloop()


if __name__ == "__main__":
    main()
