import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import email, imaplib, re, os, threading, json, csv
from email import policy
from email.parser import BytesParser

# ====================== Custom Data Structures ======================
class Stack:
    def __init__(self): self.items = []
    def push(self, item): self.items.append(item)
    def pop(self): return self.items.pop() if self.items else None
    def is_empty(self): return not self.items

class Queue:
    def __init__(self): self.items = []
    def enqueue(self, item): self.items.append(item)
    def dequeue(self): return self.items.pop(0) if self.items else None
    def is_empty(self): return not self.items

# ================== Analyzer Class ==================
class EmailHeaderAnalyzer:
    def __init__(self, raw_email_bytes):
        self.msg = BytesParser(policy=policy.default).parsebytes(raw_email_bytes)
        self.headers = dict(self.msg.items())
        self.body = self.get_body()
        self.reasons = []
        self.auth_results = None

    def get_body(self):
        try:
            if self.msg.is_multipart():
                for part in self.msg.walk():
                    if part.get_content_type() == 'text/plain':
                        try:
                            return part.get_payload(decode=True).decode(errors='ignore')
                        except (UnicodeDecodeError, AttributeError):
                            continue
            else:
                try:
                    return self.msg.get_payload(decode=True).decode(errors='ignore')
                except (UnicodeDecodeError, AttributeError):
                    return ""
        except Exception as e:
            print(f"[!] Error extracting body: {e}")
            return ""
        return ""

    def list_attachments(self):
        attachments = []
        if self.msg.is_multipart():
            for part in self.msg.walk():
                if part.get_content_disposition() == "attachment":
                    attachments.append(part.get_filename() or "Unnamed")
        return attachments

    def get_sender_ip(self):
        for header in reversed(self.msg.get_all("Received", [])):
            match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header)
            if match: return match.group()
        return "Not found"

    # ==== Detection Functions ====
    def is_spoofed(self):
        from_addr = self.headers.get("From", "")
        if "@" not in from_addr:
            self.reasons.append("From address missing '@'")
            return True
        if from_addr.split("@")[-1].lower().endswith("example.com"):
            self.reasons.append("Suspicious domain: example.com")
            return True
        return False

    def reply_to_mismatch(self):
        reply_to = self.headers.get("Reply-To", "")
        if reply_to and reply_to != self.headers.get("From", ""):
            self.reasons.append("Reply-To does not match From")
            return True
        return False

    def contains_suspicious_keywords(self):
        keywords = ["verify", "urgent", "reset", "click", "login", "account"]
        flagged = [kw for kw in keywords if kw in self.body.lower()]
        if flagged:
            self.reasons.append(f"Suspicious keywords: {', '.join(flagged)}")
            return True
        return False

    def contains_links(self):
        if re.search(r"https?://", self.body.lower()):
            self.reasons.append("Contains suspicious URL links")
            return True
        return False

    def low_trust_ip(self):
        trusted = ["google.com", "apple.com", "microsoft.com"]
        headers = "\n".join(self.msg.get_all("Received", []))
        if not any(d in headers.lower() for d in trusted):
            self.reasons.append("Sender IP/domain not trusted")
            return True
        return False

    def has_risky_attachments(self):
        risky_exts = ['.exe', '.scr', '.js', '.bat', '.vbs']
        for fname in self.list_attachments():
            if any(fname.lower().endswith(ext) for ext in risky_exts):
                self.reasons.append(f"Risky attachment detected: {fname}")
                return True
        return False

    def spf_dkim_dmarc_summary(self):
        if self.auth_results:
            return self.auth_results
        auth = {"SPF": "not found", "DKIM": "not found", "DMARC": "not found"}
        # Check multiple headers
        headers_to_check = [
            self.headers.get("Authentication-Results", ""),
            self.headers.get("Received-SPF", ""),
            self.headers.get("DKIM-Signature", ""),
            self.headers.get("DMARC-Filter", "")
        ]
        combined = " ".join(headers_to_check)
        for proto in auth:
            match = re.search(fr"{proto.lower()}=(pass|fail|neutral|softfail|none|permerror|temperror)", combined, re.I)
            if match:
                auth[proto] = match.group(1).lower()
                if auth[proto] != "pass":
                    self.reasons.append(f"{proto}={auth[proto]}")
        self.auth_results = auth
        return auth


    # ==== Scoring & Summary ====
    def verdict(self):
        self.reasons.clear()
        auth = self.spf_dkim_dmarc_summary()

        # Weighted scoring
        risk_score_map = {
            "spoofed": 3,
            "reply_mismatch": 2,
            "suspicious_keywords": 1,
            "links": 1,
            "low_trust_ip": 2,
            "risky_attachments": 3
        }

        score = 0
        if self.is_spoofed(): score += risk_score_map["spoofed"]
        if self.reply_to_mismatch(): score += risk_score_map["reply_mismatch"]
        if self.contains_suspicious_keywords(): score += risk_score_map["suspicious_keywords"]
        if self.contains_links(): score += risk_score_map["links"]
        if self.low_trust_ip(): score += risk_score_map["low_trust_ip"]
        if self.has_risky_attachments(): score += risk_score_map["risky_attachments"]
        score += sum(1 for k in auth if auth[k] != "pass")

        if score <= 2: return "Clean"
        elif score <= 4: return "Low Risk"
        elif score <= 7: return "Medium Risk"
        else: return "High Risk"


    def summary(self):
        verdict = self.verdict()
        auth = self.spf_dkim_dmarc_summary()
        return {
            "Subject": self.headers.get("Subject", "N/A"),
            "From": self.headers.get("From", "N/A"),
            "To": self.headers.get("To", "N/A"),
            "Date": self.headers.get("Date", "N/A"),
            "Sender IP": self.get_sender_ip(),
            "Attachments": ", ".join(self.list_attachments()) or "None",
            "SPF": auth["SPF"],
            "DKIM": auth["DKIM"],
            "DMARC": auth["DMARC"],
            "Risk Verdict": verdict,
            "Reasons": "; ".join(set(self.reasons))
        }

# ================== GUI Class ==================
class EmailForensicsGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Enhanced Email Forensics Analyzer")
        self.root.geometry("900x680")
        self.reports_stack = Stack()
        self.risk_queue = Queue()
        self.gmail_results = []  # store Gmail scan results for CSV export

        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook.Tab', padding=[15, 5], font=('Segoe UI', 11, 'bold'))

        self.tab_control = ttk.Notebook(root)
        self.manual_tab, self.gmail_tab = ttk.Frame(self.tab_control), ttk.Frame(self.tab_control)
        self.tab_control.add(self.manual_tab, text='Upload .eml')
        self.tab_control.add(self.gmail_tab, text='Scan Gmail')
        self.tab_control.pack(expand=1, fill="both")

        self.build_manual_tab()
        self.build_gmail_tab()

    def safe_insert(self, widget, text):
        self.root.after(0, lambda: widget.insert(tk.END, text))

    # Manual Tab
    def build_manual_tab(self):
        ttk.Label(self.manual_tab, text="Select a .eml file to analyze").pack(pady=10)
        ttk.Button(self.manual_tab, text="Browse .eml File", command=self.load_eml_file).pack(pady=5)
        ttk.Button(self.manual_tab, text="Undo Last Analysis", command=self.undo_last).pack(pady=5)
        ttk.Button(self.manual_tab, text="Export JSON", command=self.export_json).pack(pady=5)

        self.manual_result = scrolledtext.ScrolledText(self.manual_tab, wrap=tk.WORD, height=22, bg="#1e1e1e", fg="#d4d4d4", font=("Consolas", 10))
        for tag, color in [("high","red"),("medium","orange"),("low","yellow"),("clean","green")]:
            self.manual_result.tag_config(tag, foreground=color)
        self.manual_result.pack(padx=10, pady=10, fill='both', expand=True)

    # Gmail Tab
    def build_gmail_tab(self):
        ttk.Label(self.gmail_tab, text="Gmail Address:").pack(pady=3)
        self.email_entry = ttk.Entry(self.gmail_tab, width=40); self.email_entry.pack()
        ttk.Label(self.gmail_tab, text="App Password:").pack(pady=3)
        self.pass_entry = ttk.Entry(self.gmail_tab, show="*", width=40); self.pass_entry.pack()
        ttk.Label(self.gmail_tab, text="Number of emails to scan:").pack(pady=3)
        self.limit_spin = ttk.Spinbox(self.gmail_tab, from_=1, to=50, width=5)
        self.limit_spin.set(10)
        self.limit_spin.pack(pady=2)
        ttk.Button(self.gmail_tab, text="Scan Gmail Inbox", command=self.start_gmail_thread).pack(pady=10)
        ttk.Button(self.gmail_tab, text="Export CSV", command=self.export_csv).pack(pady=5)

        self.gmail_result = scrolledtext.ScrolledText(self.gmail_tab, wrap=tk.WORD, height=22, bg="#1e1e1e", fg="#d4d4d4", font=("Consolas", 10))
        self.gmail_result.pack(padx=10, pady=10, fill='both', expand=True)

    # Manual Functions
    def load_eml_file(self):
        path = filedialog.askopenfilename(filetypes=[("EML Files","*.eml")])
        if not path: return
        try:
            with open(path,'rb') as f:
                analyzer = EmailHeaderAnalyzer(f.read())
            report = analyzer.summary()
            self.reports_stack.push(report)
            self.display_report(report, self.manual_result)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze file: {e}")

    def undo_last(self):
        if not self.reports_stack.is_empty():
            self.reports_stack.pop()
            if not self.reports_stack.is_empty():
                self.display_report(self.reports_stack.items[-1], self.manual_result)
            else:
                self.manual_result.delete(1.0, tk.END)
                self.manual_result.insert(tk.END, "No previous analysis to show.")

    def export_json(self):
        if not self.reports_stack.is_empty():
            with open("email_analysis.json","w") as f:
                json.dump(self.reports_stack.items[-1], f, indent=4)
            messagebox.showinfo("Export","Analysis saved to email_analysis.json")

    def export_csv(self):
        if not self.gmail_results:
            messagebox.showinfo("Export", "No Gmail scan results to export.")
            return
        with open("gmail_scan_results.csv", "w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.gmail_results[0].keys())
            writer.writeheader()
            writer.writerows(self.gmail_results)
        messagebox.showinfo("Export", "Results saved to gmail_scan_results.csv")

    def display_report(self, report, widget):
        widget.delete(1.0, tk.END)
        widget.insert(tk.END, "Email Analysis Report\n" + "-" * 60 + "\n")
        for k, v in report.items():
            if k == "Reasons":
                # Apply color per reason (high=red, medium=orange, etc.)
                for reason in v.split("; "):
                    tag = "high" if "Risky" in reason or "spoofed" in reason.lower() else "medium" if "mismatch" in reason else "low"
                    widget.insert(tk.END, f"{k}: {reason}\n", tag)
            else:
                widget.insert(tk.END, f"{k}: {v}\n")

        widget.insert(tk.END, "\nApplied Filters: SPF/DKIM/DMARC, IP Trust, Keywords, Links, Attachments\n")
        tag = report["Risk Verdict"].split()[0].lower()
        widget.insert(tk.END, f"Final Risk Verdict: {report['Risk Verdict']}\n", tag)


    # Gmail Functions
    def start_gmail_thread(self): threading.Thread(target=self.scan_gmail).start()

    def scan_gmail(self):
        user, pwd = self.email_entry.get().strip(), self.pass_entry.get().strip()
        limit = int(self.limit_spin.get())
        self.safe_insert(self.gmail_result, "[*] Connecting to Gmail...\n")
        try:
            imap = imaplib.IMAP4_SSL("imap.gmail.com")
            imap.login(user, pwd)
        except imaplib.IMAP4.error as e:
            self.safe_insert(self.gmail_result, f"[!] Authentication Failed: {e}\n")
            return

        try:
            imap.select("inbox")
            _, msgs = imap.search(None, "ALL")
            for eid in msgs[0].split()[-limit:]:
                try:
                    _, data = imap.fetch(eid, "(RFC822)")
                    analyzer = EmailHeaderAnalyzer(data[0][1])
                    self.risk_queue.enqueue(analyzer.summary())
                except Exception as e:
                    self.safe_insert(self.gmail_result, f"[!] Error analyzing email ID {eid}: {e}\n")
            imap.logout()
            self.safe_insert(self.gmail_result, "[✓] Scan Completed.\n\n")
            self.root.after(0, self.show_grouped_results)
        except Exception as e:
            self.safe_insert(self.gmail_result, f"[!] Gmail Scan Error: {e}\n")


    def show_grouped_results(self):
        grouped = {"High Risk": [], "Medium Risk": [], "Low Risk": []}
        temp_storage = []  # copy for CSV export

        while not self.risk_queue.is_empty():
            report = self.risk_queue.dequeue()
            temp_storage.append(report)
            grouped.get(report["Risk Verdict"], []).append(report)

        # store results for later CSV export
        self.gmail_results = temp_storage.copy()

        choice = messagebox.askquestion("Display Mode","Show all risky emails? Yes=All, No=One per category")
        for level in ["High Risk","Medium Risk","Low Risk"]:
            if grouped[level]:
                emails = grouped[level] if choice=="yes" else [grouped[level][0]]
                for idx, rep in enumerate(emails,1):
                    self.gmail_result.insert(tk.END,f"{level} Email #{idx}\n{'-'*30}\n")
                    for k,v in rep.items(): self.gmail_result.insert(tk.END,f"{k}: {v}\n")
                    self.gmail_result.insert(tk.END,"\n")

# ---- Main ----
if __name__ == '__main__':
    root = tk.Tk()
    EmailForensicsGUI(root)
    root.mainloop()
