import email, imaplib, re, os, json, csv
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

    def verdict(self):
        self.reasons.clear()
        auth = self.spf_dkim_dmarc_summary()
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

# ================== CLI Utility ==================
def analyze_eml_file(path):
    with open(path, 'rb') as f:
        analyzer = EmailHeaderAnalyzer(f.read())
    report = analyzer.summary()
    print_report(report)
    return report

def print_report(report):
    print("\n" + "="*60)
    print("Email Analysis Report")
    print("="*60)
    for k, v in report.items():
        print(f"{k}: {v}")
    print("="*60)

def export_to_json(report, filename="email_analysis.json"):
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    print(f"[✓] Report saved to {filename}")

def main():
    print("Email Forensics Analyzer (Non-GUI Mode)")
    print("1. Analyze .eml file\n2. Exit")
    choice = input("Select option: ").strip()

    if choice == "1":
        path = input("Enter path to .eml file: ").strip()
        if os.path.isfile(path):
            report = analyze_eml_file(path)
            save = input("Save report to JSON? (y/n): ").strip().lower()
            if save == "y":
                export_to_json(report)
        else:
            print("[!] File not found.")
    else:
        print("Exiting.")

if __name__ == '__main__':
    main()
