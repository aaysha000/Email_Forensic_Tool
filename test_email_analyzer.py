import unittest
from email_analyzer_without_GUI import EmailHeaderAnalyzer

class TestEmailHeaderAnalyzer(unittest.TestCase):

    def create_email(self, headers, body="", attachments=False):
        if attachments:
            content = (
                "MIME-Version: 1.0\n"
                "Content-Type: multipart/mixed; boundary=BOUNDARY\n"
                f"{headers}\n\n"
                "--BOUNDARY\n"
                "Content-Type: text/plain\n\n"
                f"{body}\n"
                "--BOUNDARY\n"
                "Content-Type: application/octet-stream\n"
                "Content-Disposition: attachment; filename=\"malware.exe\"\n\n"
                "FAKE-BINARY-DATA\n"
                "--BOUNDARY--"
            )
        else:
            content = (
                headers +
                "\nContent-Type: text/plain; charset=\"utf-8\"\n\n" +
                body
            )
        return content.encode()

    def test_is_spoofed_missing_at(self):
        raw = self.create_email("From: suspiciousdomain.com")
        analyzer = EmailHeaderAnalyzer(raw)
        self.assertTrue(analyzer.is_spoofed())
        self.assertIn("From address missing '@'", analyzer.reasons)

    def test_contains_suspicious_keywords(self):
        raw = self.create_email("From: test@example.com", body="Please click to reset your account.")
        analyzer = EmailHeaderAnalyzer(raw)
        self.assertTrue(analyzer.contains_suspicious_keywords())
        self.assertTrue(any("Suspicious keywords" in r for r in analyzer.reasons))

    def test_contains_links(self):
        raw = self.create_email("From: test@example.com", body="Visit https://example.com now!")
        analyzer = EmailHeaderAnalyzer(raw)
        self.assertTrue(analyzer.contains_links())
        self.assertIn("Contains suspicious URL links", analyzer.reasons)

    def test_reply_to_mismatch(self):
        raw = self.create_email("From: sender@example.com\nReply-To: attacker@example.net")
        analyzer = EmailHeaderAnalyzer(raw)
        self.assertTrue(analyzer.reply_to_mismatch())
        self.assertIn("Reply-To does not match From", analyzer.reasons)

    def test_summary_contains_all_keys(self):
        raw = self.create_email("From: test@example.com\nTo: a@example.com\nSubject: Test Email\nDate: Today")
        analyzer = EmailHeaderAnalyzer(raw)
        summary = analyzer.summary()
        expected_keys = [
            "Subject", "From", "To", "Date", "Sender IP",
            "Attachments", "SPF", "DKIM", "DMARC", "Risk Verdict", "Reasons"
        ]
        for key in expected_keys:
            self.assertIn(key, summary)

    def test_spf_dkim_dmarc_failures(self):
        headers = (
            "From: user@example.com\n"
            "Authentication-Results: spf=fail dkim=fail dmarc=fail"
        )
        raw = self.create_email(headers)
        analyzer = EmailHeaderAnalyzer(raw)
        auth = analyzer.spf_dkim_dmarc_summary()
        self.assertEqual(auth['SPF'], 'fail')
        self.assertEqual(auth['DKIM'], 'fail')
        self.assertEqual(auth['DMARC'], 'fail')
        self.assertIn("SPF=fail", analyzer.reasons)
        self.assertIn("DKIM=fail", analyzer.reasons)
        self.assertIn("DMARC=fail", analyzer.reasons)

    def test_has_risky_attachments(self):
        raw = self.create_email("From: test@example.com", body="Here is the file", attachments=True)
        analyzer = EmailHeaderAnalyzer(raw)
        self.assertTrue(analyzer.has_risky_attachments())
        self.assertIn("Risky attachment detected: malware.exe", analyzer.reasons)

    def test_verdict_high_risk(self):
        headers = (
            "From: bad@phishingsite.example.com\n"
            "Reply-To: hacker@evil.com\n"
            "Authentication-Results: spf=fail dkim=fail dmarc=fail"
        )
        body = "Urgent! Please click here: http://malicious.com to reset your account!"
        raw = self.create_email(headers, body=body, attachments=True)
        analyzer = EmailHeaderAnalyzer(raw)
        result = analyzer.verdict()
        self.assertEqual(result, "High Risk")

    def test_verdict_clean(self):
        headers = (
            "From: user@gmail.com\n"
            "To: receiver@example.com\n"
            "Subject: Greetings\n"
            "Date: Fri, 1 Aug 2025 12:00:00 +0000\n"
            "Received: from mail.google.com by mx.example.com\n"
            "Authentication-Results: spf=pass dkim=pass dmarc=pass"
        )
        body = "Hello, just checking in. Hope you're well."
        raw = self.create_email(headers, body)
        analyzer = EmailHeaderAnalyzer(raw)
        result = analyzer.verdict()
        self.assertEqual(result, "Clean")



if __name__ == "__main__":
    unittest.main()
