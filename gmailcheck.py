import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import queue
import csv
import socket
import smtplib
import dns.resolver
import re
import os
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

APP_TITLE = "Bulk Email Validator Pro"
MAX_WORKERS = 6
DNS_TIMEOUT = 5
SMTP_TIMEOUT = 8

BG = "#F4F7FB"
CARD = "#FFFFFF"
CARD_BORDER = "#D9E2EC"
HEADER_BG = "#EAF1F8"
TEXT = "#17202A"
SECONDARY = "#52606D"
MUTED = "#7B8794"
BLUE = "#2F8FD3"
BLUE_HOVER = "#237BB9"
GREEN = "#16A05D"
GREEN_HOVER = "#118B50"
GREEN_LIGHT = "#E7F7EF"
GREEN_TEXT = "#087A45"
RED = "#D9363E"
RED_HOVER = "#B82C34"
RED_LIGHT = "#FDEBEC"
RED_TEXT = "#B4232A"
WHITE = "#FFFFFF"

EMAIL_REGEX = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)

mx_cache = {}
mx_lock = threading.Lock()
resolver = dns.resolver.Resolver()
resolver.timeout = DNS_TIMEOUT
resolver.lifetime = DNS_TIMEOUT


def check_syntax(email):
    if not email or len(email) > 254 or " " in email:
        return False
    if email.count("@") != 1:
        return False
    return bool(EMAIL_REGEX.fullmatch(email))


def get_domain(email):
    return email.rsplit("@", 1)[1].lower()


def get_mx_records(domain):
    with mx_lock:
        if domain in mx_cache:
            return mx_cache[domain]

    records = []
    try:
        answers = resolver.resolve(domain, "MX")
        records = sorted(
            [(int(a.preference), str(a.exchange).rstrip(".").lower())
             for a in answers],
            key=lambda x: x[0]
        )
    except Exception:
        records = []

    # RFC-compliant fallback: if there is no MX, an A/AAAA host can
    # receive mail. This avoids incorrectly declaring such domains invalid.
    if not records:
        try:
            resolver.resolve(domain, "A")
            records = [(0, domain)]
        except Exception:
            try:
                resolver.resolve(domain, "AAAA")
                records = [(0, domain)]
            except Exception:
                records = []

    with mx_lock:
        mx_cache[domain] = records
    return records


def smtp_rcpt_check(host, email):
    """
    Return:
      VALID   -> the server explicitly accepted RCPT TO
      INVALID -> the server explicitly rejected RCPT TO as a mailbox
      RETRY   -> connection/policy/temporary failure; cannot prove either way

    IMPORTANT: SMTP cannot guarantee that a mailbox exists. Some providers
    deliberately accept every RCPT TO (catch-all) or hide mailbox status.
    """
    server = None
    try:
        server = smtplib.SMTP(host, 25, timeout=SMTP_TIMEOUT)
        code, _ = server.ehlo()
        if code >= 400:
            return "RETRY", f"EHLO rejected ({code})"

        # Use TLS when the server advertises it. We do not authenticate.
        if server.has_extn("starttls"):
            try:
                server.starttls()
                code, _ = server.ehlo()
                if code >= 400:
                    return "RETRY", f"EHLO after STARTTLS rejected ({code})"
            except (smtplib.SMTPException, OSError):
                # Some servers advertise STARTTLS incorrectly. Continue
                # without TLS rather than treating this as a mailbox rejection.
                pass

        code, msg = server.mail("")
        if code >= 500:
            return "RETRY", f"MAIL FROM rejected ({code})"

        code, msg = server.rcpt(email)

        if 200 <= code < 300:
            return "VALID", f"SMTP accepted recipient ({code})"

        if code in (550, 551, 553):
            return "INVALID", f"SMTP rejected recipient ({code})"

        if 500 <= code < 600:
            return "INVALID", f"SMTP rejected recipient ({code})"

        return "RETRY", f"Temporary/policy response ({code})"

    except socket.timeout:
        return "RETRY", "SMTP timeout"
    except (ConnectionRefusedError, ConnectionResetError, OSError):
        return "RETRY", "SMTP connection failed"
    except smtplib.SMTPServerDisconnected:
        return "RETRY", "SMTP server disconnected"
    except smtplib.SMTPConnectError:
        return "RETRY", "SMTP connection error"
    except smtplib.SMTPException as e:
        return "RETRY", f"SMTP error: {str(e)[:100]}"
    except Exception as e:
        return "RETRY", f"SMTP unavailable: {str(e)[:100]}"
    finally:
        if server:
            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass


def check_catch_all(host, domain):
    """
    Test a random mailbox. If it is accepted, the domain is probably
    catch-all, so an SMTP-positive result cannot prove the requested mailbox.
    """
    random_local = "email-validator-" + uuid.uuid4().hex[:14]
    probe = f"{random_local}@{domain}"
    result, _ = smtp_rcpt_check(host, probe)
    return result == "VALID"


def check_email(email, stop_event):
    result = {
        "email": email,
        "syntax": "No",
        "domain": "No",
        "mx": "No",
        "smtp": "No",
        "status": "Invalid",
        "reason": ""
    }

    if stop_event.is_set():
        return None

    email = email.strip().lower()
    result["email"] = email

    if not check_syntax(email):
        result["reason"] = "Invalid email format"
        return result

    result["syntax"] = "Yes"
    domain = get_domain(email)

    if not domain:
        result["reason"] = "Domain missing"
        return result

    if stop_event.is_set():
        return None

    mx_records = get_mx_records(domain)
    if not mx_records:
        result["reason"] = "Domain has no reachable MX/A/AAAA mail host"
        return result

    result["domain"] = "Yes"
    result["mx"] = "Yes"

    retry_reasons = []

    for _, host in mx_records:
        if stop_event.is_set():
            return None

        state, reason = smtp_rcpt_check(host, email)

        if state == "VALID":
            # A catch-all domain accepts random recipients too. In that
            # situation the requested address cannot be proven to exist.
            if check_catch_all(host, domain):
                result["smtp"] = "Yes"
                result["status"] = "Invalid"
                result["reason"] = (
                    "Domain appears to be catch-all; mailbox existence "
                    "cannot be confirmed"
                )
                return result

            result["smtp"] = "Yes"
            result["status"] = "Valid"
            result["reason"] = reason
            return result

        if state == "INVALID":
            result["smtp"] = "No"
            result["status"] = "Invalid"
            result["reason"] = reason
            return result

        retry_reasons.append(reason)

    # User requested only two outcomes: Valid / Invalid.
    # Any SMTP timeout, blocking, connection failure, or provider refusal
    # that does not explicitly prove the mailbox exists is therefore Invalid.
    result["status"] = "Invalid"
    result["reason"] = (
        retry_reasons[-1] if retry_reasons else
        "Mailbox could not be confirmed"
    )
    return result


class BulkEmailValidator(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1360x760")
        self.minsize(1050, 650)
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color=BG)

        self.emails = []
        self.results = []
        self.result_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.executor = None
        self.running = False

        self.total = 0
        self.completed = 0
        self.valid_count = 0
        self.invalid_count = 0

        self.search_var = tk.StringVar()
        self.filter_var = tk.StringVar(value="All")
        self.file_name_var = tk.StringVar(value="No file selected")

        self.build_ui()
        self.search_var.trace_add("write", lambda *_: self.refresh_table())
        self.filter_var.trace_add("write", lambda *_: self.refresh_table())
        self.after(120, self.process_result_queue)

    def build_ui(self):
        self.create_header()
        self.create_buttons()
        self.create_input_box()
        self.create_file_info()
        self.create_statistics()
        self.create_progress()
        self.create_search_filter()
        self.create_results_table()

    def create_header(self):
        header = ctk.CTkFrame(
            self, fg_color=HEADER_BG, corner_radius=14,
            border_width=1, border_color=CARD_BORDER
        )
        header.pack(fill="x", padx=20, pady=(12, 6))

        ctk.CTkLabel(
            header, text="✉", font=("Segoe UI", 34, "bold"),
            text_color=BLUE
        ).grid(row=0, column=0, rowspan=2, padx=(18, 12), pady=10)

        ctk.CTkLabel(
            header, text="Bulk Email Validator Pro",
            font=("Segoe UI", 25, "bold"), text_color=TEXT
        ).grid(row=0, column=1, sticky="w", pady=(12, 0))

        ctk.CTkLabel(
            header,
            text="Syntax  •  Domain  •  MX  •  SMTP recipient check",
            font=("Segoe UI", 12), text_color=SECONDARY
        ).grid(row=1, column=1, sticky="w", pady=(0, 12))

        ctk.CTkLabel(
            header, text="Valid or Invalid",
            font=("Segoe UI", 13, "italic"), text_color=BLUE
        ).grid(row=0, column=2, rowspan=2, padx=20)

        header.grid_columnconfigure(1, weight=1)

    def create_buttons(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="x", padx=20, pady=3)

        def button(text, color, hover, width, command, state="normal"):
            return ctk.CTkButton(
                frame, text=text, width=width, height=38,
                corner_radius=8, fg_color=color, hover_color=hover,
                text_color=WHITE, font=("Segoe UI", 13, "bold"),
                command=command, state=state
            )

        self.upload_button = button(
            "⇧  Upload CSV / TXT", BLUE, BLUE_HOVER, 170, self.upload_file
        )
        self.upload_button.pack(side="left", padx=(0, 8))

        self.start_button = button(
            "▶  Start Validation", GREEN, GREEN_HOVER, 170,
            self.start_validation
        )
        self.start_button.pack(side="left", padx=4)

        self.stop_button = button(
            "■  Stop", RED, RED_HOVER, 105,
            self.stop_validation, "disabled"
        )
        self.stop_button.pack(side="left", padx=4)

        self.clear_button = button(
            "♲  Clear All", "#64748B", "#475569", 115, self.clear_all
        )
        self.clear_button.pack(side="left", padx=4)

        self.export_button = button(
            "▣  Export CSV", BLUE, BLUE_HOVER, 145, self.export_csv
        )
        self.export_button.pack(side="right")

    def create_input_box(self):
        outer = ctk.CTkFrame(
            self, fg_color=CARD, corner_radius=10,
            border_width=1, border_color=CARD_BORDER
        )
        outer.pack(fill="x", padx=20, pady=(3, 4))

        title_frame = ctk.CTkFrame(outer, fg_color="transparent")
        title_frame.pack(fill="x", padx=12, pady=(7, 1))

        ctk.CTkLabel(
            title_frame, text="⌨  Type / Paste Emails",
            font=("Segoe UI", 14, "bold"), text_color=TEXT
        ).pack(side="left")

        ctk.CTkLabel(
            title_frame, text="One per line, or paste a list",
            font=("Segoe UI", 11), text_color=MUTED
        ).pack(side="left", padx=10)

        self.email_textbox = ctk.CTkTextbox(
            outer, height=70, font=("Segoe UI", 12),
            text_color=TEXT, fg_color="#FBFCFE",
            border_width=1, border_color="#B8C4D0", corner_radius=7
        )
        self.email_textbox.pack(fill="x", padx=12, pady=3)

        button_frame = ctk.CTkFrame(outer, fg_color="transparent")
        button_frame.pack(fill="x", padx=12, pady=(1, 7))

        self.add_typed_button = ctk.CTkButton(
            button_frame, text="＋  Add Typed Emails",
            width=165, height=32, corner_radius=7,
            fg_color=GREEN, hover_color=GREEN_HOVER,
            text_color=WHITE, font=("Segoe UI", 12, "bold"),
            command=self.add_typed_emails
        )
        self.add_typed_button.pack(side="left")

        self.clear_typed_button = ctk.CTkButton(
            button_frame, text="Clear Typed", width=115, height=32,
            corner_radius=7, fg_color="#94A3B8", hover_color="#64748B",
            text_color=WHITE, font=("Segoe UI", 12, "bold"),
            command=self.clear_typed
        )
        self.clear_typed_button.pack(side="left", padx=7)

        self.input_count_label = ctk.CTkLabel(
            button_frame, text="0 emails ready to add",
            font=("Segoe UI", 11), text_color=SECONDARY
        )
        self.input_count_label.pack(side="right")
        self.email_textbox.bind("<KeyRelease>", self.update_typed_count)

    def update_typed_count(self, event=None):
        text = self.email_textbox.get("1.0", "end").strip()
        count = len(self.extract_typed_entries(text)) if text else 0
        self.input_count_label.configure(text=f"{count} emails ready to add")

    def extract_typed_entries(self, text):
        entries = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            matches = re.findall(r"[^\s,;]+@[^\s,;]+", line)
            if matches:
                entries.extend(x.strip().lower() for x in matches)
            else:
                entries.append(line.lower())
        return list(dict.fromkeys(entries))

    def add_typed_emails(self):
        if self.running:
            messagebox.showwarning(
                "Validation running",
                "Please stop the current validation first."
            )
            return

        text = self.email_textbox.get("1.0", "end").strip()
        if not text:
            messagebox.showwarning(
                "No emails", "Please type or paste some emails first."
            )
            return

        typed = self.extract_typed_entries(text)
        before = len(self.emails)
        for email in typed:
            if email not in self.emails:
                self.emails.append(email)

        added = len(self.emails) - before
        self.reset_results_only()
        self.total = len(self.emails)
        self.file_name_var.set(
            f"⌨  Typed / pasted emails   |   "
            f"{len(self.emails)} unique emails ready"
        )
        self.email_textbox.delete("1.0", "end")
        self.update_typed_count()
        self.update_statistics()
        self.refresh_table()

        messagebox.showinfo(
            "Emails added" if added else "Already added",
            f"{added} new email(s) added.\n\n"
            f"Total emails ready: {len(self.emails)}"
            if added else
            "All of these emails are already in the list."
        )

    def clear_typed(self):
        self.email_textbox.delete("1.0", "end")
        self.update_typed_count()

    def create_file_info(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="x", padx=22, pady=(0, 2))
        ctk.CTkLabel(
            frame, textvariable=self.file_name_var,
            font=("Segoe UI", 11), text_color=SECONDARY, anchor="w"
        ).pack(side="left")

    def create_statistics(self):
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="x", padx=20, pady=2)

        self.total_card = self.create_stat_card(frame, "TOTAL", "0", BLUE, 0)
        self.valid_card = self.create_stat_card(frame, "VALID", "0", GREEN, 1)
        self.invalid_card = self.create_stat_card(frame, "INVALID", "0", RED, 2)

        for i in range(3):
            frame.grid_columnconfigure(i, weight=1)

    def create_stat_card(self, parent, title, value, accent, column):
        card = ctk.CTkFrame(
            parent, fg_color=CARD, corner_radius=9,
            border_width=2, border_color=accent
        )
        card.grid(row=0, column=column, padx=4, sticky="nsew")
        ctk.CTkLabel(
            card, text=title, font=("Segoe UI", 10, "bold"),
            text_color=SECONDARY
        ).pack(pady=(5, 0))
        label = ctk.CTkLabel(
            card, text=value, font=("Segoe UI", 20, "bold"),
            text_color=TEXT
        )
        label.pack(pady=(0, 5))
        return label

    def create_progress(self):
        frame = ctk.CTkFrame(
            self, fg_color=CARD, corner_radius=9,
            border_width=1, border_color=CARD_BORDER
        )
        frame.pack(fill="x", padx=20, pady=4)

        self.progress_label = ctk.CTkLabel(
            frame, text="Ready", font=("Segoe UI", 11, "bold"),
            text_color=TEXT
        )
        self.progress_label.pack(anchor="w", padx=12, pady=(5, 2))

        self.progress = ctk.CTkProgressBar(
            frame, height=9, corner_radius=5,
            progress_color=BLUE, fg_color="#D9E2EC"
        )
        self.progress.pack(fill="x", padx=12, pady=(0, 7))
        self.progress.set(0)

    def create_search_filter(self):
        frame = ctk.CTkFrame(
            self, fg_color=CARD, corner_radius=9,
            border_width=1, border_color=CARD_BORDER
        )
        frame.pack(fill="x", padx=20, pady=(2, 4))

        self.search_entry = ctk.CTkEntry(
            frame, textvariable=self.search_var, height=34,
            placeholder_text="Search email...", font=("Segoe UI", 12),
            text_color=TEXT, fg_color=WHITE, border_color="#AAB7C4"
        )
        self.search_entry.pack(
            side="left", fill="x", expand=True, padx=(10, 8), pady=7
        )

        ctk.CTkLabel(
            frame, text="Filter:", font=("Segoe UI", 11, "bold"),
            text_color=TEXT
        ).pack(side="left", padx=(3, 6))

        self.filter_menu = ctk.CTkOptionMenu(
            frame, variable=self.filter_var,
            values=["All", "Valid", "Invalid"], width=115, height=34,
            fg_color=BLUE, button_color=BLUE,
            button_hover_color=BLUE_HOVER,
            text_color=WHITE, font=("Segoe UI", 11, "bold")
        )
        self.filter_menu.pack(side="right", padx=(0, 10), pady=7)

    def create_results_table(self):
        outer = ctk.CTkFrame(
            self, fg_color=CARD, corner_radius=10,
            border_width=1, border_color=CARD_BORDER
        )
        outer.pack(fill="both", expand=True, padx=20, pady=(0, 12))

        table_frame = tk.Frame(outer, bg=WHITE)
        table_frame.pack(fill="both", expand=True, padx=5, pady=5)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "Email.Treeview", background=WHITE, foreground=TEXT,
            fieldbackground=WHITE, rowheight=32,
            font=("Segoe UI", 10), borderwidth=0
        )
        style.configure(
            "Email.Treeview.Heading", background="#E8EEF5",
            foreground=TEXT, font=("Segoe UI", 10, "bold"),
            relief="flat", padding=6
        )

        columns = (
            "number", "email", "syntax", "domain",
            "mx", "smtp", "status", "reason"
        )
        self.tree = ttk.Treeview(
            table_frame, columns=columns, show="headings",
            style="Email.Treeview", selectmode="browse"
        )

        headings = {
            "number": "#", "email": "Email", "syntax": "Syntax",
            "domain": "Domain", "mx": "MX", "smtp": "SMTP",
            "status": "Status", "reason": "Reason"
        }
        for col, heading in headings.items():
            self.tree.heading(col, text=heading)

        self.tree.column("number", width=45, minwidth=40, anchor="center")
        self.tree.column("email", width=300, minwidth=220, anchor="w")
        self.tree.column("syntax", width=70, minwidth=60, anchor="center")
        self.tree.column("domain", width=75, minwidth=60, anchor="center")
        self.tree.column("mx", width=65, minwidth=55, anchor="center")
        self.tree.column("smtp", width=70, minwidth=55, anchor="center")
        self.tree.column("status", width=95, minwidth=80, anchor="center")
        self.tree.column("reason", width=500, minwidth=250, anchor="w")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        self.tree.tag_configure("valid", background=GREEN_LIGHT, foreground=GREEN_TEXT)
        self.tree.tag_configure("invalid", background=RED_LIGHT, foreground=RED_TEXT)
        self.tree.tag_configure("pending", background=WHITE, foreground=TEXT)

    def upload_file(self):
        if self.running:
            messagebox.showwarning(
                "Validation running",
                "Please stop the current validation first."
            )
            return

        path = filedialog.askopenfilename(
            title="Select email file",
            filetypes=[
                ("Email files", "*.txt *.csv"),
                ("Text files", "*.txt"),
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ]
        )
        if not path:
            return

        try:
            emails = self.read_emails(path)
        except Exception as e:
            messagebox.showerror("File Error", f"Could not read the file.\n\n{e}")
            return

        if not emails:
            messagebox.showwarning("No emails found", "No entries were found.")
            return

        self.emails = emails
        self.reset_results_only()
        self.total = len(emails)
        filename = os.path.basename(path)
        self.file_name_var.set(
            f"▣  {filename}   |   {len(emails)} unique emails"
        )
        self.progress.set(0)
        self.progress_label.configure(text=f"Ready to validate {len(emails)} emails")
        self.update_statistics()
        self.refresh_table()

        messagebox.showinfo(
            "Emails loaded",
            f"{len(emails)} unique entries loaded successfully.\n\n"
            "Every result will be shown only as Valid or Invalid."
        )

    def read_emails(self, path):
        found = []
        if path.lower().endswith(".csv"):
            with open(
                path, "r", encoding="utf-8-sig",
                errors="ignore", newline=""
            ) as file:
                for row in csv.reader(file):
                    for cell in row:
                        value = cell.strip().lower()
                        if value:
                            # If a CSV contains names or other text, only
                            # take cells that look like email candidates.
                            if "@" in value:
                                found.append(value)
        else:
            with open(path, "r", encoding="utf-8", errors="ignore") as file:
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                    matches = re.findall(r"[^\s,;]+@[^\s,;]+", line)
                    if matches:
                        found.extend(x.strip().lower() for x in matches)
                    else:
                        found.append(line.lower())
        return list(dict.fromkeys(found))

    def reset_results_only(self):
        self.results = []
        self.completed = 0
        self.valid_count = 0
        self.invalid_count = 0

    def start_validation(self):
        if self.running:
            return
        if not self.emails:
            messagebox.showwarning(
                "No emails",
                "Please upload a file or type/paste emails first."
            )
            return

        self.reset_results_only()
        self.total = len(self.emails)

        while True:
            try:
                self.result_queue.get_nowait()
            except queue.Empty:
                break

        self.stop_event = threading.Event()
        self.running = True

        for button in (
            self.start_button, self.upload_button,
            self.add_typed_button, self.clear_typed_button
        ):
            button.configure(state="disabled")

        self.stop_button.configure(state="normal")
        self.clear_button.configure(state="disabled")
        self.export_button.configure(state="disabled")
        self.progress.set(0)
        self.progress_label.configure(
            text=f"Checking 0 / {self.total}   (0%)"
        )
        self.refresh_table()

        threading.Thread(
            target=self.run_bulk_validation, daemon=True
        ).start()

    def run_bulk_validation(self):
        try:
            self.executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
            futures = {}

            for email in self.emails:
                if self.stop_event.is_set():
                    break
                future = self.executor.submit(
                    check_email, email, self.stop_event
                )
                futures[future] = email

            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception as e:
                    result = {
                        "email": futures[future],
                        "syntax": "No", "domain": "No",
                        "mx": "No", "smtp": "No",
                        "status": "Invalid",
                        "reason": f"Validation error: {str(e)[:120]}"
                    }

                if result is not None:
                    self.result_queue.put(("result", result))

                if self.stop_event.is_set():
                    break

            self.result_queue.put(("finished", None))

        except Exception as e:
            self.result_queue.put(("error", str(e)))
            self.result_queue.put(("finished", None))

    def process_result_queue(self):
        changed = False
        finished = False

        for _ in range(30):
            try:
                message_type, data = self.result_queue.get_nowait()
            except queue.Empty:
                break

            if message_type == "result":
                self.results.append(data)
                self.completed += 1
                if data["status"] == "Valid":
                    self.valid_count += 1
                else:
                    self.invalid_count += 1
                changed = True

            elif message_type == "error":
                messagebox.showerror("Validation error", data)

            elif message_type == "finished":
                finished = True

        if changed:
            self.update_statistics()
            percentage = self.completed / self.total if self.total else 0
            self.progress.set(percentage)
            self.progress_label.configure(
                text=(
                    f"Checking {self.completed} / {self.total}   "
                    f"({int(percentage * 100)}%)"
                )
            )
            self.refresh_table()

        if finished:
            self.validation_finished()

        self.after(120, self.process_result_queue)

    def validation_finished(self):
        if not self.running:
            return

        self.running = False

        if self.completed >= self.total:
            self.progress.set(1)
            self.progress_label.configure(
                text=f"Completed {self.total} / {self.total}   (100%)"
            )
        else:
            self.progress_label.configure(
                text=f"Stopped at {self.completed} / {self.total}"
            )

        if self.executor:
            try:
                self.executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                try:
                    self.executor.shutdown(wait=False)
                except Exception:
                    pass
            except Exception:
                pass
            self.executor = None

        self.start_button.configure(state="normal")
        self.upload_button.configure(state="normal")
        self.add_typed_button.configure(state="normal")
        self.clear_typed_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.clear_button.configure(state="normal")
        self.export_button.configure(
            state="normal" if self.results else "disabled"
        )
        self.refresh_table()

    def stop_validation(self):
        if not self.running:
            return
        self.stop_event.set()
        self.progress_label.configure(text="Stopping validation...")
        self.stop_button.configure(state="disabled")

    def get_filtered_results(self):
        search = self.search_var.get().strip().lower()
        selected = self.filter_var.get()

        filtered = []
        for result in self.results:
            if search and search not in result["email"].lower():
                continue
            if selected != "All" and result["status"] != selected:
                continue
            filtered.append(result)
        return filtered

    def refresh_table(self):
        if not hasattr(self, "tree"):
            return

        self.tree.delete(*self.tree.get_children())
        for index, result in enumerate(self.get_filtered_results(), start=1):
            status = result["status"]
            tag = "valid" if status == "Valid" else "invalid"
            self.tree.insert(
                "", "end",
                values=(
                    index, result["email"], result["syntax"],
                    result["domain"], result["mx"], result["smtp"],
                    status, result["reason"]
                ),
                tags=(tag,)
            )

    def update_statistics(self):
        self.total_card.configure(text=str(self.total))
        self.valid_card.configure(text=str(self.valid_count))
        self.invalid_card.configure(text=str(self.invalid_count))

    def export_csv(self):
        if not self.results:
            messagebox.showwarning(
                "No results", "There are no validation results to export."
            )
            return

        path = filedialog.asksaveasfilename(
            title="Save validation results",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile="email_validation_results.csv"
        )
        if not path:
            return

        try:
            with open(
                path, "w", newline="", encoding="utf-8-sig"
            ) as file:
                writer = csv.writer(file)
                writer.writerow([
                    "#", "Email", "Syntax", "Domain",
                    "MX", "SMTP", "Status", "Reason"
                ])
                for index, result in enumerate(self.results, start=1):
                    writer.writerow([
                        index, result["email"], result["syntax"],
                        result["domain"], result["mx"], result["smtp"],
                        result["status"], result["reason"]
                    ])

            messagebox.showinfo("Export complete", "Results exported successfully.")

        except Exception as e:
            messagebox.showerror(
                "Export error", f"Could not export CSV.\n\n{e}"
            )

    def clear_all(self):
        if self.running:
            messagebox.showwarning(
                "Validation running",
                "Stop validation before clearing."
            )
            return

        self.emails = []
        self.reset_results_only()
        self.total = 0
        self.file_name_var.set("No file selected")
        self.search_var.set("")
        self.filter_var.set("All")
        self.progress.set(0)
        self.progress_label.configure(text="Ready")
        self.email_textbox.delete("1.0", "end")
        self.update_typed_count()
        self.update_statistics()
        self.refresh_table()


if __name__ == "__main__":
    app = BulkEmailValidator()
    app.mainloop()
