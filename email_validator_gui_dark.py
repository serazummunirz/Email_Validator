import csv
import re
import sys
import time
import random
import string
import socket
import socks
import smtplib
import threading
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

import dns.resolver
import dns.exception
import dns.name

from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit,
    QPushButton, QFileDialog, QSpinBox, QProgressBar, QTextEdit,
    QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox, QMessageBox,
    QFrame, QGridLayout, QDialog, QComboBox, QDialogButtonBox, QCheckBox
)
from PyQt5.QtGui import (
    QIcon, QPixmap, QPainter, QColor, QPen, QBrush
)

# -------------------- CONFIGURATION --------------------

SMTP_TIMEOUT = 8
DNS_TIMEOUT = 5
DEFAULT_WORKERS = 5
MAX_WORKERS = 10

# Use a real, monitored address on a domain you control.
# Some receiving mail servers reject placeholder sender addresses.
SENDER_EMAIL = "verify@example.com"

VALID_OUTPUT = "verified_emails.csv"
INVALID_OUTPUT = "rejected_emails.csv"

FIELDS = ["email", "syntax", "mx", "smtp", "catch_all", "status"]


# -------------------- VALIDATION FUNCTIONS --------------------

def valid_syntax(email):
    """Basic syntax check; not a guarantee that the mailbox exists."""
    if not email or len(email) > 254 or email.count("@") != 1:
        return False

    local, domain = email.rsplit("@", 1)

    if not local or len(local) > 64 or not domain or ".." in local:
        return False

    if local.startswith(".") or local.endswith("."):
        return False

    if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local):
        return False

    if not re.fullmatch(r"[A-Za-z0-9.-]+", domain):
        return False

    if domain.startswith(".") or domain.endswith(".") or ".." in domain:
        return False

    labels = domain.split(".")
    if len(labels) < 2:
        return False

    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        for label in labels
    ):
        return False

    return len(labels[-1]) >= 2 and labels[-1].isalpha()


def get_mx_records(domain):
    try:
        dns.name.from_text(domain, origin=None)
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT + 2

        answers = resolver.resolve(domain, "MX")
        records = sorted(answers, key=lambda record: record.preference)
        return [str(record.exchange).rstrip(".") for record in records]

    except dns.resolver.NXDOMAIN:
        return None
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.name.EmptyLabel,
        dns.name.NameTooLong,
        dns.exception.SyntaxError,
        ValueError,
    ):
        return None
    except Exception:
        return []


def random_email(domain):
    username = "".join(
        random.choices(string.ascii_lowercase + string.digits, k=16)
    )
    return f"{username}@{domain}"


def smtp_check(email, mx_records, stop_event=None, proxy=None):
    """Best-effort SMTP recipient test with optional proxy support."""

    for mx in mx_records:
        if stop_event and stop_event.is_set():
            return "UNKNOWN"

        server = None

        try:
            if proxy and proxy.get("enabled"):
                proxy_type = {
                    "SOCKS5": socks.SOCKS5,
                    "SOCKS4": socks.SOCKS4,
                    "HTTP": socks.HTTP,
                }[proxy["type"]]

                proxy_socket = socks.socksocket()
                proxy_socket.set_proxy(
                    proxy_type,
                    proxy["host"],
                    int(proxy["port"]),
                    username=proxy.get("username") or None,
                    password=proxy.get("password") or None,
                )
                proxy_socket.settimeout(SMTP_TIMEOUT)
                proxy_socket.connect((mx, 25))

                server = smtplib.SMTP(timeout=SMTP_TIMEOUT)
                server.connect(mx, 25)
                server.sock.close()
                server.sock = proxy_socket
                server.file = None

            else:
                server = smtplib.SMTP(timeout=SMTP_TIMEOUT)
                server.connect(mx, 25)

            server.ehlo()
            server.mail(SENDER_EMAIL)

            code, _message = server.rcpt(email)

            if code in (250, 251):
                return "ACCEPTED"

            if code in (550, 551, 553):
                return "REJECTED"

            return "UNKNOWN"

        except (
            socket.timeout,
            socket.error,
            smtplib.SMTPException,
            OSError,
        ):
            continue

        finally:
            if server:
                try:
                    server.quit()
                except Exception:
                    try:
                        server.close()
                    except Exception:
                        pass

    return "UNKNOWN"



def verify_email(email, stop_event=None):
    email = (email or "").strip().lower()

    result = {
        "email": email,
        "syntax": "INVALID",
        "mx": "UNKNOWN",
        "smtp": "UNKNOWN",
        "catch_all": "UNKNOWN",
        "status": "UNKNOWN",
    }

    if not valid_syntax(email):
        result["status"] = "INVALID"
        return result

    result["syntax"] = "VALID"
    domain = email.rsplit("@", 1)[1]

    mx_records = get_mx_records(domain)

    if mx_records is None or not mx_records:
        result["mx"] = "INVALID"
        result["status"] = "INVALID"
        return result

    result["mx"] = "VALID"

    smtp_result = smtp_check(email, mx_records, stop_event)
    result["smtp"] = smtp_result

    if smtp_result == "REJECTED":
        result["status"] = "INVALID"
        return result

    if smtp_result != "ACCEPTED":
        return result

    # Catch-all detection uses one random recipient probe.
    # Some providers accept or defer all probes, so this remains indicative.
    if stop_event and stop_event.is_set():
        return result

    fake_email = random_email(domain)
    catch_result = smtp_check(fake_email, mx_records, stop_event)

    if catch_result == "ACCEPTED":
        result["catch_all"] = "YES"
        result["status"] = "UNKNOWN"
    elif catch_result == "REJECTED":
        result["catch_all"] = "NO"
        result["status"] = "VALID"

    return result


# -------------------- INPUT LOADING --------------------

def load_emails(filename):
    emails = []

    if filename.lower().endswith(".csv"):
        with open(filename, "r", encoding="utf-8-sig", newline="") as file:
            reader = csv.DictReader(file)

            if not reader.fieldnames:
                return []

            email_column = next(
                (
                    col for col in reader.fieldnames
                    if col and col.strip().lower() == "email"
                ),
                None,
            )

            if not email_column:
                raise ValueError("CSV must contain a column named 'email'.")

            for row in reader:
                value = row.get(email_column)
                if value and value.strip():
                    emails.append(value.strip())
    else:
        with open(filename, "r", encoding="utf-8-sig") as file:
            emails = [line.strip() for line in file if line.strip()]

    # Deduplicate case-insensitively while preserving input order.
    seen = set()
    unique = []
    for email in emails:
        key = email.strip().lower()
        if key and key not in seen:
            seen.add(key)
            unique.append(email.strip())

    return unique


# -------------------- BACKGROUND WORKER --------------------

class ValidationWorker(QThread):
    progress = pyqtSignal(int, int, str, str)
    counts_updated = pyqtSignal(int, int, int)
    log = pyqtSignal(str)
    finished_summary = pyqtSignal(int, int, int, bool)
    failed = pyqtSignal(str)

    def __init__(self, input_path, output_dir, max_workers):
        super().__init__()
        self.input_path = input_path
        # self.input_path.setMinimumHeight(38)
        self.output_dir = output_dir
        self.max_workers = max_workers
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.pause_event.set()  # Initially running

    def stop(self):
        self.stop_event.set()

    def run(self):
        try:
            emails = load_emails(self.input_path)
            total = len(emails)

            if total == 0:
                self.failed.emit("No email addresses were found in the input file.")
                return

            valid_path = f"{self.output_dir}/{VALID_OUTPUT}"
            invalid_path = f"{self.output_dir}/{INVALID_OUTPUT}"

            valid_count = 0
            invalid_count = 0
            unknown_count = 0
            completed = 0

            self.log.emit(f"Loaded {total:,} unique email addresses.")
            self.log.emit(f"Starting {self.max_workers} worker threads.")

            with open(valid_path, "w", newline="", encoding="utf-8") as valid_file, \
                 open(invalid_path, "w", newline="", encoding="utf-8") as invalid_file:

                valid_writer = csv.DictWriter(valid_file, fieldnames=FIELDS)
                invalid_writer = csv.DictWriter(invalid_file, fieldnames=FIELDS)
                valid_writer.writeheader()
                invalid_writer.writeheader()

                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:

                    futures = {
                        executor.submit(
                            verify_email,
                            email,
                            self.stop_event,
                            # self.proxy_config
                        ): email
                        for email in emails
                    }

                    pending = set(futures)

                    while pending:

                        # Cancel tasks that haven't started when Stop is requested
                        if self.stop_event.is_set():
                            for future in pending:
                                future.cancel()

                        # Wait briefly so Stop can be detected promptly
                        done, pending = wait(
                            pending,
                            timeout=0.2,
                            return_when=FIRST_COMPLETED
                        )

                        for future in done:

                            # Ignore tasks successfully cancelled before execution
                            if future.cancelled():
                                continue

                            # Respect Pause, but allow Stop to release the pause
                            while not self.pause_event.is_set():
                                if self.stop_event.is_set():
                                    break
                                time.sleep(0.2)

                            email = futures[future]
                            completed += 1

                            try:
                                result = future.result()

                            except Exception as exc:
                                result = {
                                    "email": email,
                                    "syntax": "UNKNOWN",
                                    "mx": "UNKNOWN",
                                    "smtp": "UNKNOWN",
                                    "catch_all": "UNKNOWN",
                                    "status": "UNKNOWN",
                                }

                                self.log.emit(f"Error checking {email}: {exc}")

                            if result["status"] == "VALID":
                                valid_writer.writerow(result)
                                valid_count += 1
                                valid_file.flush()

                            elif result["status"] == "INVALID":
                                invalid_writer.writerow(result)
                                invalid_count += 1
                                invalid_file.flush()

                            else:
                                unknown_count += 1

                            self.counts_updated.emit(
                                valid_count,
                                invalid_count,
                                unknown_count
                            )

                            self.progress.emit(
                                completed,
                                total,
                                email,
                                result["status"]
                            )

            stopped = self.stop_event.is_set()
            self.finished_summary.emit(
                valid_count, invalid_count, unknown_count, stopped
            )

        except Exception as exc:
            self.failed.emit(str(exc))

    def toggle_pause(self):
        if self.pause_event.is_set():
            self.pause_event.clear()
        else:
            self.pause_event.set()

    def request_stop(self):
        self.stop_event.set()

        # Release the worker if it is currently paused
        self.pause_event.set()


# -------------------- GUI --------------------

class ProxyDialog(QDialog):
    def __init__(self, proxy_config=None, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Proxy Configuration")
        self.setMinimumWidth(400)

        self.proxy_config = proxy_config or {}

        layout = QVBoxLayout(self)

        title = QLabel("PROXY CONFIGURATION")
        title.setStyleSheet(
            "font-size: 12pt; font-weight: bold; color: #45d6a5;"
        )
        layout.addWidget(title)

        self.enable_proxy = QCheckBox("Enable proxy")
        self.enable_proxy.setChecked(
            self.proxy_config.get("enabled", False)
        )
        layout.addWidget(self.enable_proxy)

        form = QFormLayout()

        self.proxy_type = QComboBox()
        self.proxy_type.addItems(["SOCKS5", "SOCKS4", "HTTP"])
        self.proxy_type.setCurrentText(
            self.proxy_config.get("type", "SOCKS5")
        )

        self.proxy_host = QLineEdit(
            self.proxy_config.get("host", "")
        )
        self.proxy_host.setPlaceholderText("127.0.0.1")

        self.proxy_port = QLineEdit(
            str(self.proxy_config.get("port", ""))
        )
        self.proxy_port.setPlaceholderText("1080")

        self.proxy_username = QLineEdit(
            self.proxy_config.get("username", "")
        )

        self.proxy_password = QLineEdit(
            self.proxy_config.get("password", "")
        )
        self.proxy_password.setEchoMode(QLineEdit.Password)

        form.addRow("Proxy Type:", self.proxy_type)
        form.addRow("Host / IP:", self.proxy_host)
        form.addRow("Port:", self.proxy_port)
        form.addRow("Username:", self.proxy_username)
        form.addRow("Password:", self.proxy_password)

        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Save | QDialogButtonBox.Cancel
        )

        buttons.accepted.connect(self.save_proxy)
        buttons.rejected.connect(self.reject)

        layout.addWidget(buttons)

    def save_proxy(self):
        if self.enable_proxy.isChecked():
            if not self.proxy_host.text().strip():
                QMessageBox.warning(
                    self, "Missing Host", "Please enter a proxy host."
                )
                return

            try:
                port = int(self.proxy_port.text())
                if not 1 <= port <= 65535:
                    raise ValueError
            except ValueError:
                QMessageBox.warning(
                    self, "Invalid Port", "Please enter a valid port."
                )
                return
        else:
            port = self.proxy_port.text().strip()

        self.proxy_config = {
            "enabled": self.enable_proxy.isChecked(),
            "type": self.proxy_type.currentText(),
            "host": self.proxy_host.text().strip(),
            "port": port,
            "username": self.proxy_username.text().strip(),
            "password": self.proxy_password.text(),
        }

        self.accept()


def create_app_icon():
    pixmap = QPixmap(64, 64)
    pixmap.fill(QColor(0, 0, 0, 0))

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)

    # Teal background
    painter.setBrush(QColor(23, 107, 87))
    painter.setPen(Qt.NoPen)
    painter.drawRoundedRect(2, 2, 60, 60, 14, 14)

    # White envelope
    painter.setPen(QPen(Qt.white, 3, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    painter.setBrush(Qt.NoBrush)

    painter.drawRoundedRect(12, 18, 40, 29, 4, 4)
    painter.drawLine(13, 20, 32, 35)
    painter.drawLine(51, 20, 32, 35)

    # Green verification badge
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(80, 200, 120))
    painter.drawEllipse(39, 39, 20, 20)

    # White checkmark
    painter.setPen(QPen(Qt.white, 2.5, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
    painter.drawLine(44, 49, 48, 53)
    painter.drawLine(48, 53, 55, 45)

    painter.end()

    return QIcon(pixmap)


class EmailValidatorWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowIcon(create_app_icon())
        self.setWindowTitle("CPA Email Validator")
        self.resize(1100, 900)
        self.setMinimumSize(1100, 900)
        

        self.worker = None
        self.input_path = ""
        self.output_dir = ""
        self.started_at = None
        self.last_completed = 0
        self.total_emails = 0

        self.setStyleSheet("""
            QWidget {
                background: #0b1220;
                color: #e5edf7;
                font-family: 'Inter', 'Segoe UI', sans-serif;
                font-size: 10pt;
            }
            QMainWindow { background: #0b1220; }
            QLabel { background: transparent; }
            QLabel#muted { color: #91a1b7; }
            QLabel#eyebrow {
                color: #54d6b0;
                font-size: 9pt;
                font-weight: 700;
                letter-spacing: 1px;
            }
            QLabel#mainTitle { font-size: 25pt; font-weight: 750; color: #f4f8fc; }
            QLabel#sectionTitle { font-size: 12pt; font-weight: 700; color: #edf4fb; }
            QFrame#panel, QGroupBox {
                background: #111c2d;
                border: 1px solid #24344a;
                border-radius: 13px;
            }
            QGroupBox {
                margin-top: 12px;
                padding: 16px 14px 12px 14px;
                font-weight: 700;
                color: #dce7f3;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 14px;
                padding: 0 6px;
                color: #9fb0c5;
            }
            QLineEdit, QSpinBox {
                background: #0b1422;
                border: 1px solid #2b3c52;
                border-radius: 8px;
                padding: 10px 11px;
                color: #e8f0f8;
                selection-background-color: #147b68;
            }
            QLineEdit:focus, QSpinBox:focus { border: 1px solid #35b99a; }
            QPushButton {
                background: #1b2a3e;
                border: 1px solid #344961;
                border-radius: 8px;
                padding: 9px 15px;
                color: #e5edf7;
                font-weight: 650;
            }
            QPushButton:hover { background: #263a52; border-color: #4b6683; }
            QPushButton:disabled { color: #627187; background: #172234; border-color: #26354a; }
            QPushButton#primaryButton {
                background: #087f68;
                border: 1px solid #10977d;
                color: white;
                padding: 11px 20px;
                font-size: 10.5pt;
            }
            QPushButton#primaryButton:hover { background: #0a967b; }
            QPushButton#stopButton {
                background: #3a202b;
                border: 1px solid #744052;
                color: #ffc6d0;
            }
            QPushButton#stopButton:hover { background: #512736; }
            QPushButton#subtleButton {
                background: transparent;
                border: 1px solid #344961;
                color: #aebed0;
            }
            QProgressBar {
                background: #0a1422;
                border: 1px solid #2a3b50;
                border-radius: 7px;
                height: 14px;
                text-align: center;
                color: transparent;
            }
            QProgressBar::chunk { background: #19a889; border-radius: 6px; }
            QTextEdit {
                background: #08111e;
                border: 1px solid #26384e;
                border-radius: 9px;
                padding: 10px;
                color: #c9d6e5;
                selection-background-color: #176b57;
                font-family: 'JetBrains Mono', 'Consolas', monospace;
                font-size: 9pt;
            }
            QSpinBox::up-button, QSpinBox::down-button { width: 18px; }
        """)

        root = QWidget()
        self.setCentralWidget(root)
        main_layout = QVBoxLayout(root)
        main_layout.setContentsMargins(28, 24, 28, 22)
        main_layout.setSpacing(16)

        # Header
        header = QHBoxLayout()
        heading = QVBoxLayout()
        eyebrow = QLabel("EMAIL VERIFICATION / WORKSPACE")
        eyebrow.setObjectName("eyebrow")
        title = QLabel("CPA Email Validator")
        title.setObjectName("mainTitle")
        # subtitle = QLabel("A focused workspace for DNS/MX checks and best-effort SMTP validation.")
        # subtitle.setContentsMargins(0, 0, 0, 15)
        # subtitle.setObjectName("muted")
        # subtitle.setWordWrap(True)
        heading.addWidget(eyebrow)
        heading.addWidget(title)
        # heading.addWidget(subtitle)
        header.addLayout(heading)
        header.addStretch(1)
        self.status_badge = QLabel("●  READY")
        self.status_badge.setAlignment(Qt.AlignCenter)
        self.status_badge.setStyleSheet(
            "background:#12352f; color:#66e0bd; border:1px solid #1d5b4e;"
            "border-radius:12px; padding:9px 14px; font-weight:700;"
        )
        header.addWidget(self.status_badge, 0, Qt.AlignTop)
        main_layout.addLayout(header)

        # File selection panel
        files_group = QGroupBox("INPUT & OUTPUT")
        files_group.setMinimumHeight(160)

        files_grid = QGridLayout(files_group)
        files_grid.setContentsMargins(15, 25, 15, 15)
        files_grid.setHorizontalSpacing(12)
        files_grid.setVerticalSpacing(14)

        # Source file
        self.input_edit = QLineEdit()
        self.input_edit.setPlaceholderText(
            "Choose a .txt file or CSV with an 'email' column"
        )
        self.input_edit.setReadOnly(True)
        self.input_edit.setMinimumHeight(42)

        browse_input = QPushButton("Browse…")
        browse_input.setMinimumHeight(42)
        browse_input.clicked.connect(self.choose_input)

        # Output folder
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText(
            "Choose where result CSV files will be saved"
        )
        self.output_edit.setReadOnly(True)
        self.output_edit.setMinimumHeight(42)

        browse_output = QPushButton("Browse…")
        browse_output.setMinimumHeight(42)
        browse_output.clicked.connect(self.choose_output)

        # Add widgets to grid
        files_grid.addWidget(QLabel("SOURCE FILE"), 0, 0)
        files_grid.addWidget(self.input_edit, 0, 1)
        files_grid.addWidget(browse_input, 0, 2)

        files_grid.addWidget(QLabel("OUTPUT FOLDER"), 1, 0)
        files_grid.addWidget(self.output_edit, 1, 1)
        files_grid.addWidget(browse_output, 1, 2)

        # Column sizing
        files_grid.setColumnStretch(0, 0)
        files_grid.setColumnStretch(1, 1)
        files_grid.setColumnStretch(2, 0)

        main_layout.addWidget(files_group)
        # main_layout.addSpacing(60)

        # Settings and action buttons
        controls = QHBoxLayout()
        settings_group = QGroupBox("VALIDATION SETTINGS")
        settings_layout = QHBoxLayout(settings_group)
        settings_layout.addWidget(QLabel("Concurrent Threads"))
        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, MAX_WORKERS)
        self.workers_spin.setValue(DEFAULT_WORKERS)
        self.workers_spin.setToolTip(
            "Keep concurrency modest. High SMTP concurrency can trigger recipient-server throttling."
        )
        settings_layout.addWidget(self.workers_spin)
        
        settings_layout.addStretch(1)
        controls.addWidget(settings_group, 1)

        actions = QVBoxLayout()
        actions.addStretch(1)
        action_row = QHBoxLayout()
        self.start_button = QPushButton("▶  Start validation")
        self.start_button.setObjectName("primaryButton")
        self.start_button.clicked.connect(self.handle_start_pause)

        # self.pause_button = QPushButton("⏸ Pause")
        # self.pause_button.setEnabled(False)
        # self.pause_button.clicked.connect(self.toggle_pause)
        # settings_layout.addWidget(self.pause_button)

        self.stop_button = QPushButton("■  Stop")
        self.stop_button.setObjectName("stopButton")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_validation)
        action_row.addWidget(self.start_button)
        action_row.addWidget(self.stop_button)
        actions.addLayout(action_row)
        actions.addStretch(1)
        controls.addLayout(actions)
        main_layout.addLayout(controls)

        # Live metric cards
        metrics = QGridLayout()
        metrics.setSpacing(12)
        self.valid_value = self.make_metric_card(
            metrics, 0, "VALID", "0",
            "#45d6a5",
            "Accepted by SMTP and not identified as catch-all"
        )

        self.invalid_value = self.make_metric_card(
            metrics, 1, "INVALID", "0",
            "#ff7185",
            "Rejected or missing valid mail routing"
        )

        self.unknown_value = self.make_metric_card(
            metrics, 2, "UNKNOWN", "0",
            "#f4bd50",
            "Inconclusive or policy-restricted result"
        )

        self.processed_value = self.make_metric_card(
            metrics, 3, "PROCESSED", "0",
            "#72a7ff",
            "Emails completed so far"
        )
        main_layout.addLayout(metrics)

        # Progress panel
        progress_panel = QFrame()
        progress_panel.setObjectName("panel")
        progress_layout = QVBoxLayout(progress_panel)
        progress_layout.setContentsMargins(17, 14, 17, 15)
        progress_layout.setSpacing(10)
        progress_top = QHBoxLayout()
        progress_heading = QLabel("VALIDATION PROGRESS:")
        progress_heading.setObjectName("sectionTitle")
        self.percent_label = QLabel("0%")
        self.percent_label.setStyleSheet("color:#62daba; font-weight:750; font-size:14pt;")
        progress_top.addWidget(progress_heading)
        progress_top.addStretch(1)
        progress_top.addWidget(self.percent_label)
        progress_layout.addLayout(progress_top)
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        progress_layout.addWidget(self.progress_bar)
        progress_bottom = QHBoxLayout()
        self.progress_label = QLabel("Ready — select a file to begin.")
        self.progress_label.setObjectName("muted")
        self.speed_label = QLabel("0 emails/min")
        self.speed_label.setObjectName("muted")
        progress_bottom.addWidget(self.progress_label, 1)
        progress_bottom.addWidget(self.speed_label)
        progress_layout.addLayout(progress_bottom)
        main_layout.addWidget(progress_panel)

        # Activity log
        log_header = QHBoxLayout()
        log_title = QLabel("ACTIVITY LOG:")
        log_title.setObjectName("sectionTitle")
        # log_hint = QLabel("Live validation events")
        # log_hint.setObjectName("muted")
        log_header.addWidget(log_title)
        log_header.addSpacing(8)
        # log_header.addWidget(log_hint)
        log_header.addStretch(1)
        clear_log = QPushButton("Clear log")
        clear_log.setObjectName("subtleButton")
        clear_log.clicked.connect(self.log_box_clear)
        log_header.addWidget(clear_log)
        main_layout.addLayout(log_header)
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setPlaceholderText("Validation activity will appear here…")
        self.log_box.document().setMaximumBlockCount(3000)
        main_layout.addWidget(self.log_box, 1)

        note = QLabel(
            "Note: SMTP validation is best-effort and cannot conclusively confirm mailbox existence. "
            "Server policies, throttling, and network restrictions may produce UNKNOWN results. "
            "Only VALID and INVALID results are saved; UNKNOWN results are omitted from both CSV files. "
            "Validate only addresses you are authorized to check and respect recipient-server policies."
        )
        note.setObjectName("muted")
        note.setWordWrap(True)
        note.setStyleSheet("color:#8192a8; font-size:8.5pt;")
        main_layout.addWidget(note)

    def make_metric_card(self, grid, column, title, value, accent, description):
        card = QFrame()
        card.setObjectName("panel")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(15, 12, 15, 12)
        card_layout.setSpacing(5)
        label = QLabel(title)
        label.setStyleSheet(f"color:{accent}; font-size:9pt; font-weight:750; letter-spacing:1px;")
        number = QLabel(value)
        number.setStyleSheet("color:#f2f7fc; font-size:25pt; font-weight:750;")
        detail = QLabel(description)
        detail.setObjectName("muted")
        detail.setWordWrap(True)
        detail.setStyleSheet("font-size:8pt; color:#8fa1b7;")
        card_layout.addWidget(label)
        card_layout.addWidget(number)
        card_layout.addWidget(detail)
        grid.addWidget(card, 0, column)
        return number

    def log_box_clear(self):
        self.log_box.clear()

    def choose_input(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select email list",
            "",
            "Email lists (*.txt *.csv);;All files (*)",
        )
        if path:
            self.input_path = path
            self.input_edit.setText(path)

            if not self.output_dir:
                import os
                self.output_dir = os.path.dirname(path)
                self.output_edit.setText(self.output_dir)

    def choose_output(self):
        path = QFileDialog.getExistingDirectory(
            self, "Select output folder", self.output_dir or ""
        )
        if path:
            self.output_dir = path
            self.output_edit.setText(path)

    def append_log(self, message):
        self.log_box.append(message)

    def start_validation(self):
        if self.worker and self.worker.isRunning():
            return

        if not self.input_path:
            QMessageBox.warning(self, "Missing input", "Please select an input file.")
            return

        if not self.output_dir:
            QMessageBox.warning(self, "Missing output", "Please select an output folder.")
            return

        self.started_at = time.monotonic()
        self.last_completed = 0
        self.total_emails = 0
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(1)
        self.percent_label.setText("0%")
        self.progress_label.setText("Starting validation…")
        self.speed_label.setText("0 emails/min")
        self.valid_value.setText("0")
        self.invalid_value.setText("0")
        self.unknown_value.setText("0")
        self.processed_value.setText("0")
        self.log_box.clear()
        self.status_badge.setText("●  RUNNING")
        self.status_badge.setStyleSheet(
            "background:#12352f; color:#66e0bd; border:1px solid #1d5b4e;"
            "border-radius:12px; padding:9px 14px; font-weight:700;"
        )

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(True)
        self.workers_spin.setEnabled(False)

        self.worker = ValidationWorker(
            self.input_path,
            self.output_dir,
            self.workers_spin.value(),
        )
        self.worker.progress.connect(self.on_progress)
        self.worker.counts_updated.connect(self.on_counts_updated)
        self.worker.log.connect(self.append_log)
        self.worker.finished_summary.connect(self.on_finished)
        self.worker.failed.connect(self.on_failed)
        self.worker.start()

        self.start_button.setEnabled(True)
        self.start_button.setText("⏸  Pause")
        self.stop_button.setEnabled(True)

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(True)

    def stop_validation(self):
        if self.worker and self.worker.isRunning():
            self.worker.request_stop()
            self.stop_button.setEnabled(False)
            self.progress_label.setText("Stopping after current network requests…")
            self.status_badge.setText("●  STOPPING")
            self.append_log("Stop requested.")

            # self.pause_button.setEnabled(False)
            # self.pause_button.setText("⏸  Pause")
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)

    def on_progress(self, completed, total, email, status):
        self.total_emails = total
        self.last_completed = completed
        self.progress_bar.setMaximum(max(total, 1))
        self.progress_bar.setValue(min(completed, total))
        percent = int((completed / total) * 100) if total else 0
        self.percent_label.setText(f"{percent}%")
        self.processed_value.setText(f"{completed:,}")
        self.progress_label.setText(
            f"{completed:,} / {total:,}  ·  {email}  ·  {status}"
        )
        elapsed = max(time.monotonic() - self.started_at, 0.001) if self.started_at else 0.001
        rate = (completed / elapsed) * 60
        self.speed_label.setText(f"{rate:,.1f} emails/min")
        self.append_log(f"{email}  →  {status}")

    def on_counts_updated(self, valid, invalid, unknown):
        self.valid_value.setText(f"{valid:,}")
        self.invalid_value.setText(f"{invalid:,}")
        self.unknown_value.setText(f"{unknown:,}")

    def on_finished(self, valid, invalid, unknown, stopped):
        self.valid_value.setText(f"{valid:,}")
        self.invalid_value.setText(f"{invalid:,}")
        self.unknown_value.setText(f"{unknown:,}")
        self.processed_value.setText(f"{valid + invalid + unknown:,}")

        self.append_log("")
        self.append_log("========== VALIDATION SUMMARY ==========")
        self.append_log(f"Valid:   {valid:,}")
        self.append_log(f"Invalid: {invalid:,}")
        self.append_log(f"Unknown: {unknown:,}")
        self.append_log("Stopped by user." if stopped else "Completed.")

        self.progress_label.setText("Validation stopped." if stopped else "Validation completed successfully.")
        self.status_badge.setText("●  STOPPED" if stopped else "●  COMPLETED")
        self.status_badge.setStyleSheet(
            "background:#332b1a; color:#f4c96b; border:1px solid #66502a;"
            "border-radius:12px; padding:9px 14px; font-weight:700;"
        ) if stopped else self.status_badge.setStyleSheet(
            "background:#12352f; color:#66e0bd; border:1px solid #1d5b4e;"
            "border-radius:12px; padding:9px 14px; font-weight:700;"
        )
        self.set_idle()

        QMessageBox.information(
            self,
            "Validation finished",
            f"Valid: {valid:,}\nInvalid: {invalid:,}\nUnknown: {unknown:,}\n\n"
            f"Output folder:\n{self.output_dir}",
        )

        self.start_button.setEnabled(True)
        self.start_button.setText("▶  Start validation")
        self.stop_button.setEnabled(False)

    def on_failed(self, message):
        self.append_log(f"ERROR: {message}")
        self.progress_label.setText("Validation error — see activity log.")
        self.status_badge.setText("●  ERROR")
        self.status_badge.setStyleSheet(
            "background:#3a202b; color:#ff9baa; border:1px solid #744052;"
            "border-radius:12px; padding:9px 14px; font-weight:700;"
        )
        self.set_idle()
        QMessageBox.critical(self, "Validation error", message)

    def set_idle(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.workers_spin.setEnabled(True)

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            answer = QMessageBox.question(
                self,
                "Validation running",
                "Validation is still running. Stop it and close the application?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer == QMessageBox.Yes:
                self.worker.stop()
                self.worker.wait()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()

    def toggle_pause(self):
        self.worker.toggle_pause()

        if self.worker.pause_event.is_set():
            self.start_button.setText("⏸  Pause")
            self.append_log("Validation resumed.")
        else:
            self.start_button.setText("▶  Resume")
            self.append_log("Validation paused.")

    def handle_start_pause(self):
        if not self.worker or not self.worker.isRunning():
            self.start_validation()
            return

        self.toggle_pause()


def main():
    app = QApplication(sys.argv)
    window = EmailValidatorWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
