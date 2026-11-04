import csv
import re
import sys
import time
import random
import string
import socket
import smtplib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import dns.exception
import dns.name

from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit,
    QPushButton, QFileDialog, QSpinBox, QProgressBar, QTextEdit,
    QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox, QMessageBox
)


# -------------------- CONFIGURATION --------------------

SMTP_TIMEOUT = 8
DNS_TIMEOUT = 5
DEFAULT_WORKERS = 3
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


def smtp_check(email, mx_records, stop_event=None):
    """A best-effort SMTP recipient test. Responses are not definitive."""
    for mx in mx_records:
        if stop_event and stop_event.is_set():
            return "UNKNOWN"

        server = None
        try:
            server = smtplib.SMTP(timeout=SMTP_TIMEOUT)
            server.connect(mx, 25)
            server.ehlo()
            server.mail(SENDER_EMAIL)

            code, _message = server.rcpt(email)

            if code in (250, 251):
                return "ACCEPTED"

            if code in (550, 551, 553):
                return "REJECTED"

            # 4xx, policy blocks, and other responses are inconclusive.
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
    log = pyqtSignal(str)
    finished_summary = pyqtSignal(int, int, int, bool)
    failed = pyqtSignal(str)
    counts_updated = pyqtSignal(int, int, int)

    def __init__(self, input_path, output_dir, max_workers):
        super().__init__()
        self.input_path = input_path
        self.output_dir = output_dir
        self.max_workers = max_workers
        self.stop_event = threading.Event()

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
                        executor.submit(verify_email, email, self.stop_event): email
                        for email in emails
                    }

                    for future in as_completed(futures):
                        if self.stop_event.is_set():
                            # Cancel tasks that have not started. Running SMTP
                            # requests finish or time out before the thread exits.
                            for pending in futures:
                                pending.cancel()

                        email = futures[future]
                        completed += 1

                        if future.cancelled():
                            continue

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
                            result["status"],
                        )

            stopped = self.stop_event.is_set()
            self.finished_summary.emit(
                valid_count, invalid_count, unknown_count, stopped
            )

        except Exception as exc:
            self.failed.emit(str(exc))


# -------------------- GUI --------------------

class EmailValidatorWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Email Validator")
        self.resize(850, 650)

        self.worker = None
        self.input_path = ""
        self.output_dir = ""

        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)

        title = QLabel("Email Validator")
        title.setStyleSheet("font-size: 22px; font-weight: bold;")
        layout.addWidget(title)

        subtitle = QLabel(
            "DNS/MX lookup and best-effort SMTP checks. "
            # "SMTP responses cannot conclusively prove mailbox existence."
        )
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        files_group = QGroupBox("Files")
        files_form = QFormLayout(files_group)

        input_row = QHBoxLayout()
        self.input_edit = QLineEdit()
        self.input_edit.setPlaceholderText("Select an .txt or .csv file")
        self.input_edit.setReadOnly(True)
        browse_input = QPushButton("Browse…")
        browse_input.clicked.connect(self.choose_input)
        input_row.addWidget(self.input_edit)
        input_row.addWidget(browse_input)
        files_form.addRow("Input file:", input_row)

        output_row = QHBoxLayout()
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("Select output folder")
        self.output_edit.setReadOnly(True)
        browse_output = QPushButton("Browse…")
        browse_output.clicked.connect(self.choose_output)
        output_row.addWidget(self.output_edit)
        output_row.addWidget(browse_output)
        files_form.addRow("Output folder:", output_row)

        layout.addWidget(files_group)

        settings_group = QGroupBox("Settings")
        settings_form = QFormLayout(settings_group)

        self.workers_spin = QSpinBox()
        self.workers_spin.setRange(1, MAX_WORKERS)
        self.workers_spin.setValue(DEFAULT_WORKERS)
        self.workers_spin.setToolTip(
            "Keep concurrency modest. High SMTP concurrency can trigger provider throttling."
        )
        settings_form.addRow("Concurrent workers:", self.workers_spin)

        layout.addWidget(settings_group)

        buttons = QHBoxLayout()
        self.start_button = QPushButton("Start validation")
        self.start_button.clicked.connect(self.start_validation)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_validation)
        buttons.addWidget(self.start_button)
        buttons.addWidget(self.stop_button)
        layout.addLayout(buttons)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        self.progress_label = QLabel("Ready")
        layout.addWidget(self.progress_label)

        counts = QHBoxLayout()
        self.valid_label = QLabel("Valid: 0")
        self.invalid_label = QLabel("Invalid: 0")
        self.unknown_label = QLabel("Unknown: 0")
        counts.addWidget(self.valid_label)
        counts.addWidget(self.invalid_label)
        counts.addWidget(self.unknown_label)
        layout.addLayout(counts)

        layout.addWidget(QLabel("Activity log:"))
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        layout.addWidget(self.log_box)

        note = QLabel(
            "Only VALID and INVALID results are written. UNKNOWN results are "
            "left out of both CSV files. Use this only for addresses you are "
            "authorized to validate, and respect recipient-server policies."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color: gray;")
        layout.addWidget(note)

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

        self.progress_bar.setValue(0)
        self.progress_label.setText("Starting…")
        self.valid_label.setText("Valid: 0")
        self.invalid_label.setText("Invalid: 0")
        self.unknown_label.setText("Unknown: 0")
        self.log_box.clear()

        self.start_button.setEnabled(False)
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

    def stop_validation(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.stop_button.setEnabled(False)
            self.progress_label.setText("Stopping after current network requests…")
            self.append_log("Stop requested.")

    def on_progress(self, completed, total, email, status):
        self.progress_bar.setMaximum(max(total, 1))
        self.progress_bar.setValue(min(completed, total))
        self.progress_label.setText(
            f"{completed:,} / {total:,} — {email} — {status}"
        )
        # Counts are also summarized when the worker completes.
        self.append_log(f"{email} -> {status}")

    def on_finished(self, valid, invalid, unknown, stopped):
        self.valid_label.setText(f"Valid: {valid:,}")
        self.invalid_label.setText(f"Invalid: {invalid:,}")
        self.unknown_label.setText(f"Unknown: {unknown:,}")

        self.append_log("")
        self.append_log("========== SUMMARY ==========")
        self.append_log(f"Valid:   {valid:,}")
        self.append_log(f"Invalid: {invalid:,}")
        self.append_log(f"Unknown: {unknown:,}")
        self.append_log("Stopped by user." if stopped else "Completed.")

        self.progress_label.setText("Stopped" if stopped else "Completed")
        self.set_idle()

        QMessageBox.information(
            self,
            "Validation finished",
            f"Valid: {valid:,}\nInvalid: {invalid:,}\nUnknown: {unknown:,}\n\n"
            f"Output folder:\n{self.output_dir}",
        )

    def on_failed(self, message):
        self.append_log(f"ERROR: {message}")
        self.progress_label.setText("Error")
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

    def on_counts_updated(self, valid, invalid, unknown):
        self.valid_label.setText(str(valid))
        self.invalid_label.setText(str(invalid))
        self.unknown_label.setText(str(unknown))

def main():
    app = QApplication(sys.argv)
    window = EmailValidatorWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
