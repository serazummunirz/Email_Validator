
import csv
import re
import sys
import time
import random
import string
import socket
import smtplib
import dns.resolver
import dns.exception
import dns.name
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_FILE = "emails.txt"
OUTPUT_FILE = "verified_emails.csv"

SENDER_EMAIL = "verify@example.com"
SMTP_TIMEOUT = 10
DELAY = 0
MAX_WORKERS = 5

# DNS resolver
resolver = dns.resolver.Resolver()
resolver.timeout = 5
resolver.lifetime = 10


def valid_syntax(email):
    pattern = r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return bool(re.match(pattern, email))



def get_mx_records(domain):
    try:
        domain = domain.strip().rstrip(".")

        if not domain or ".." in domain or domain.startswith("."):
            return None

        # Validate DNS domain syntax
        dns.name.from_text(domain)

        answers = resolver.resolve(domain, "MX")

        records = sorted(
            answers,
            key=lambda record: record.preference
        )

        return [
            str(record.exchange).rstrip(".")
            for record in records
        ]

    except dns.resolver.NXDOMAIN:
        return None

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.name.EmptyLabel,
        dns.name.NameTooLong,
        dns.exception.SyntaxError,
        ValueError
    ):
        return None

    except Exception as e:
        print(f"DNS error for {domain}: {e}")
        return []



def random_email(domain):
    username = ''.join(
        random.choices(string.ascii_lowercase + string.digits, k=16)
    )
    return f"{username}@{domain}"


def smtp_check(email, mx_records):
    for mx in mx_records:
        server = None

        try:
            server = smtplib.SMTP(timeout=SMTP_TIMEOUT)
            server.connect(mx, 25)

            server.ehlo()
            server.mail(SENDER_EMAIL)

            code, message = server.rcpt(email)

            if code == 250 or code == 251:
                return "ACCEPTED"

            if code in (550, 551, 553):
                return "REJECTED"

            return "UNKNOWN"

        except (
            socket.timeout,
            socket.error,
            smtplib.SMTPException,
            OSError
        ):
            continue

        finally:
            if server:
                try:
                    server.quit()
                except Exception:
                    pass

    return "UNKNOWN"


def verify_email(email):
    email = email.strip().lower()

    result = {
        "email": email,
        "syntax": "INVALID",
        "mx": "UNKNOWN",
        "smtp": "UNKNOWN",
        "catch_all": "UNKNOWN",
        "status": "UNKNOWN"
    }

    if not valid_syntax(email):
        result["status"] = "INVALID"
        return result

    result["syntax"] = "VALID"

    domain = email.rsplit("@", 1)[1]

    mx_records = get_mx_records(domain)

    if mx_records is None:
        result["mx"] = "INVALID"
        result["status"] = "INVALID"
        return result

    if not mx_records:
        result["mx"] = "INVALID"
        result["status"] = "INVALID"
        return result

    result["mx"] = "VALID"

    smtp_result = smtp_check(email, mx_records)
    result["smtp"] = smtp_result

    if smtp_result == "REJECTED":
        result["status"] = "INVALID"
        return result

    if smtp_result == "UNKNOWN":
        return result

    # Test a random address to detect catch-all domains
    fake_email = random_email(domain)
    catch_result = smtp_check(fake_email, mx_records)

    if catch_result == "ACCEPTED":
        result["catch_all"] = "YES"
        result["status"] = "UNKNOWN"

    elif catch_result == "REJECTED":
        result["catch_all"] = "NO"
        result["status"] = "VALID"

    else:
        result["status"] = "UNKNOWN"

    return result


def load_emails(filename):
    emails = []

    if filename.lower().endswith(".csv"):
        with open(filename, "r", encoding="utf-8-sig", newline="") as file:
            reader = csv.DictReader(file)

            if not reader.fieldnames:
                return emails

            email_column = next(
                (col for col in reader.fieldnames if col.lower() == "email"),
                None
            )

            if not email_column:
                raise ValueError("CSV must contain an 'email' column.")

            for row in reader:
                if row.get(email_column):
                    emails.append(row[email_column].strip())

    else:
        with open(filename, "r", encoding="utf-8-sig") as file:
            emails = [
                line.strip()
                for line in file
                if line.strip()
            ]

    return list(dict.fromkeys(emails))




def main():
    input_file = sys.argv[1] if len(sys.argv) > 1 else INPUT_FILE

    emails = load_emails(input_file)

    total = len(emails)

    print(f"Loaded {total} unique emails.")
    print(f"Starting {MAX_WORKERS} workers...\n")

    fields = [
        "email",
        "syntax",
        "mx",
        "smtp",
        "catch_all",
        "status"
    ]

    valid_count = 0
    invalid_count = 0
    unknown_count = 0
    completed = 0

    with open(
        "verified_emails.csv",
        "w",
        newline="",
        encoding="utf-8"
    ) as valid_file, open(
        "rejected_emails.csv",
        "w",
        newline="",
        encoding="utf-8"
    ) as invalid_file:

        valid_writer = csv.DictWriter(
            valid_file,
            fieldnames=fields
        )

        invalid_writer = csv.DictWriter(
            invalid_file,
            fieldnames=fields
        )

        valid_writer.writeheader()
        invalid_writer.writeheader()

        with ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as executor:

            futures = {
                executor.submit(verify_email, email): email
                for email in emails
            }

            for future in as_completed(futures):

                email = futures[future]
                completed += 1

                try:
                    result = future.result()

                except Exception as e:
                    print(f"ERROR: {email} -> {e}")

                    result = {
                        "email": email,
                        "syntax": "UNKNOWN",
                        "mx": "UNKNOWN",
                        "smtp": "UNKNOWN",
                        "catch_all": "UNKNOWN",
                        "status": "UNKNOWN"
                    }

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

                print(
                    f"[{completed}/{total}] "
                    f"{email} -> {result['status']} "
                    f"| Valid: {valid_count} "
                    f"| Invalid: {invalid_count} "
                    f"| Unknown: {unknown_count}"
                )

    print("\n========== SUMMARY ==========")
    print(f"Total:    {total}")
    print(f"Valid:    {valid_count}")
    print(f"Invalid:  {invalid_count}")
    print(f"Unknown:  {unknown_count}")
    print("=============================")

    print("\nSaved:")
    print("verified_emails.csv")
    print("rejected_emails.csv")


if __name__ == "__main__":
    main()
