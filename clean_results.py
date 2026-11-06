from pathlib import Path

RESULT_FILES = [
    "filtered_emails.csv",
    "filtered_emails.xlsx",
    "rejected_emails.csv",
    "rejected_emails.xlsx",
    "unknown_emails.csv",
    "unknown_emails.xlsx",
    "verified_emails.csv",
    "verified_emails.xlsx",
]

folder = Path(__file__).resolve().parent

deleted = 0

for filename in RESULT_FILES:
    file_path = folder / filename

    if file_path.is_file():
        file_path.unlink()
        print(f"Deleted: {filename}")
        deleted += 1

print(f"\nCleanup complete: {deleted}/8 result files deleted.")