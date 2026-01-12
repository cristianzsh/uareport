#!/usr/bin/env python3

"""
uareport: parser for the UserAssist forensic evidence.
by Cristian Souza (cristianmsbr@gmail.com)
"""

import os
import argparse
import csv
import datetime
import codecs
from Registry import Registry
from tabulate import tabulate

VERSION = "0.0.1"

def decode_rot13(s: str) -> str:
    try:
        return codecs.decode(s, "rot_13")
    except Exception:
        return s

def filetime_to_dt(filetime: int):
    """Convert Windows FILETIME to human datetime."""
    if filetime == 0:
        return None
    us = filetime / 10
    dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=us)
    return dt

def parse_userassist(hive_file):
    records = []
    try:
        hive = Registry.Registry(hive_file)
        root_key = hive.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
    except Exception:
        return records

    for guid_key in root_key.subkeys():
        try:
            count_key = guid_key.subkey("Count")
        except Exception:
            continue

        for v in count_key.values():
            raw_name = v.name()
            decoded_name = decode_rot13(raw_name)

            raw_data = v.value()
            if not isinstance(raw_data, (bytes, bytearray)) or len(raw_data) < 68:
                continue

            run_count = int.from_bytes(raw_data[4:8], "little")
            focus_count = int.from_bytes(raw_data[8:12], "little")
            focus_time = int.from_bytes(raw_data[12:16], "little")

            last_run_ft = int.from_bytes(raw_data[60:68], "little")
            last_run_dt = filetime_to_dt(last_run_ft)

            records.append({
                "Artifact": decoded_name,
                "RunCount": run_count,
                "LastRun": last_run_dt,
                "FocusCount": focus_count,
                "FocusTime": focus_time
            })

    return records

def main():
    parser = argparse.ArgumentParser(description="Parse UserAssist from NTUSER.DAT files in a directory")
    parser.add_argument("-d", "--directory", required=True, help="Directory to walk")
    parser.add_argument("--user", help="Filter by specific user (case-insensitive)")
    parser.add_argument("--csv", help="Save output to CSV")
    parser.add_argument('-V', '--version', action='version',
                        version=f"uareport {VERSION} by Cristian Souza")
    args = parser.parse_args()

    all_rows = []

    for root, dirs, files in os.walk(args.directory):
        for file in files:
            if file.lower() == "ntuser.dat":
                user = os.path.basename(root.rstrip(os.sep))

                # Apply user filter
                if args.user and user.lower() != args.user.lower():
                    continue

                hive_path = os.path.join(root, file)
                ua_records = parse_userassist(hive_path)

                for r in ua_records:
                    all_rows.append([
                        user,
                        r["Artifact"],
                        r["RunCount"],
                        r["LastRun"].strftime("%Y-%m-%d %H:%M:%S") if r["LastRun"] else "",
                        r["FocusCount"],
                        r["FocusTime"]
                    ])

    if not all_rows:
        print("No UserAssist records found" +
              (f" for user '{args.user}'" if args.user else "") + ".")
        return

    headers = ["User", "Artifact", "Run Count", "Last Run Time", "Focus Count", "Focus Time (ms)"]
    print("\n" + tabulate(all_rows, headers=headers, tablefmt="grid") + "\n")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            writer.writerows(all_rows)
        print(f"CSV saved: {args.csv}")

if __name__ == "__main__":
    main()
