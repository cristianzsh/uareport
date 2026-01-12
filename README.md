# UserAssistReport

`uareport` is a Python command-line tool to parse UserAssist artifacts from Windows registry hives (`NTUSER.DAT`).  
It walks a directory, finds `NTUSER.DAT` files, decodes UserAssist entries (ROT-13), and outputs:

* User (folder name)  
* Executed application/shortcut name  
* Run count  
* Last run time  
* Focus count  
* Focus time (ms)  

The script supports optional filtering by user and can export results to CSV.

<img src="screenshot.png"/>

# Background

`UserAssist` artifacts store Windows user activity data that is especially useful for identifying evidence of program execution and are located under:

```
NTUSER.dat\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
```

Each value name is **ROT-13-encoded** and the binary data includes run count, focus count/time, and last execution time.

# Requirements

- Python 3.7+  
- `python-registry` library  
- `tabulate` (for table formatting)

Install the dependencies with:

```
pip install python-registry tabulate
```

# Usage

Display parsed UserAssist output:

```
python3 parse_userassist.py -d /path/to/evidence
```

Filter by specific user (case-insensitive):

```
python3 parse_userassist.py -d /path/to/evidence/Users --user alice
```

Save results to CSV:

```
python3 parse_userassist.py -d /path/to/evidence/Users --csv output.csv
```

Combine filters and CSV export:

```
python3 parse_userassist.py -d /path/to/evidence/Users --user bob --csv bob_userassist.csv
```

The script assumes each user’s NTUSER.DAT is located inside a folder named after the user.

## Building executables

A `build.sh` script is provided to generate standalone binaries for both Linux and Windows (via Wine).

```bash
chmod +x build.sh
./build.sh
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
