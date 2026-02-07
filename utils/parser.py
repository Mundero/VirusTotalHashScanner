# parser.py
import argparse
import sys
from pathlib import Path
import psutil



def volume_exists(volume_name: str) -> bool:
    drives = set(d.device for d in psutil.disk_partitions())
    return volume_name in drives


def ask_user():
    print("No argument provided.")
    print("1 - Directory")
    print("2 - Volume")

    choice = input("Select option (1/2): ").strip()

    if choice == "1":
        return {"directory": input("Enter directory path: ").strip()}
    elif choice == "2":
        return {"volume": input("Enter volume name: ").strip()}
    else:
        print("Invalid choice.")
        sys.exit(1)



def get_args():
    parser = argparse.ArgumentParser(description="Example Tool")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-d", "--directory", type=str, help="Directory path")
    group.add_argument("-v", "--volume", type=str, help="Volume name")

    args = parser.parse_args()

    directory = args.directory
    volume = args.volume
    if not directory and not volume:
        user_input = ask_user()
        directory = user_input.get("directory")
        volume = user_input.get("volume")

    if directory:
        path = Path(directory)
        if not path.exists():
            raise ValueError("Directory does not exist.")
        else:
            return Path(directory)

    # ---- Volume validation ----
    if volume:
        if not volume_exists(volume):
            drives = ", ".join(d.device for d in psutil.disk_partitions())
            raise ValueError(f"Volume does not exist. Available: {drives}")
        else:
            return Path(volume)
