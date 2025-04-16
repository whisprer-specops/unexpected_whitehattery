#!/usr/bin/env python3
import os
import shutil

REPLACEMENT_FILE = "index.html"

def main():
    root_dir = os.getcwd()

    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename == "index.html":
                target_path = os.path.join(dirpath, filename)
                if os.path.abspath(target_path) == os.path.abspath(REPLACEMENT_FILE):
                    print(f"[skip] Skipping root index.html to avoid self-copy.")
                    continue
                print(f"[replacing] {target_path}")
                shutil.copy2(REPLACEMENT_FILE, target_path)

if __name__ == "__main__":
    main()
