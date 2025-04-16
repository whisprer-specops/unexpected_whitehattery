#!/usr/bin/env python3
import os
import time
from urllib.parse import quote

# CONFIG: set to your actual site root URL
SITE_ROOT = "https://example.com"

# CONFIG: path to website files
WEB_DIR = "."

def get_lastmod(filepath):
    ts = os.path.getmtime(filepath)
    return time.strftime("%Y-%m-%d", time.gmtime(ts))

def build_url(path):
    path = path.replace("\\", "/")  # windows-safe
    quoted_path = quote(path.lstrip("./"))
    return f"{SITE_ROOT}/{quoted_path}"

def main():
    sitemap = ['<?xml version="1.0" encoding="UTF-8"?>']
    sitemap.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')

    for root, _, files in os.walk(WEB_DIR):
        for file in files:
            if file.endswith(".html"):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, WEB_DIR)
                url = build_url(rel_path)
                lastmod = get_lastmod(full_path)

                sitemap.append("  <url>")
                sitemap.append(f"    <loc>{url}</loc>")
                sitemap.append(f"    <lastmod>{lastmod}</lastmod>")
                sitemap.append("  </url>")

    sitemap.append('</urlset>')

    with open("sitemap.xml", "w", encoding="utf-8") as f:
        f.write("\n".join(sitemap))

    print("✅ sitemap.xml generated successfully.")

if __name__ == "__main__":
    main()
