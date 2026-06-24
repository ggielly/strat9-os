#!/usr/bin/env python3
"""
Dead link checker for the Strat9 docs site.

Crawls all HTML files in the built site directory and checks:
- Internal links (relative and absolute) point to existing files
- Fragment identifiers (#...) reference existing anchors
- External links are reachable (optional, slow)

Usage:
    python3 tools/scripts/check-links.py [--external] [--site-dir build/docs-site]

Exit code: 0 if no broken links, 1 if any found.
"""

import argparse
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse


class LinkExtractor(HTMLParser):
    """Extract href and src attributes from HTML tags."""

    def __init__(self):
        super().__init__()
        self.links: list[tuple[str, str]] = []  # (tag, url)

    def handle_starttag(self, tag, attrs):
        for attr_name, attr_val in attrs:
            if attr_name in ("href", "src") and attr_val:
                self.links.append((tag, attr_val))


def check_internal_links(site_dir: Path) -> list[str]:
    """Check all internal links in HTML files under site_dir."""
    errors: list[str] = []

    html_files = sorted(site_dir.rglob("*.html"))
    if not html_files:
        print(f"No HTML files found in {site_dir}")
        return errors

    # Build anchor index: file -> set of anchor ids
    anchor_index: dict[Path, set[str]] = {}
    for html_file in html_files:
        anchors = set()
        try:
            content = html_file.read_text(encoding="utf-8", errors="replace")
            # Extract id="..." and name="..." anchors
            for match in re.finditer(r'id="([^"]+)"', content):
                anchors.add(match.group(1))
        except Exception:
            pass
        anchor_index[html_file] = anchors

    checked = 0
    broken = 0

    for html_file in html_files:
        # Skip rustdoc-generated source pages (they have line-range links
        # like #L25-30 that are valid in rustdoc but not resolvable as anchors)
        if "/src/" in str(html_file) or ".rs.html" in html_file.name:
            continue

        try:
            content = html_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        parser = LinkExtractor()
        try:
            parser.feed(content)
        except Exception:
            continue

        for tag, url in parser.links:
            # Skip external URLs, mailto, javascript, data URIs
            if url.startswith(("http://", "https://", "mailto:", "javascript:", "data:")):
                continue

            if url.startswith("#"):
                # Check fragment-only link
                fragment = url[1:]
                # Skip rustdoc line-range anchors (e.g., #L25-30, #functionname-5)
                if re.match(r'^L\d+-\d+$', fragment) or re.match(r'.*-\d+$', fragment):
                    continue
                if fragment and fragment not in anchor_index.get(html_file, set()):
                    rel = html_file.relative_to(site_dir)
                    errors.append(f"  {rel}: broken anchor #{fragment}")
                    broken += 1
                continue

            checked += 1

            # Split path and fragment
            if "#" in url:
                path_part, fragment = url.split("#", 1)
            else:
                path_part, fragment = url, ""

            if not path_part:
                continue

            # Resolve relative to the HTML file's directory
            target = (html_file.parent / path_part).resolve()

            if not target.exists():
                rel = html_file.relative_to(site_dir)
                errors.append(f"  {rel}: broken link -> {path_part}")
                broken += 1
            elif fragment:
                # Skip rustdoc line-range anchors
                if re.match(r'^L\d+-\d+$', fragment) or re.match(r'.*-\d+$', fragment):
                    continue
                # Check fragment exists in target file
                if target.suffix == ".html" and target in anchor_index:
                    if fragment not in anchor_index[target]:
                        rel = html_file.relative_to(site_dir)
                        errors.append(f"  {rel}: broken anchor #{fragment} in {path_part}")
                        broken += 1

    return errors


def check_external_links(site_dir: Path) -> list[str]:
    """Check external links (slow, requires network)."""
    import urllib.request
    import urllib.error

    errors: list[str] = []
    html_files = sorted(site_dir.rglob("*.html"))
    seen: set[str] = set()

    for html_file in html_files:
        try:
            content = html_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        parser = LinkExtractor()
        try:
            parser.feed(content)
        except Exception:
            continue

        for tag, url in parser.links:
            if not url.startswith(("http://", "https://")):
                continue
            if url in seen:
                continue
            seen.add(url)

            try:
                req = urllib.request.Request(url, method="HEAD")
                req.add_header("User-Agent", "Strat9-Docs-Link-Checker/1.0")
                urllib.request.urlopen(req, timeout=10)
            except (urllib.error.URLError, urllib.error.HTTPError, Exception) as e:
                rel = html_file.relative_to(site_dir)
                errors.append(f"  {rel}: external link broken -> {url} ({e})")

    return errors


def main():
    parser = argparse.ArgumentParser(description="Check for broken links in docs site")
    parser.add_argument(
        "--site-dir",
        default="build/docs-site",
        help="Path to built site directory (default: build/docs-site)",
    )
    parser.add_argument(
        "--external",
        action="store_true",
        help="Also check external links (slow, requires network)",
    )
    args = parser.parse_args()

    site_dir = Path(args.site_dir).resolve()
    if not site_dir.is_dir():
        print(f"Error: site directory not found: {site_dir}")
        sys.exit(1)

    print(f"Checking links in {site_dir} ...")

    errors = check_internal_links(site_dir)
    if errors:
        print(f"\nBroken internal links ({len(errors)} found):")
        for e in errors:
            print(e)
    else:
        print("  All internal links OK")

    ext_errors = []
    if args.external:
        print("\nChecking external links (this may take a while)...")
        ext_errors = check_external_links(site_dir)
        if ext_errors:
            print(f"\nBroken external links ({len(ext_errors)} found):")
            for e in ext_errors:
                print(e)
        else:
            print("  All external links OK")

    total = len(errors) + len(ext_errors)
    if total > 0:
        print(f"\nTotal broken links: {total}")
        sys.exit(1)
    else:
        print("\nAll links OK.")
        sys.exit(0)


if __name__ == "__main__":
    main()
