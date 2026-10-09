#!/usr/bin/env python3
"""Check repository Markdown paths/anchors against tracked files, without network.

Supports the repository's inline Markdown links, reference definitions and ATX
headings. Fenced code is excluded. External URLs are counted, not validated;
HTTP availability and remote fragments require a separate authenticated audit.
"""
import html
from pathlib import Path
import posixpath
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit


def prose(text):
    output, fence = [], None
    for line in text.splitlines():
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if match:
            marker = match[1]
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            output.append('')
        else:
            output.append(line if fence is None else '')
    return '\n'.join(output)


def anchors(text):
    result, used = set(), set()
    for line in prose(text).splitlines():
        heading = re.match(r'^\s{0,3}#{1,6}\s+(.+?)(?:\s+#+)?$', line)
        if heading:
            title = re.sub(r'\[([^]]+)\]\([^)]+\)', r'\1', heading[1])
            title = html.unescape(re.sub(r'<[^>]+>', '', title)).lower()
            slug = ''.join(c for c in title if c.isalnum() or c in '_- ')
            slug = slug.replace(' ', '-')
            candidate, index = slug, 0
            while candidate in used:
                index += 1
                candidate = f'{slug}-{index}'
            used.add(candidate)
            result.add(candidate)
        result.update(re.findall(r'<a\s+(?:id|name)=["\']([^"\']+)', line))
    return result


def links(text):
    for number, line in enumerate(prose(text).splitlines(), 1):
        for match in re.finditer(r'\]\((?:<([^>]+)>|([^\s)]+))(?:\s+["\'][^"\']*["\'])?\)', line):
            yield number, match[1] or match[2]
        definition = re.match(r'^\s{0,3}\[[^]]+\]:\s*(?:<([^>]+)>|([^\s]+))', line)
        if definition:
            yield number, definition[1] or definition[2]


def check(root, tracked):
    files = set(tracked)
    directories = {str(parent) for f in files for parent in Path(f).parents}
    errors, local, external = [], 0, 0
    for name in sorted(f for f in files if f.endswith('.md')):
        for line, link in links((root / name).read_text()):
            url = urlsplit(link)
            if url.scheme or url.netloc:
                external += 1
                continue
            local += 1
            target = posixpath.normpath(posixpath.join(posixpath.dirname(name), unquote(url.path))) if url.path else name
            if target not in files and target not in directories:
                errors.append(f'{name}:{line}: missing tracked target: {link}')
            elif url.fragment and target.endswith('.md') and target in files:
                if unquote(url.fragment) not in anchors((root / target).read_text()):
                    errors.append(f'{name}:{line}: missing heading: {link}')
    return errors, local, external


def main():
    root = Path(__file__).resolve().parents[1]
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root).decode().split('\0')[:-1]
    errors, local, external = check(root, tracked)
    for error in errors:
        print(error)
    print(f'{local} local links checked; {external} external links excluded; {len(errors)} errors')
    return bool(errors)


if __name__ == '__main__':
    sys.exit(main())
