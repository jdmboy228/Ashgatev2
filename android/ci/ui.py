#!/usr/bin/env python3
"""Finds a view in a `uiautomator dump` and prints the centre of its bounds.

    ui.py DUMP text TEXT     a view whose text (or content-desc) is TEXT
    ui.py DUMP id ID         the first view with resource-id ID
Exits 1 when there is no such view.
"""
import re
import sys
import xml.etree.ElementTree as ET


def main():
    if len(sys.argv) != 4:
        sys.exit(1)
    dump, by, value = sys.argv[1:4]
    try:
        root = ET.parse(dump).getroot()
    except (ET.ParseError, OSError):
        sys.exit(1)
    for node in root.iter("node"):
        if by == "text":
            hit = value in (node.get("text"), node.get("content-desc"))
        else:
            hit = node.get("resource-id") == value
        if hit:
            x1, y1, x2, y2 = map(int, re.findall(r"\d+", node.get("bounds")))
            print((x1 + x2) // 2, (y1 + y2) // 2)
            return
    sys.exit(1)


main()
