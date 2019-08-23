"""Code for handling printing to console depending on if debugging is enabled"""

import sys


def dprint(debugging: bool, message: str) -> None:
    """Prints message to console if debugging"""
    if debugging:
        sys.stderr.write(message)
        sys.stderr.write("\n")


def dwrite(debugging: bool, message: str) -> None:
    """Writes message to console if debugging (no newline at the end)"""
    if debugging:
        sys.stderr.write(message)
