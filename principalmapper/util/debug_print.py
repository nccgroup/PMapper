"""Code for handling printing to console depending on if debugging is enabled"""

import sys


def dprint(debugging: bool, message: str) -> None:
    """Prints message to console if debugging"""
    if debugging:
        sys.stderr.write(message)
        sys.stderr.write("\n")
