"""Code for handling the process of storing or retrieving data to/from disk"""

import os
import os.path
import sys


def get_storage_root():
    """Locates and returns a path to the storage root, depending on OS. If the path does not exist yet, it is
    created.

    Uses per-platform locations recommended by:
    https://stackoverflow.com/questions/3373948/equivalents-of-xdg-config-home-and-xdg-data-home-on-mac-os-x
    """
    platform = sys.platform
    result = None
    if platform == 'win32' or platform == 'cygwin':
        # Windows: file root at %APPDATA%\principalmapper\
        appdatadir = os.getenv('APPDATA')
        if appdatadir is None:
            raise ValueError('%APPDATA% was unexpectedly not set')
        result = os.path.join(appdatadir, 'principalmapper')
    elif platform == 'linux' or platform == 'freebsd':
        # Linux/FreeBSD: follow XDG convention: $XDG_DATA_HOME/principalmapper/
        appdatadir = os.getenv('XDG_DATA_HOME')
        if appdatadir is None:
            appdatadir = os.path.join(os.path.expanduser('~'), '.local', 'share')
        result = os.path.join(appdatadir, 'principalmapper')
    elif platform == 'darwin':
        # MacOS: follow MacOS convention: ~/Library/Application Support/com.nccgroup.principalmapper/
        appdatadir = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support')
        result = os.path.join(appdatadir, 'com.nccgroup.principalmapper')
    if not os.path.exists(result):
        os.makedirs(result, 0o700)
    return result
