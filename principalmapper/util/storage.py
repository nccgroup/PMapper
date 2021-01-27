"""Code for handling the process of storing or retrieving data to/from disk"""

#  Copyright (c) NCC Group and Erik Steringer 2019. This file is part of Principal Mapper.
#
#      Principal Mapper is free software: you can redistribute it and/or modify
#      it under the terms of the GNU Affero General Public License as published by
#      the Free Software Foundation, either version 3 of the License, or
#      (at your option) any later version.
#
#      Principal Mapper is distributed in the hope that it will be useful,
#      but WITHOUT ANY WARRANTY; without even the implied warranty of
#      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#      GNU Affero General Public License for more details.
#
#      You should have received a copy of the GNU Affero General Public License
#      along with Principal Mapper.  If not, see <https://www.gnu.org/licenses/>.

import os
import os.path
import sys


def get_storage_root():
    """Locates and returns a path to the storage root, depending on OS. If the path does not exist yet, it is
    created.

    First, it checks for the environment variable PMAPPER_STORAGE and uses that if set. Then, it goes for
    per-platform locations recommended by:
    https://stackoverflow.com/questions/3373948/equivalents-of-xdg-config-home-and-xdg-data-home-on-mac-os-x
    """
    platform = sys.platform
    pmapper_env_var = os.getenv('PMAPPER_STORAGE')
    result = None
    if pmapper_env_var is not None:
        result = pmapper_env_var
    elif platform == 'win32' or platform == 'cygwin':
        # Windows: file root at %APPDATA%\principalmapper\
        appdatadir = os.getenv('APPDATA')
        if appdatadir is None:
            raise ValueError('%APPDATA% was unexpectedly not set')
        result = os.path.join(appdatadir, 'principalmapper')
    elif platform == 'linux' or platform == 'freebsd' or platform.startswith('openbsd'):
        # Linux/FreeBSD: follow XDG convention: $XDG_DATA_HOME/principalmapper/
        # if $XDG_DATA_HOME isn't set, default to ~/.local/share/principalmapper/
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


def get_default_graph_path(account_or_org: str):
    """Returns a path to a given account or organization by the provided string."""
    return os.path.join(get_storage_root(), account_or_org)
