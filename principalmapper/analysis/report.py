"""Python code for putting together a report of findings. Holds the main Report class."""

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

import datetime as dt
from typing import List

from principalmapper.analysis.finding import Finding


class Report:
    """FindingsReport holds information about findings, and where the findings were pulled from. It also provides a
    utility function to convert the contents of the report to a dictionary object.
    """

    def __init__(self, account: str, date_and_time: dt.datetime, findings: List[Finding], source: str):
        self.account = account
        self.date_and_time = date_and_time
        self.findings = findings
        self.source = source

    def as_dictionary(self) -> dict:
        """Produces a dictionary representing this Report's contents."""
        return {
            'account': self.account,
            'date_and_time': self.date_and_time.isoformat(),
            'findings': [x.as_dictionary() for x in self.findings],
            'source': self.source
        }
