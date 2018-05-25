#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import MAXDB_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.maxdb.enumeration import Enumeration
from plugins.dbms.maxdb.filesystem import Filesystem
from plugins.dbms.maxdb.fingerprint import Fingerprint
from plugins.dbms.maxdb.syntax import Syntax
from plugins.dbms.maxdb.takeover import Takeover
from plugins.generic.misc import Miscellaneous

class A(Syntax):
    def __init__(self):
        Syntax.__init__(self)


class B(A, Fingerprint):
    def __init__(self):
        Fingerprint.__init__(self)


class C(B, Enumeration):
    def __init__(self):
        Enumeration.__init__(self)


class D(C, Filesystem):
    def __init__(self):
        Filesystem.__init__(self)


class E(D, Miscellaneous):
    def __init__(self):
        Miscellaneous.__init__(self)


class F(E, Takeover):
    def __init__(self):
        Takeover.__init__(self)


class MaxDBMap(F):
    """
    This class defines SAP MaxDB methods
    """

    def __init__(self):
        self.excludeDbsList = MAXDB_SYSTEM_DBS

    unescaper[DBMS.MAXDB] = Syntax.escape
