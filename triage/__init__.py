"""Turn scanner findings into prioritised, documented GitHub issues.

Every finding gets a CVSS 3.1 base score. Dependency advisories carry a
published score. Code findings are scored from a reviewed CWE to vector table,
the same way an NVD analyst scores a new CVE: assign the vector, compute the
score. The P1 to P4 priority is derived from that score.
"""
