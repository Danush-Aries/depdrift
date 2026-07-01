"""depdrift — a supply-chain DIFF for dependency lockfiles.

Given two dependency states (two lockfiles, or one repo at two git refs) depdrift
reports which dependencies were ADDED / REMOVED / UPGRADED (with semver
classification) and flags security & trust risk on the *newly-introduced* set:
known vulnerabilities (OSV.dev), typosquats, and abandonment.

Cross-ecosystem (PyPI + npm), keyless, and offline-testable.
"""

__version__ = "0.1.0"
