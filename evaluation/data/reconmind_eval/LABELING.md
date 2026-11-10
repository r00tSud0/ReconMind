# ReconMind test set: labeling rules

`labels.jsonl` is the answer key for `findings.jsonl`. Each line gives one finding id, its correct MITRE ATT&CK technique IDs, and the rule that produced them.

The rules follow MITRE CTID's published method for mapping vulnerabilities to ATT&CK:
https://center-for-threat-informed-defense.github.io/mappings-explorer/about/methodology/cve-methodology

Every ID is checked against ATT&CK v20 (`reconmind/data/attack_techniques.json`): all are active, none revoked or deprecated.

Labels were drafted with AI assistance and reviewed by the author against these rules and MITRE's technique pages. They were written before any model was run on this set.

## Rules

**R1. Only what the finding text says.** No outside knowledge. If the text shows no exploit and no risk, the label set is empty. Models must learn to predict nothing for these.

**R2. A remote exploit is listed:** T1210 Exploitation of Remote Services. ReconMind only scans private internal networks, so these services are not public facing (T1190).

**R3. What each listed exploit does:**
* a. Command execution, backdoor, SQL injection: T1059
* b. Denial of service, or memory corruption with no stated execution (integer overflow, format string): T1499.004
* c. Information disclosure or memory leak: T1005
* d. Username enumeration: T1589
* e. Remote download and execute: T1105 plus T1059
* f. An exploit marked Local: T1068

**R4. Remote login services:** T1021 (SSH is T1021.004, VNC is T1021.005). Cleartext logins also get T1040 Network Sniffing.

**R5. Risk flags:**
* a. Unauthenticated root shell: T1059.004
* b. NFS exposed: T1135 plus T1039
* c. X11 exposed: T1113 plus T1056.001
* d. Java RMI registry exposed: T1210
* e. A service that runs commands or code for anyone who connects (distccd, Ruby DRb): T1210 plus T1059

## Coverage note

Of the 16 techniques used here, only 6 are among the 50 TRAM techniques Model B was trained on (T1210, T1005, T1113, T1056.001, T1068, T1105). Models are scored on all labels and, separately, on the TRAM 50 only.
