# Security Policy

This repository contains an experimental intrusion detector. It does not
replace a maintained endpoint security product. Do not use the bundled
bootstrap model as the sole basis for blocking traffic.

Firewall changes are off by default. Never automate the
`--apply` confirmations from model output. Review the target, allowlist,
expiration cleanup, rollback state, and kill switch before any authorized
Windows firewall test. Signed model packages protect integrity and publisher
authenticity only when the trusted public key was obtained independently;
they do not prove model quality.

Feedback files, feature snapshots, benchmark and provenance reports, firewall
state, captures, private signing keys, and update test artifacts may contain
sensitive local data. `.gitignore` covers the standard output paths, but every
staged file still needs to be checked before committing.

Please report vulnerabilities privately through GitHub's **Report a
vulnerability** feature when available. Do not include real credentials,
private packet captures, personal data, or production network logs in a public
issue.
