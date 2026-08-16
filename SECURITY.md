# Security Policy

This repository is an educational intrusion-detection prototype. It is not a
replacement for a maintained endpoint security product, and the bootstrap
model must not be used as the sole basis for blocking traffic.

Version 1.0 keeps firewall changes off by default. Never automate the
`--apply` confirmations from model output. Review the target, allowlist,
expiration cleanup, rollback state, and kill switch before any authorized
Windows firewall test. Signed model packages protect integrity and publisher
authenticity only when the trusted public key was obtained independently;
they do not prove model quality.

Feedback files, feature snapshots, benchmark/provenance reports, firewall
state, captures, private signing keys, and update test artifacts are local
sensitive data. The repository `.gitignore` excludes their normal names, but
contributors must still inspect every staged file before committing.

Please report vulnerabilities privately through GitHub's **Report a
vulnerability** feature when available. Do not include real credentials,
private packet captures, personal data, or production network logs in a public
issue.
