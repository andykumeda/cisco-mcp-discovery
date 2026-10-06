# Pre-Publication Checklist

Run this checklist before making the repository public.

- Confirm this repo has no history from private operational repositories.
- Run a secret scanner across the working tree and Git history.
- Verify `.gitignore` excludes keys, inventories, `.env` files, generated
  artifacts, logs, and MCP client configs.
- Inspect all examples for documentation IP ranges only: `192.0.2.0/24`,
  `198.51.100.0/24`, and `203.0.113.0/24`.
- Confirm generated diagrams and reports are sanitized fixtures.
- Confirm README screenshots, terminal output, and docs do not reveal real
  hostnames, usernames, IP ranges, customer names, or topology details.
- Confirm private operations folders, private inventory, real audit logs,
  trusted-target caches, and client configs are not part of the publication set.
- Run the test suite and CI checks.
