# Contributing
Author: Rajarshi

Use Python 3.12 or newer. Install with `pip install -e ".[dev]"`, then run
`python -m pytest` and `python -m ruff check general_ai_gateway tests examples`.
Tests use HTTPX mock transports and make no live provider calls.

Preserve explicit authorization before upstream calls, whole-document config
validation, no automatic retries for side effects, bounded telemetry labels,
and credential-free error/audit output. Document protocol restrictions honestly.
Add behavioral tests for policy changes and failure paths. Redis integration
checks require an isolated instance; never point tests at production Redis.

Copyright (c) 2026, Rajarshi (General AI Gateway). Licensed under the
[BSD-3-Clause license](LICENSE). Preserve the original copyright notice,
license conditions and disclaimer when redistributing; see [NOTICE](NOTICE).
