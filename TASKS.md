# Proposed follow-up tasks

## Typo fix
- **Issue:** The malleable profile ships an abbreviated `user_agent` string (`AppleWebKit/537.36` without the usual `(KHTML, like Gecko) ... Safari/537.36` suffix), so implants inherit an obviously truncated header that can raise suspicion and diverges from the main client default.
- **Task:** Expand `security.user_agent` in `malleable_profile.json` to the full browser-style string used by `phantomrat_main.py` so C2 requests present a consistent, realistic User-Agent.

## Bug fix
- **Issue:** The C2 seeds the database with a hard-coded `admin / phantomrat` login and even prints those credentials at startup, leaving the dashboard permanently exposed and contradicting the goal of correcting the login password.
- **Task:** Replace the baked-in password setup in `phantomrat_c2.py` with a configurable credential bootstrap (e.g., environment variables or prompts) and stop echoing the default password on launch so operators must set secure credentials before using the dashboard.

## Comment/documentation discrepancy
- **Issue:** The implant-side Telegram helper in `phantomrat_evasion.py` says it "Requires python-telegram-bot" but actually imports `telebot` with placeholder tokens, so the comment and dependency guidance do not match the code.
- **Task:** Align the comment and dependency guidance with the actual library (or switch the code to the documented library) and wire the bot token/chat ID to the shared configuration so Telegram notifications are accurate and consistent.

## Test improvement
- **Issue:** `test_phantomrat.py` only checks for file presence, basic config parsing, and dependency imports; it never validates that dashboard credentials and notification settings are properly configured, so operators get no automated warning when defaults/placeholder Telegram values remain.
- **Task:** Extend the quick check to fail when the dashboard password is left at the shipped default or when Telegram settings are unset/placeholder, ensuring the C2, implants, and Telegram notifications are configured before deployment.
