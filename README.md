# claude-admin-audit

Small audit repo for capturing and reviewing Claude administration settings.

## Files

- `extract_claude_admin_config.py` pulls configuration data from Anthropic's
  Compliance and Admin APIs and writes a snapshot plus markdown reports.

## Usage

Set the required environment variables, then run:

```bash
python3 extract_claude_admin_config.py
```

Useful options:

- `--baseline baseline.json`
- `--outdir out`
- `--skip-users`

## Output

By default the script writes generated audit artifacts into `./out`.
