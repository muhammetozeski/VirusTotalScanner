# Brainstorm queue (FIFO)

Autonomous experimental development loop. AI agents debate (proposer vs critic) until they
converge on an idea worth building, then the idea is written here as a Markdown file.

## Folders
- **Inbox/** — pending ideas, FIFO. Filename: `yyyy.MM.dd HH.mm.ss.fff - Title.md`. The
  timestamp prefix keeps the queue ordered; the oldest is taken first.
- **Applied/** — ideas that have been implemented (moved here once done).
- **Rejected/** — ideas decided against (moved here, never deleted, so the reasoning is kept).

## Rules
- Take from the front of Inbox (oldest timestamp).
- Implement it on branch `claude/autoloop` only.
- Move the file to Applied/ when done, or Rejected/ (with a short reason appended) if skipped.
- New agent ideas append to Inbox with a fresh timestamp so the queue both fills and drains.
