# Autonomous development-loop discipline

The hardest part of an autonomous "keep building" loop is not the code — it's not stopping wrongly and not
shipping unverified work. Lessons from a 200+ commit loop.

## Never stop wrongly — implicit questions are still questions
The single worst failure: ending a turn with plain prose like *"sıradaki hazır — devam dersen build ederim,
yoksa bekliyorum."* No tool call, but functionally identical to asking — the loop stalled waiting on the user.
The ban is on the FUNCTION (deferring continuation to the user), not on a specific tool. Three banned stop-modes:
- **Implicit/soft question** — any sentence that makes the next step conditional on the user's reply
  ("devam dersen / istersen / want me to continue").
- **Summary-as-stop** — writing a status report and ending while the queue still has work. A summary is a
  comma before the next task, not a period. After it, take the next item in the SAME turn and keep building.
- **Milestone-as-stop** — "did a lot / many commits / context full" is never a reason to pause.

The last sentence of a turn must be a DECISION + action ("şu an X'i build ediyorum"), never a wait/approval
request. Only a real stop condition closes the loop: the user says "dur", the task is genuinely done, or token
exhaustion (which is not a real stop — the cron resumes after the quota window).

## Cross-turn continuation = a cron heartbeat, never ScheduleWakeup
`ScheduleWakeup` ends the turn and creates a dead gap → forbidden for driving a loop. The only sanctioned
continuation is a recurring CRON (fires only when the REPL is idle, i.e. when you actually stopped):
*"if already running, ignore; if stopped, continue from disk state."* All progress lives on DISK (commits +
the Brainstorm queue) so a cold cron-resume reads exactly where things stand.

## Don't ship unverified work; defer it with notes
Some ideas touch core mechanisms that can't be verified at the desk:
- streaming/scheduler refactors (need large-tree runs; progress-total semantics break),
- WebView2 scrape generalization for URL/IP (needs a live-VT session to confirm the capture endpoints).
Shipping these blind risks breaking the app's core or shipping a dead feature. Park them in
`Brainstorm/Deferred/` WITH an implementation note explaining what to do and why it was deferred — that is
sound engineering, distinct from stopping the loop (you still take the next buildable item). Protection-sensitive
logic (verdict band, auto-actions) must stay correct and backward-compatible (empty rule store = built-in
behavior unchanged).

## Per-iteration rhythm
Get-Date → read state from disk (git log, Brainstorm/Inbox) → finish any half work else take the oldest FIFO
idea → implement → `dotnet build` → test (CLI / `--snapshot`) → one-concern commit → push → move the idea to
Applied (or Rejected with a reason) → loop. When the Inbox runs low (<5), kick off a background brainstorm to
refill while you keep building. On any GUI change, snapshot the changed screen and review it.

## Takeaways
- The loop fails by stopping (often via a soft, prose-level question) far more easily than by bad code.
- Keep state on disk, continue via a cron, and defer-with-notes anything you can't verify rather than shipping
  it unverified.
