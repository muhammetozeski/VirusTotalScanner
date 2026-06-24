# Multi-agent brainstorm orchestration (proposer / critic / writer)

## Goal
Keep an autonomous build loop fed with genuinely-new, non-overengineered feature ideas, written to disk so
the loop just drains a FIFO queue.

## Pattern (the `Workflow` tool)
A 3-stage pipeline over N "lenses" (distinct themes so ideas don't overlap):
1. **Propose** — one agent per lens generates 2–3 concrete ideas (structured output).
2. **Critique** — a harsh critic picks the single best per lens and REJECTS duplicates / overengineering /
   low-value (structured verdict).
3. **Write** — a writer agent runs `Get-Date -Format 'yyyy.MM.dd HH.mm.ss.fff'` and Writes the surviving
   idea to the Inbox folder as `<timestamp> - <title>.md`. Real Get-Date stamps (ms precision) avoid
   collisions across parallel writers.

```js
const results = await pipeline(LENSES, propose, critique, write);
```

## Hard-won details
- **The `Workflow` tool always runs in the background.** There is NO `run_in_background` parameter — passing
  it is an InputValidationError. It returns a task id immediately and notifies on completion.
- **Stop re-proposing shipped/deferred ideas.** Pass the SHIPPED feature list in the prompt AND an explicit
  "ASLA ÖNERME (deferred, in Brainstorm/Deferred): …" block. Even then a duplicate slips through — verify the
  top idea against the actual codebase before building and move true duplicates to `Brainstorm/Rejected`
  with a one-line reason (e.g. ArrayPool hash buffers was re-proposed after already shipping in HashService).
- **Session token limit mid-run** → the workflow returns 0 kept with per-agent "session limit" failures. After
  the quota window resets, just re-invoke with the same `scriptPath` (nothing cached, so it re-runs clean).
- **Iterate the script without re-sending it**: every invocation persists the script under the session dir;
  edit that file and re-invoke with `{ scriptPath }`.
- Keep a `Brainstorm/{Inbox,Applied,Rejected,Deferred}` layout so state is fully on disk and a cold resume
  reads exactly where things stand.

## Takeaways
- Proposer→critic→writer with disk-backed output makes an autonomous loop self-feeding. The critic must be
  given the shipped + deferred context, and you still verify against the code — agents re-propose what exists.
