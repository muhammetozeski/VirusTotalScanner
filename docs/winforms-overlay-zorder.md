# WinForms overlay rendered behind the grid (two Dock.Fill siblings)

## Problem
The empty-state onboarding card (shown over the scan queue when it has no rows) did not render. The
`--snapshot` of the scan tab kept showing the bare empty grid with its column headers — the card was nowhere.

## Symptom
- Card created with `Dock = DockStyle.Fill`, added to `SplitContainer.Panel1` after the grid, `Visible = true`,
  `BringToFront()` called in the ctor.
- Snapshot still showed the grid on top. Adding an `OnHandleCreated` override that re-asserted
  `BringToFront()` did NOT fix it either.

## Root cause
The grid is also `Dock = DockStyle.Fill`. Two `Dock=Fill` siblings in the same container compete for the same
fill rectangle, and the dock-layout + z-order interaction is fragile — `BringToFront()` does not reliably win,
especially in the snapshot/`DrawToBitmap` render path where the full Show/layout lifecycle hasn't run. The
grid (added first, the "natural" fill) kept painting on top.

## Solution
Don't overlay — **swap visibility** so only one `Dock=Fill` control is visible at a time. No z-order race can
exist when only one Fill control is shown.

```csharp
void UpdateEmptyState()
{
    bool empty = _scheduler.Items.Count == 0;
    _grid.Visible = !empty;   // hide the grid when empty
    _emptyCard.Visible = empty; // show the card instead
    if (empty) _emptyCard.BringToFront();
}
```

Drive it from the data: `BindingList.ListChanged` (filtered to ItemAdded/ItemDeleted/Reset), plus the scan
`Started` (force grid) and `Finished` (re-evaluate) events, plus one init call after construction.

## Takeaways
- Two `Dock=Fill` siblings = unreliable z-order. Prefer swapping `Visible` over overlay + `BringToFront`.
- The GUI critic-snapshot earned its keep here: the bug was invisible in code review but obvious in the
  rendered snapshot. Always snapshot a changed screen and actually look at it.
