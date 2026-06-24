# WinForms layout clipping at higher DPI / font scale

## Problem
Buttons and tile captions on the overview/launchpad were rendered "half" — clipped — at the user's DPI/font
scale, even though they looked fine at the design size.

## Symptom
- Fixed-pixel control sizes (e.g. a drop zone `Height = 166`, tiles `Height = 96`, labels `Width = 200`)
  clipped their content once the system font/DPI was larger than assumed.
- A first fix that hard-coded new heights just pushed a different element ("Son taramalar") off the bottom.

## Root cause
Hard-coded pixel dimensions don't scale with the font. Any layout whose heights/widths are constants will clip
or overflow on a machine whose DPI or font scale differs from the one the numbers were eyeballed on.

## Solution
Make the layout responsive instead of re-measuring by hand:
- `AutoSize = true` on content controls and their rows; let them grow to fit the text.
- Derive any necessary explicit heights from the font, not a constant: `Height = Font.Height + 14`.
- Put the whole scrollable region in an `AutoScroll = true` container so content that exceeds the viewport
  scrolls instead of being cut off.
- For a row of label + value + action, give the label a generous `Width` (or `AutoSize`) so a longer
  translation/word doesn't truncate (one card truncated "API anahtarı ekle ya da…" at `Width = 200`).

## Takeaways
- Never trust a hard-coded control size to survive another machine's DPI. `AutoSize` + `AutoScroll` +
  font-derived heights is the responsive baseline.
- Re-snapshot after the fix: the first responsive pass pushed a panel off-screen, only caught by looking
  at the new snapshot.
