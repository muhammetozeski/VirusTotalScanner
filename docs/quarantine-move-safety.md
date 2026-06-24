# Quarantine move safety: free space + cross-volume atomicity

## Problem
Quarantine moves a confirmed-threat file into the vault with `File.Move(path, vaultFile, overwrite: true)`.
That single call has two failure modes that leave the threat in limbo: out of disk space, and a cross-volume
move (which is not atomic).

## Symptom / risk
- Disk full mid-move → a half-written `.VIRUS` with no manifest record, or the original gone and the copy
  incomplete. The vault's own `Reconcile()` could only clean this up AFTER the fact, not prevent it.
- `File.Move` across different volumes silently becomes copy-then-delete; a USB-yank or disk-full during the
  copy leaves a partial target or a deleted-but-uncopied source.

## Solution — preflight before the move
1. **Free space**: compare `new FileInfo(path).Length` to `new DriveInfo(GetPathRoot(vaultFolder)).AvailableFreeSpace`
   plus a margin; bail with a clear message and the original untouched if it won't fit.
2. **Cross-volume**: if `GetPathRoot(src) != GetPathRoot(dst)`, do the copy+delete explicitly so failures are
   handled; same-volume keeps the atomic rename.

```csharp
string dest = VaultFile(id);
try {
    long need = new FileInfo(path).Length;
    var drive = new DriveInfo(Path.GetPathRoot(Folder)!);
    if (drive.IsReady && drive.AvailableFreeSpace < need + 8L*1024*1024) { error = "Kasada yer yok…"; return false; }
} catch { /* can't measure → let the move try */ }

if (!string.Equals(Path.GetPathRoot(path), Path.GetPathRoot(dest), StringComparison.OrdinalIgnoreCase)) {
    try { File.Copy(path, dest, overwrite: true); }
    catch (Exception ex) { try { if (File.Exists(dest)) File.Delete(dest); } catch {} error = ex.Message; return false; }
    File.Delete(path); // copy succeeded → drop the original
} else {
    File.Move(path, dest, overwrite: true); // same volume = atomic rename
}
```

## Related: anti-tamper restore + self-reconcile
- Capture `VaultSha` (sha256 of the held file) at quarantine time; re-hash before restore and refuse if it
  changed (don't re-arm a swapped binary at a trusted path). Works even when the VT sha256 is null.
- A once-per-session `Reconcile()` on vault open still heals legacy orphans: surface manifest-less `.VIRUS`
  files as recoverable rows and drop records whose `.VIRUS` is gone.

## Takeaways
- `File.Move` is only atomic within a volume. For sensitive moves, preflight space and handle cross-volume
  explicitly. Capture an integrity hash so the reverse operation can be trusted.
