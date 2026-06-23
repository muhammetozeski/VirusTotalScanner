using System.Drawing;
using System.Drawing.Imaging;

namespace VirusTotalScanner;

/// <summary>Dev-only: renders the main window to a PNG off-screen (for visual review). Used via --snapshot.</summary>
internal static class SnapshotRunner
{
    public static int Run(string path, string[]? preloadHashes = null)
    {
        try
        {
            ApplicationConfiguration.Initialize();
            using var form = new MainForm
            {
                StartPosition = FormStartPosition.Manual,
                Location = new Point(-4000, -4000),
                ShowInTaskbar = false,
            };
            form.Show();
            for (int i = 0; i < 8; i++) { Application.DoEvents(); Thread.Sleep(120); }

            // Optionally pre-load real results so the snapshot shows the engine table / trusted-skip.
            if (preloadHashes is { Length: > 0 })
            {
                foreach (var token in preloadHashes)
                {
                    try
                    {
                        if (File.Exists(token))
                        {
                            var (md5, sha256) = HashService.ComputeAsync(token).GetAwaiter().GetResult();
                            var t = TrustService.Evaluate(token);
                            if (TrustService.ShouldSkip(t, Settings.TrustMicrosoftOnly, Settings.TrustPublisherAllowList))
                            {
                                AppServices.Scheduler.Items.Add(new ScanItem(token)
                                { Status = ScanStatus.TrustedSkipped, SkipReason = t.Reason, Publisher = t.Publisher, Md5 = md5, Sha256 = sha256 });
                                continue;
                            }
                        }
                        if (AppServices.Rotator.HasUsableKeys)
                        {
                            string key = AppServices.Rotator.AcquireAsync().GetAwaiter().GetResult();
                            var report = AppServices.Api.GetFileReportAsync(token, key).GetAwaiter().GetResult();
                            if (report != null)
                                AppServices.Scheduler.Items.Add(new ScanItem(token) { Report = report, Status = ScanStatus.Completed, Md5 = report.Md5, Sha256 = report.Sha256 });
                        }
                    }
                    catch (Exception ex) { Console.Error.WriteLine("preload failed: " + ex.Message); }
                }
                form.SelectFirstResult();
                for (int i = 0; i < 4; i++) { Application.DoEvents(); Thread.Sleep(100); }
            }

            string dir = Path.GetDirectoryName(path) ?? ".";
            string baseName = Path.GetFileNameWithoutExtension(path);
            for (int tab = 0; tab < 4; tab++)
            {
                form.SelectTab(tab);
                for (int i = 0; i < 4; i++) { Application.DoEvents(); Thread.Sleep(80); }
                using var bmp = new Bitmap(form.Width, form.Height);
                form.DrawToBitmap(bmp, new Rectangle(0, 0, form.Width, form.Height));
                string outPath = Path.Combine(dir, $"{baseName}-tab{tab}.png");
                bmp.Save(outPath, ImageFormat.Png);
                Console.WriteLine("snapshot: " + outPath);
            }
            form.Close();
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("snapshot failed: " + ex);
            return 1;
        }
    }
}
