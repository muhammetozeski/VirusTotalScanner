namespace VirusTotalScanner;

internal static class Program
{
    /// <summary>
    /// Hybrid entry point. One WinExe behaves as:
    ///   • double-click / no args      -> full GUI
    ///   • file/folder args (Explorer) -> GUI scan (paths forwarded to a running instance)
    ///   • launched from a terminal    -> CLI, no GUI (writes to the parent console)
    /// </summary>
    [STAThread]
    static int Main(string[] args)
    {
        var opts = ArgumentDef.Parse(args);

        // Dev snapshot path needs core services but no console/instance handling.
        if (opts.SnapshotPath != null)
        {
            InitCore();
            return SnapshotRunner.Run(opts.SnapshotPath, opts.Paths.ToArray());
        }

        bool hasParentConsole = ConsoleBootstrap.TryAttachParentConsole();

        LaunchMode mode;
        if (opts.ShowHelp || opts.ShowVersion || opts.NoGui || opts.InstallMenu || opts.UninstallMenu || opts.RepairMenu)
            mode = LaunchMode.Cli;
        else if (opts.ForceGui)
            mode = opts.Paths.Count > 0 ? LaunchMode.GuiWithPaths : LaunchMode.Gui;
        else if (hasParentConsole)
            mode = LaunchMode.Cli;
        else if (opts.Paths.Count > 0)
            mode = LaunchMode.GuiWithPaths;
        else
            mode = LaunchMode.Gui;

        InitCore();

        try
        {
            if (mode == LaunchMode.Cli)
                return CliRunner.RunAsync(opts).GetAwaiter().GetResult();
            return RunGui(opts);
        }
        catch (Exception ex)
        {
            Log("Fatal: " + ex, LogLevel.Error);
            if (mode == LaunchMode.Cli) { try { Console.Error.WriteLine("FATAL: " + ex.Message); } catch { } return 2; }
            try { NativeMessageBox.Error("Beklenmeyen hata:\n" + ex.Message); } catch { }
            return 1;
        }
    }

    static void InitCore()
    {
        SettingsManager.LoadSettings();
        LoggerHost.Initialize();
        Theme.ApplyFromSettings();
        AppServices.Initialize();
    }

    static int RunGui(CliOptions opts)
    {
        bool primary = SingleInstance.TryAcquirePrimary();
        if (!primary)
        {
            // Forward to the already-running window; fall back to our own window if that fails.
            var forwardPaths = opts.Paths.Count > 0 ? opts.Paths.ToArray() : ["--show"];
            if (SingleInstance.ForwardToPrimary(forwardPaths))
            {
                Log("Forwarded to running instance; exiting.", LogLevel.Info);
                return 0;
            }
            Log("Forward failed; opening a standalone window.", LogLevel.Warning);
        }

        StartupManager.Sync(); // fix the login entry if the exe moved

        ApplicationConfiguration.Initialize();
        var form = new MainForm { StartHidden = opts.Tray };

        if (primary)
            SingleInstance.StartPipeServer(paths => form.EnqueueExternalPaths(paths));

        if (opts.Paths.Count > 0)
        {
            var initial = opts.Paths.ToArray();
            form.Shown += (_, _) => form.EnqueueExternalPaths(initial);
        }

        Log($"GUI starting ({(primary ? "primary" : "standalone")})", LogLevel.Info);
        Application.Run(form);
        return 0;
    }
}
