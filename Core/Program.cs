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
            if (mode == LaunchMode.Cli) { try { Console.Error.WriteLine(string.Format(Strings.CliFatalFormat, ex.Message)); } catch { } return 2; }
            try { NativeMessageBox.Error(string.Format(Strings.FatalUnexpectedErrorFormat, ex.Message)); } catch { }
            return 1;
        }
    }

    static void InitCore()
    {
        SettingsManager.LoadSettings();
        LoggerHost.Initialize();
        Theme.ApplyFromSettings();
        AppServices.Initialize();
        InstallGlobalExceptionLogging();
    }

    /// <summary>
    /// Safety net: nothing crashes silently. Every unhandled exception (background threads,
    /// unobserved tasks, the UI thread) is forced to ActivateLogging-independent Error logging.
    /// Hardening does NOT mean swallowing — these are logged, not hidden.
    /// </summary>
    static void InstallGlobalExceptionLogging()
    {
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            Log("UNHANDLED exception: " + ((e.ExceptionObject as Exception)?.ToString() ?? e.ExceptionObject?.ToString()), LogLevel.Error);

        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            Log("UNOBSERVED task exception: " + e.Exception, LogLevel.Error);
            e.SetObserved();
        };
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
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) =>
        {
            Log("UNHANDLED UI exception: " + e.Exception, LogLevel.Error);
            try { NativeMessageBox.Error(string.Format(Strings.UiThreadExceptionFormat, e.Exception.Message)); }
            catch (Exception ex) { Log("Error dialog failed: " + ex.Message, LogLevel.Warning); }
        };
        // Paths that arrive before the window can take them: this launch's own, and any a second launch
        // forwards while this one is still building its window. The pipe server used to start only after
        // the window was built — ten seconds and more — while a second launch gives up after two, so a
        // multi-select right-click opened standalone windows that each ran their own start-up retries.
        var early = new List<string[]>();
        MainForm? ready = null;
        var handOffLock = new object();
        void Deliver(string[] paths)
        {
            MainForm? target;
            lock (handOffLock)
            {
                target = ready;
                if (target == null) { early.Add(paths); return; }
            }
            target.EnqueueExternalPaths(paths);
        }

        if (opts.Paths.Count > 0) early.Add(opts.Paths.ToArray());
        if (primary)
            SingleInstance.StartPipeServer(Deliver);

        var form = new MainForm(startHidden: opts.Tray);

        // Once, and only once. EnqueueExternalPaths restores the window from the tray, which shows
        // the form again and raises Shown a second time — the handler then started the same scan
        // twice and the second one queued itself as an automatic follow-up run of the whole drive.
        EventHandler? handOff = null;
        handOff = (_, _) =>
        {
            form.Shown -= handOff;
            string[][] backlog;
            lock (handOffLock)
            {
                ready = form;
                backlog = [.. early];
                early.Clear();
            }
            foreach (var paths in backlog) form.EnqueueExternalPaths(paths);
        };
        form.Shown += handOff;

        Log($"GUI starting ({(primary ? "primary" : "standalone")})", LogLevel.Info);
        Application.Run(form);
        return 0;
    }
}
