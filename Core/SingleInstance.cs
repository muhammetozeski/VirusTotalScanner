using System.IO.Pipes;

namespace VirusTotalScanner;

/// <summary>
/// Single-instance guard + IPC. The first GUI instance owns a named mutex and runs a pipe
/// server; later launches (e.g. the context menu spawning one process per selected file)
/// forward their paths to the running window so everything pools into one queue.
/// </summary>
internal static class SingleInstance
{
    const string MutexName = @"Local\VirusTotalScanner.SingleInstance";
    const string PipeName = "VirusTotalScanner.ipc";

    static Mutex? _mutex;

    public static bool TryAcquirePrimary()
    {
        _mutex = new Mutex(initiallyOwned: true, MutexName, out bool createdNew);
        return createdNew;
    }

    public static void StartPipeServer(Action<string[]> onPaths)
    {
        var t = new Thread(() =>
        {
            while (true)
            {
                try
                {
                    using var server = new NamedPipeServerStream(PipeName, PipeDirection.In, 1,
                        PipeTransmissionMode.Byte, PipeOptions.None);
                    server.WaitForConnection();
                    using var reader = new StreamReader(server);
                    string all = reader.ReadToEnd();
                    var paths = all.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    if (paths.Length > 0) onPaths(paths);
                }
                catch (Exception ex) { Log("IPC server error: " + ex.Message, LogLevel.Warning); }
            }
        })
        { IsBackground = true, Name = "vt-ipc-server" };
        t.Start();
    }

    public static bool ForwardToPrimary(string[] paths)
    {
        try
        {
            using var client = new NamedPipeClientStream(".", PipeName, PipeDirection.Out);
            client.Connect(2000);
            using var w = new StreamWriter(client);
            foreach (var p in paths) w.WriteLine(p);
            w.Flush();
            return true;
        }
        catch (Exception ex)
        {
            Log("IPC forward failed: " + ex.Message, LogLevel.Warning);
            return false;
        }
    }
}
