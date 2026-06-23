using System.Diagnostics;
using System.Net;

namespace VirusTotalScanner;

/// <summary>
/// HttpContent that streams a file to the request while reporting upload progress
/// (bytes, percent, speed). Wrapped inside a MultipartFormDataContent's "file" field so
/// the GUI can show a detailed upload bar.
/// </summary>
internal sealed class ProgressableStreamContent : HttpContent
{
    readonly Stream _content;
    readonly long _total;
    readonly IProgress<UploadProgress>? _progress;
    readonly int _bufferSize;

    public ProgressableStreamContent(Stream content, long total, IProgress<UploadProgress>? progress, int bufferSize = 81920)
    {
        _content = content;
        _total = total;
        _progress = progress;
        _bufferSize = bufferSize;
    }

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
        SerializeToStreamAsync(stream, context, CancellationToken.None);

    protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
    {
        var buffer = new byte[_bufferSize];
        long sent = 0;
        long lastReportBytes = 0;
        long lastReportMs = 0;
        var sw = Stopwatch.StartNew();

        // Report a 0% tick immediately so the UI shows the bar from the start.
        _progress?.Report(new UploadProgress { BytesSent = 0, TotalBytes = _total, BytesPerSecond = 0 });

        int read;
        while ((read = await _content.ReadAsync(buffer.AsMemory(0, _bufferSize), cancellationToken)) > 0)
        {
            await stream.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
            sent += read;

            long ms = sw.ElapsedMilliseconds;
            if (ms - lastReportMs >= 100 || sent >= _total)
            {
                long speed = CalculateDownloadSpeed(sent - lastReportBytes, ms - lastReportMs);
                _progress?.Report(new UploadProgress { BytesSent = sent, TotalBytes = _total, BytesPerSecond = speed });
                lastReportBytes = sent;
                lastReportMs = ms;
            }
        }

        _progress?.Report(new UploadProgress { BytesSent = sent, TotalBytes = _total, BytesPerSecond = 0 });
    }

    protected override bool TryComputeLength(out long length)
    {
        length = _total;
        return true;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _content.Dispose();
        base.Dispose(disposing);
    }
}
