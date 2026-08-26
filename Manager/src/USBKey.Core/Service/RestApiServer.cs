using System.Net;
using System.Text;
using System.Text.Json;
using USBKey.Core.UsbKey;

namespace USBKey.Core.Service;

/// <summary>REST API 状态响应。</summary>
public class ApiResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = "";
    public object? Data { get; set; }
}

/// <summary>
/// 可选 REST API。仅在管理员模式且已注册授权的情况下，勾选启用。
/// 使用 HttpListener 实现，避免额外依赖。所有接口要求 Bearer Token。
/// </summary>
public sealed class RestApiServer : IDisposable
{
    private HttpListener? _listener;
    private readonly string _token;
    private readonly KeyManager _keys;
    private readonly object _auth = new();
    private CancellationTokenSource? _cts;

    public RestApiServer(string token, KeyManager keys)
    {
        _token = token;
        _keys = keys;
    }

    public bool Start(int port)
    {
        if (_listener != null) return true;
        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        _listener.Prefixes.Add($"http://localhost:{port}/");
        try { _listener.Start(); }
        catch { return false; }
        _cts = new CancellationTokenSource();
        _ = AcceptLoopAsync(_cts.Token);
        return true;
    }

    public void Stop()
    {
        _cts?.Cancel();
        _listener?.Stop();
        _listener = null;
    }

    private bool Authorize(HttpListenerRequest req)
    {
        var header = req.Headers["Authorization"] ?? "";
        return string.Equals(header, "Bearer " + _token, StringComparison.OrdinalIgnoreCase);
    }

    private async Task AcceptLoopAsync(CancellationToken token)
    {
        while (_listener != null && !token.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try { ctx = await _listener.GetContextAsync(); }
            catch { break; }
            _ = Task.Run(() => Handle(ctx));
        }
    }

    private void Handle(HttpListenerContext ctx)
    {
        try
        {
            if (!Authorize(ctx.Request))
            {
                Reply(ctx, HttpStatusCode.Unauthorized, new ApiResult { Success = false, Message = "未授权" });
                return;
            }
            var seg = ctx.Request.Url!.AbsolutePath.Trim('/').ToLowerInvariant();
            var resp = seg switch
            {
                "devices" => new ApiResult { Success = true, Data = _keys.EnumerateAll() },
                "device" => HandleDevice(),
                _ => new ApiResult { Success = false, Message = "未知接口" },
            };
            Reply(ctx, HttpStatusCode.OK, resp);
        }
        catch (Exception ex)
        {
            Reply(ctx, HttpStatusCode.InternalServerError, new ApiResult { Success = false, Message = ex.Message });
        }
    }

    private object HandleDevice()
    {
        // GET /device?platform=lnca&serial=xxx  → 打开设备返回
        return new { Platform = "lnca", Hint = "通过 USBKey.Core 的 LncaProvider 操作" };
    }

    private static void Reply(HttpListenerContext ctx, HttpStatusCode code, object obj)
    {
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(obj,
            new JsonSerializerOptions { WriteIndented = true }));
        ctx.Response.StatusCode = (int)code;
        ctx.Response.ContentType = "application/json; charset=utf-8";
        ctx.Response.ContentLength64 = bytes.Length;
        try { ctx.Response.OutputStream.Write(bytes); ctx.Response.OutputStream.Close(); }
        catch { }
    }

    public void Dispose() => Stop();
}
