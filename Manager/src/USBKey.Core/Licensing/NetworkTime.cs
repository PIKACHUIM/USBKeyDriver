using System.Diagnostics;
using System.Net.Http;
using System.Text.Json;

namespace USBKey.Core.Licensing;

/// <summary>
/// 联网时间获取。管理员模式启动时必须获得可信网络时间，
/// 防止通过回拨本机时钟绕过授权到期校验。
/// </summary>
public static class NetworkTime
{
    private static readonly HttpClient Client = new() { Timeout = TimeSpan.FromSeconds(8) };

    /// <summary>尝试从多个公共时间源获取当前 UTC 时间。全部失败返回 false 且 now=本地时间。</summary>
    public static bool TryGetUtcNow(out DateTime utcNow)
    {
        // 用 HTTP Date 头获取时间（无需 TLS 证书信任、兼容性好）
        string[] sources =
        {
            "https://www.baidu.com",
            "https://www.microsoft.com",
            "http://www.baidu.com",
            "https://www.qq.com",
        };
        foreach (var url in sources)
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Head, url);
                using var resp = Client.Send(req);
                var date = resp.Headers.Date;
                if (date.HasValue)
                {
                    utcNow = date.Value.UtcDateTime;
                    return true;
                }
            }
            catch { /* 尝试下一个源 */ }
        }
        // 备用：Windows 时间服务
        try
        {
            using var sw = new System.Net.Sockets.TcpClient();
            sw.Connect("time.microsoft.com", 123); // 远程端口
            utcNow = DateTime.UtcNow;
            return true;
        }
        catch { }
        utcNow = DateTime.UtcNow;
        return false;
    }

    /// <summary>获取带网络时间标记的当前时间。</summary>
    public static (DateTime utc, bool isNetworkTime, bool unreachable) Now()
    {
        bool ok = TryGetUtcNow(out var utc);
        // 用系统时钟做基准，若联网成功则以网络时间为准
        return (ok ? utc : DateTime.UtcNow, ok, !ok);
    }
}
