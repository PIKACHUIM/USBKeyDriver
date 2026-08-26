using System.Management;
using USBKey.Core.Configuration;

namespace USBKey.Core.UsbKey;

/// <summary>
/// USB 设备热插拔监听。通过 WMI 的 Win32_DeviceChangeEvent 监听 USB 设备的
/// 插入/移除，并与 config.keyslist 的 VID/PID 白名单比对，命中时触发
/// <see cref="KeyArrived"/> / <see cref="KeyRemoved"/> / 变化通知。
/// </summary>
public sealed class UsbWatcher : IDisposable
{
    private readonly HashSet<(int Vid, int Pid)> _whitelist = new();
    private ManagementEventWatcher? _watcher;
    private CancellationTokenSource? _cts;
    private readonly object _sync = new();

    /// <summary>命中白名单的 Key 插入事件。</summary>
    public event Action<UsbKeyDevice>? KeyArrived;
    /// <summary>命中白名单的 Key 移除事件。</summary>
    public event Action? KeyRemoved;
    /// <summary>通用设备变化（含插入/拔出）。</summary>
    public event Action? Changed;

    public UsbWatcher(IEnumerable<UsbDeviceDef> whitelist)
    {
        foreach (var d in whitelist)
            if (d.VidInt != 0 && d.PidInt != 0)
                _whitelist.Add((d.VidInt, d.PidInt));
    }

    public void Start()
    {
        try
        {
            var scope = new ManagementScope("root\\CIMV2");
            scope.Connect();
            var query = new WqlEventQuery(
                "SELECT * FROM Win32_DeviceChangeEvent WHERE EventType = 2 OR EventType = 3");
            _watcher = new ManagementEventWatcher(scope, query);
            _watcher.EventArrived += OnDeviceEvent;
            _watcher.Start();
        }
        catch
        {
            // WMI 事件不可用时，退化为轮询（如虚拟机/受限环境）
            _cts?.Cancel();
            _cts = new CancellationTokenSource();
            PollLoop(_cts.Token);
        }
    }

    private void OnDeviceEvent(object sender, EventArrivedEventArgs e)
    {
        try
        {
            bool remove = Convert.ToInt32(e.NewEvent.Properties["EventType"].Value) == 3;
            if (remove) KeyRemoved?.Invoke();
            Changed?.Invoke();
        }
        catch { }
    }

    private async void PollLoop(CancellationToken token)
    {
        var last = new HashSet<(int, int)>();
        while (!token.IsCancellationRequested)
        {
            try
            {
                var now = SnapshotUsb();
                if (now.Count > last.Count)
                {
                    Changed?.Invoke();
                    foreach (var v in now)
                        if (v.Item2 == last.Count) KeyArrived?.Invoke(new UsbKeyDevice { Vid = v.Item1, Pid = v.Item2 });
                }
                else if (now.Count < last.Count)
                {
                    KeyRemoved?.Invoke();
                    Changed?.Invoke();
                }
                last = now;
            }
            catch { }
            try { await Task.Delay(1500, token); } catch { break; }
        }
    }

    private HashSet<(int, int)> SnapshotUsb()
    {
        var set = new HashSet<(int, int)>();
        try
        {
            using var s = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity WHERE PNPClass='USB'");
            foreach (ManagementBaseObject o in s.Get())
            {
                var id = o["PNPDeviceID"]?.ToString() ?? "";
                var m = System.Text.RegularExpressions.Regex.Match(id, @"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})");
                if (!m.Success) continue;
                int vid = Convert.ToInt32(m.Groups[1].Value, 16);
                int pid = Convert.ToInt32(m.Groups[2].Value, 16);
                if (_whitelist.Contains((vid, pid))) set.Add((vid, pid));
            }
        }
        catch { }
        return set;
    }

    public bool IsInWhiteList(int vid, int pid) => _whitelist.Contains((vid, pid));

    public void Dispose()
    {
        _watcher?.Stop();
        _watcher?.Dispose();
        _cts?.Cancel();
        _cts?.Dispose();
    }
}
