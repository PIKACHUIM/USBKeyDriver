using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace USBKey.Core.UsbKey;

/// <summary>
/// 使用 GP_IFD_LNCA.dll 的 LNCA 设备提供程序（官方工具使用的接口）
/// </summary>
public class GpIfdProvider : IKeyProvider
{
    private static readonly object _lock = new();
    private static bool _initialized = false;

    public string PlatformName => "lnca";
    public bool IsAvailable { get; private set; }

    public void Initialize()
    {
        lock (_lock)
        {
            if (_initialized) return;

            Console.WriteLine("[LNCA-IFD] 尝试初始化 GP_IFD_LNCA.dll");

            try
            {
                var result = GpIfdNative.IFD_Init();
                Console.WriteLine($"[LNCA-IFD] IFD_Init() 返回: {result}");
                
                IsAvailable = (result == 0);
                _initialized = IsAvailable;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[LNCA-IFD] 初始化失败: {ex.Message}");
                IsAvailable = false;
            }
        }
    }

    public IReadOnlyList<UsbKeyDevice> Enumerate()
    {
        var devices = new List<UsbKeyDevice>();

        try
        {
            var buffer = new byte[4096];
            var length = buffer.Length;

            Console.WriteLine("[LNCA-IFD] 调用 IFD_EnumDevice...");
            var result = GpIfdNative.IFD_EnumDevice(buffer, ref length);
            Console.WriteLine($"[LNCA-IFD] IFD_EnumDevice 返回: {result}, length={length}");

            if (result == 0 && length > 0)
            {
                Console.WriteLine($"[LNCA-IFD] 设备数据: {BitConverter.ToString(buffer, 0, Math.Min(length, 64))}");

                // 解析设备列表
                var count = length > 0 ? buffer[0] : 0;
                Console.WriteLine($"[LNCA-IFD] 设备数量: {count}");

                for (int i = 0; i < count && i < 16; i++)
                {
                    devices.Add(new UsbKeyDevice
                    {
                        Platform = PlatformName,
                        SerialNumber = $"Device_{i}",
                        Handle = i
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[LNCA-IFD] 枚举设备失败: {ex.Message}");
        }

        Console.WriteLine($"[LNCA-IFD] 共发现 {devices.Count} 台设备");
        return devices;
    }

    public UsbKeyDevice Open(int handleOrSerial) => throw new NotImplementedException();
    public void Login(UsbKeyDevice device, string pin) => throw new NotImplementedException();
    public void Logout(UsbKeyDevice device) { }
    public UsbKeyDevice GetDetail(UsbKeyDevice device) => device;
    public IReadOnlyList<KeyContainer> ListContainers(UsbKeyDevice device) => new List<KeyContainer>();
    public void ImportPfx(UsbKeyDevice device, string pfxPath, string pfxPassword) => throw new NotImplementedException();
    public void ExportCertificate(UsbKeyDevice device, KeyContainer container, string outputPath) => throw new NotImplementedException();
    
    public void ViewCertificate(KeyContainer container)
    {
        // 留给 UI 层实现
        Console.WriteLine($"[LNCA-IFD] ViewCertificate - 由 UI 层实现");
    }

    public void DeleteContainer(UsbKeyDevice device, KeyContainer container) => throw new NotImplementedException();
    public void RegisterToCsp(KeyContainer container) => throw new NotImplementedException();
    public void UnregisterFromCsp(KeyContainer container) => throw new NotImplementedException();
    public void ChangePin(UsbKeyDevice device, string oldPin, string newPin) => throw new NotImplementedException();
    public void Unlock(UsbKeyDevice device, UnlockMethod method, string credential, string newPin) => throw new NotImplementedException();
    public string GenerateChallenge(UsbKeyDevice device) => throw new NotImplementedException();
    public void UnlockByChallenge(UsbKeyDevice device, string challenge, string response, string newPin) => throw new NotImplementedException();
    public void ResetDevice(UsbKeyDevice device, string newPin, string? puk = null, string? adminKey = null) => throw new NotImplementedException();

    public void Dispose()
    {
        lock (_lock)
        {
            if (_initialized)
            {
                try
                {
                    GpIfdNative.IFD_Exit();
                    Console.WriteLine("[LNCA-IFD] 已清理资源");
                }
                catch { }
                
                _initialized = false;
            }
        }
    }
}
