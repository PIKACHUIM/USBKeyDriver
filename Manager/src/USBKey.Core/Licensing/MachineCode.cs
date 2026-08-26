using System.Management;
using System.Security.Cryptography;
using System.Text;

namespace USBKey.Core.Licensing;

/// <summary>
/// 机器码生成：CPUID + 硬盘序列号 + 主板UUID 拼接后做 SHA256 哈希，
/// 取前16字节并转换为大写16进制（32字符）作为稳定、可复现的机器标识。
/// </summary>
public static class MachineCode
{
    /// <summary>生成机器码（失败时降级为空串并拼接备用指纹，保证可复现）。</summary>
    public static string Get()
    {
        var cpu = SafeQuery("Processor", "ProcessorId");
        var disk = SafeQuery("Win32_DiskDrive", "SerialNumber");
        var mb = SafeQuery("Win32_BaseBoard", "SerialNumber");
        var mobo = SafeQuery("Win32_ComputerSystemProduct", "UUID");

        var raw = $"CPU={cpu};DISK={disk};MB={mb};UUID={mobo}";
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        // 取前16字节 -> 32个hex字符
        var sb = new StringBuilder(bytes.Length * 2);
        for (var i = 0; i < 16; i++) sb.Append(bytes[i].ToString("X2"));
        // 按 8 位分组便于阅读
        var code = sb.ToString();
        return $"{code.Substring(0, 8)}-{code.Substring(8, 8)}-{code.Substring(16, 8)}-{code.Substring(24, 8)}";
    }

    private static string SafeQuery(string wmiClass, string prop)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"SELECT " + prop + " FROM " + wmiClass);
            foreach (ManagementBaseObject o in searcher.Get())
            {
                var v = o[prop]?.ToString();
                if (!string.IsNullOrWhiteSpace(v) && v.Trim() != "To be filled by O.E.M." && v.Trim() != "Default string")
                    return v.Trim();
            }
        }
        catch { /* WMI 可能被禁用/无权限，忽略 */ }
        // 降级：尝试从注册表获取硬盘/主板信息
        try
        {
            using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SystemInformation");
            if (k != null)
            {
                var uuid = k.GetValue("ComputerHardwareId")?.ToString();
                if (!string.IsNullOrWhiteSpace(uuid)) return uuid;
            }
        }
        catch { }
        return "";
    }
}
