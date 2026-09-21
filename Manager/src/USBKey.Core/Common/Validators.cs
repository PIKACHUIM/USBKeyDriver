using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace USBKey.Core.Common;

/// <summary>参数合法性校验。</summary>
public static class Validators
{
    public static readonly Regex PinRule = new(@"^.{6,}$", RegexOptions.Compiled);

    /// <summary>校验 PIN：6 位起。</summary>
    public static void EnsurePin(string pin, string what = "PIN")
    {
        if (string.IsNullOrEmpty(pin) || !PinRule.IsMatch(pin))
            throw new ArgumentException($"{what} 长度不能少于 6 位");
    }

    /// <summary>校验密码一致性。</summary>
    public static void EnsureSame(string a, string b, string what = "密码")
    {
        if (!string.Equals(a, b)) throw new ArgumentException($"两次输入的{what}不一致");
    }

    /// <summary>生成随机口令（默认随机 PIN/PUK/AdminKey，用于重置设备）。</summary>
    public static string RandomPassword(int length = 8, string chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789")
    {
        // 安全凭据必须使用加密安全随机源，避免可预测。
        var sb = new StringBuilder(length);
        var buf = new byte[length * 4];
        RandomNumberGenerator.Fill(buf);
        for (int i = 0; i < length; i++)
        {
            // 用 4 字节无符号整数取模，避免低位偏差（拒绝采样更严谨，这里长度有限足够）。
            var idx = (int)(BitConverter.ToUInt32(buf, i * 4) % (uint)chars.Length);
            sb.Append(chars[idx]);
        }
        return sb.ToString();
    }
}
