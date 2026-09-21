using System.Runtime.InteropServices;

namespace USBKey.Core.UsbKey;

/// <summary>
/// LNCA COS 层 <c>HDCOS_LNCA.dll</c> 的原生接口委托定义（「完全格式化 / 重设 PIN」链路）。
/// <para>
/// 逆向依据（2026-09，静态反汇编，工具见 <c>tools/disasm_lnca.py</c>）：
/// <list type="bullet">
/// <item>JIT 层 <c>JIT_USBKEY_HD.dll</c> 的 <c>USBKey_InitKey</c>/<c>USBKey_Reset</c> 是调试空壳；
/// <c>HDCOS_LNCA.dll</c> 的 <c>InitialCard</c>（RVA 0x73F0）同样是空 stub（<c>or eax,-1; ret 0x10</c>）。</item>
/// <item><b>完全格式化</b>唯一可用入口 = <c>HD_ClearDir(hCard)</c>（RVA 0x67D0）：
/// <c>Get_Challenge</c>(CLA 0x84, 8 字节) → 用 DLL 数据段内置传输密钥（RVA 0x19050）做挑战应答 →
/// <c>External_Authentication</c>(CLA 0x82, P1=0) → <c>Clear_DF</c>(私有 APDU <c>BF CE 00 00 00</c>)。
/// 全程不需要用户 PIN，因此可用于「忘记 PIN 后恢复出厂」。</item>
/// <item><b>重设 PIN</b>入口：<c>Reload_Pin</c>（ISO7816-4 INS <c>0x5E</c> RESET RETRY COUNTER，
/// APDU <c>80 5E 00 00 Lc &lt;data&gt;</c>）或 <c>HD_ChangePin</c>（数据以 <c>0xFF</c> 分隔「旧 PIN / 新 PIN」）。</item>
/// <item><c>HD_VerifyPin</c> 并非简单的 VERIFY 命令：它用 PIN 作为密钥材料做挑战应答外部认证
/// （<c>Get_Challenge</c> → 密钥派生 → <c>External_Authentication</c> P1=1），返回 0 表示认证通过，
/// 返回正数表示剩余重试次数，返回 -1 表示已锁定/被拒。</item>
/// </list>
/// </para>
/// <para>
/// 关键约束：DLL 为 32 位（pei-i386），宿主进程必须以 x86 运行；所有导出均为 <c>__stdcall</c>，
/// 返回 int（0 = 成功，非 0 = 错误码/SW）。
/// </para>
/// </summary>
internal static class LncaHdcosNative
{
    /// <summary>HD_Open(uint port) → 返回卡片句柄（0 = 失败）。ret 4（1 参数）。</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate IntPtr HdOpenFn(uint port);

    /// <summary>HD_Close(int hCard)。ret 4（1 参数）。</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int HdCloseFn(IntPtr hCard);

    /// <summary>HD_IC_RESET(int hCard, byte* atr)。ret 8（2 参数），执行卡片复位并回填 ATR。</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int HdIcResetFn(IntPtr hCard, [In, Out] byte[] atr);

    /// <summary>
    /// HD_ClearDir(int hCard)。ret 4（1 参数）。
    /// <para>「完全格式化」：内置传输密钥外部认证通过后发送 <c>BF CE 00 00 00</c> 清除数据区（DF）。</para>
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int HdClearDirFn(IntPtr hCard);

    /// <summary>
    /// Reload_Pin(int hCard, uint dataLen, byte* data, void* reserved)。ret 0x10（4 参数）。
    /// <para>发送 APDU <c>80 5E 00 00 Lc data</c>（INS 0x5E = RESET RETRY COUNTER）。</para>
    /// <para>data 语义依卡片实现：通常为「PUK/解锁码 + 新 PIN」；部分实现允许直接给新 PIN。</para>
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int ReloadPinFn(IntPtr hCard, uint dataLen, [In] byte[] data, IntPtr reserved);

    /// <summary>
    /// HD_ChangePin(int hCard, byte* oldNewPin, uint totalLen)。ret 0xC（3 参数）。
    /// <para>缓冲区格式：<c>旧PIN + 0xFF + 新PIN</c>（DLL 内部以 0xFF 拆分，长度不含分隔符之外的填充）。</para>
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int HdChangePinFn(IntPtr hCard, [In] byte[] oldNewPin, uint totalLen);

    /// <summary>
    /// HD_VerifyPin(int hCard, byte* pin, uint pinLen)。ret 0xC（3 参数）。
    /// <para>用 PIN 作为密钥材料做挑战应答外部认证。0 = 通过；正数 = 剩余重试次数；-1 = 锁定/被拒。</para>
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int HdVerifyPinFn(IntPtr hCard, [In] byte[] pin, uint pinLen);

    /// <summary>HD_GET_BCDSN(int hCard, byte* sn)。ret 8（2 参数），读取设备序列号（BCD 文本）。</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int HdGetBcdSnFn(IntPtr hCard, [In, Out] byte[] sn);

    /// <summary>HD_GET_SN(int hCard, byte* sn)。ret 8（2 参数），读取 COS 层序列号。</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int HdGetSnFn(IntPtr hCard, [In, Out] byte[] sn);

    // ============ 认证 / 格式化子步骤（诊断与「SO 口令」备用链路） ============

    /// <summary>
    /// Get_Challenge(int hCard, uint len, byte* outBuf, ushort* sw)。ret 0x10（4 参数）。
    /// <para>APDU CLA 0x84。成功时返回实际字节数（如 8），失败返回 -1；状态字写入 <c>sw</c>。</para>
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int GetChallengeFn(IntPtr hCard, uint len, [In, Out] byte[] outBuf, out ushort sw);

    /// <summary>
    /// External_Authentication(int hCard, uint p1, byte* resp8, ushort* sw)。ret 0x10（4 参数）。
    /// <para>APDU CLA 0x82；P1=0 传输密钥、P1=1 用户 PIN、P1=2 管理员 PIN。
    /// 认证失败时 SW=0x63Cx（x = 剩余重试次数，0 表示已锁定）。</para>
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int ExternalAuthFn(IntPtr hCard, uint p1, [In] byte[] resp8, out ushort sw);

    /// <summary>
    /// Clear_DF(int hCard, ushort* sw)。ret 8（2 参数）。
    /// <para>私有 APDU <c>BF CE 00 00 00</c>：清除数据区（DF）—— 真正的「格式化」动作。</para>
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int ClearDfFn(IntPtr hCard, out ushort sw);

    /// <summary>Select_File(int hCard, a, b, c, d, ushort* sw)。ret 0x14（5 参数）。</summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int SelectFileFn(IntPtr hCard, uint a, uint b, uint c, uint d, out ushort sw);

    /// <summary>
    /// HDJIT_VerifyAdminPin(int hCard, byte* key, uint keyLen)。ret 0xC（3 参数）。
    /// <para>用<b>调用方提供的管理员口令</b>做外部认证（External_Authentication P1=2）。
    /// 返回 0 = 口令正确；-1 = 不匹配（每次失败消耗一次 P1=2 认证计数）。</para>
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int VerifyAdminPinFn(IntPtr hCard, [In] byte[] key, uint keyLen);

    /// <summary>
    /// HDJIT_ReloadPin(int hCard, byte* key, uint keyLen, byte* newPin, uint newPinLen)。ret 0x14（5 参数）。
    /// <para>管理员口令认证（P1=2）后写入 28 字节密钥记录（APDU CLA 0x84 INS 0xD4 P1=1 P2=0xF1）。</para>
    /// </summary>
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int JitReloadPinFn(IntPtr hCard, [In] byte[] key, uint keyLen,
        [In] byte[] newPin, uint newPinLen);
}
