using System.Windows.Forms;
using USBKey.Core.Common;
using USBKey.Core.Configuration;
using USBKey.Core.Licensing;

namespace USBKey.Manager;

static class Program
{
    public static AppContext? Ctx { get; private set; }

    /// <summary>单实例互斥锁，避免重复启动。</summary>
    private static Mutex? _mutex;

    [STAThread]
    static void Main()
    {
        // 高DPI 感知
        ApplicationConfiguration.Initialize();

        // 单实例
        _mutex = new Mutex(true, "USBKeyManager_SingleInstance", out bool createdNew);
        if (!createdNew)
        {
            MessageBox.Show("USB Key 管理端已在运行。", AppConfig.SoftwareName,
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (s, e) => Log.Error(e.Exception, "UI线程异常");
        AppDomain.CurrentDomain.UnhandledException += (s, e) => Log.Error(e.ExceptionObject as Exception ?? new Exception("未知"), "未处理异常");

        try
        {
            // 1. 加载配置
            var config = AppConfig.Load(AppPaths.ConfigFile);
            // 处理 keyslist 兼容：若为空，给出默认 mock 以便演示；真实环境由部署者填写。

            Ctx = new AppContext(config);
            Ctx.Initialize(watcherEnabled: true);

            // 2. 管理模式：先做授权校验；无效则进入激活流程（展示机器码+填授权引导）
            if (Ctx.IsAdminMode)
            {
                var valid = Ctx.TryValidateLicense();
                if (!valid)
                {
                    bool activated = false;
                    while (!activated)
                    {
                        using var lic = new LicenseActivateForm(Ctx);
                        activated = lic.ShowDialog() == DialogResult.OK;
                        if (!activated) break;
                    }
                    if (!activated)
                    {
                        MessageBox.Show("未完成授权激活，程序退出。", AppConfig.SoftwareName,
                            MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }
                }
            }

            // 3. 启动主界面（含托盘）
            Application.Run(new MainForm(Ctx));
        }
        catch (Exception ex)
        {
            Log.Error(ex, "启动失败");
            MessageBox.Show("启动失败：" + ex.Message, AppConfig.SoftwareName,
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            Ctx?.Dispose();
        }
    }
}
