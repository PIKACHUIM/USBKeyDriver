using System.Windows.Forms;
using USBKey.Core.Common;
using USBKey.Core.Licensing;

namespace USBKey.Manager;

/// <summary>
/// 授权激活窗体。管理模式启动、未获得合法授权时弹出：
/// 展示本机机器码与授权说明，允许填写授权内容（license JSON 明文）并保存到 license.key。
/// </summary>
internal sealed class LicenseActivateForm : Form
{
    private readonly AppContext _ctx;
    private readonly TextBox _machineCode;
    private readonly TextBox _licenseInput;
    private readonly Label _status;

    public LicenseActivateForm(AppContext ctx)
    {
        _ctx = ctx;
        Text = "授权激活 - " + AppConfig.SoftwareName;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(460, 350);
        Font = new Font("Microsoft YaHei UI", 9F);

        var mc = AppConfig.SoftwareName + " 管理模式需要有效的授权才能运行。";
        var tip1 = new Label { Left = 15, Top = 10, Width = 430, AutoSize = false, Text = mc, Height = 30 };

        var lbl1 = new Label { Left = 15, Top = 48, Text = "本机机器码（请提供给管理员生成授权）：", AutoSize = true };
        _machineCode = new TextBox { Left = 15, Top = 72, Width = 430, ReadOnly = true, Text = MachineCode.Get() };
        _machineCode.Cursor = Cursors.IBeam;

        var lbl2 = new Label { Left = 15, Top = 104, AutoSize = true, Text = "授权内容（license JSON，粘贴后保存）：" };
        _licenseInput = new TextBox { Left = 15, Top = 128, Width = 430, Height = 150, Multiline = true, ScrollBars = ScrollBars.Vertical, AcceptsReturn = true, WordWrap = false };

        _status = new Label { Left = 15, Top = 286, Width = 430, AutoSize = false, Height = 20, ForeColor = System.Drawing.Color.DarkRed };

        var btnCopy = new Button { Text = "复制机器码", Left = 15, Top = 310, Width = 100 };
        var btnSave = new Button { Text = "保存并验证授权", Left = 240, Top = 310, Width = 130 };
        var btnCancel = new Button { Text = "退出", Left = 375, Top = 310, Width = 70, DialogResult = DialogResult.Cancel };

        btnCopy.Click += (s, e) => Clipboard.SetText(_machineCode.Text);
        btnSave.Click += (s, e) => SaveAndVerify();
        btnCancel.Click += (s, e) => { };

        Controls.Add(tip1);
        Controls.Add(lbl1);
        Controls.Add(_machineCode);
        Controls.Add(lbl2);
        Controls.Add(_licenseInput);
        Controls.Add(_status);
        Controls.Add(btnCopy);
        Controls.Add(btnSave);
        Controls.Add(btnCancel);
    }

    private void SaveAndVerify()
    {
        var content = _licenseInput.Text.Trim();
        if (string.IsNullOrEmpty(content))
        {
            _status.Text = "请先粘贴授权内容。";
            return;
        }
        try
        {
            File.WriteAllText(AppPaths.LicenseFile, content);
            var (now, isNet, _) = NetworkTime.Now();
            if (!isNet) _status.Text = "警告：未能获取网络时间，授权时间依赖本机时钟。";
            else _status.Text = "";
            var result = LicenseVerifier.Check(AppPaths.LicenseFile, MachineCode.Get(), _ctx.Config.Platform, now);
            if (result.IsValid)
            {
                MessageBox.Show("授权验证通过。" + (result.Document?.Expiry is { } d ? " 有效期至 " + d : ""),
                    AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Information);
                DialogResult = DialogResult.OK;
            }
            else
            {
                _status.Text = "授权无效：" + result.Message;
            }
        }
        catch (Exception ex)
        {
            _status.Text = "保存失败：" + ex.Message;
        }
    }
}
