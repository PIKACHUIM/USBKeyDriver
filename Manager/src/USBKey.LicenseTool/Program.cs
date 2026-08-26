using System.Windows.Forms;
using USBKey.Core.Common;
using USBKey.Core.Configuration;
using USBKey.Core.Licensing;

namespace USBKey.LicenseTool;

static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new LicenseToolForm());
    }
}

/// <summary>
/// 授权生成终端：供授权管理员使用，输入目标机器的机器码、选择授权平台、设置有效期，
/// 生成 license.key 并保存。仅持有私钥的授权管理员可运行此工具。
/// </summary>
internal sealed class LicenseToolForm : Form
{
    private readonly TextBox _txtMachineCode;
    private readonly CheckedListBox _lstPlatforms;
    private readonly DateTimePicker _dtExpiry;
    private readonly TextBox _txtOutput;
    private readonly Button _btnGenerate, _btnSave;
    private string _generatedLicense = "";

    public LicenseToolForm()
    {
        Text = "USB Key 授权生成终端";
        ClientSize = new Size(540, 480);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Microsoft YaHei UI", 9F);

        var lbl1 = new Label { Text = "目标机器码（由用户管理端提供）：", Left = 14, Top = 14, AutoSize = true };
        _txtMachineCode = new TextBox { Left = 14, Top = 38, Width = 500, PlaceholderText = "XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX" };

        var lbl2 = new Label { Text = "授权平台（勾选一个或多个）：", Left = 14, Top = 74, AutoSize = true };
        _lstPlatforms = new CheckedListBox { Left = 14, Top = 98, Width = 500, Height = 80 };
        _lstPlatforms.Items.AddRange(new object[] { "lnca", "lnca1", "lnca2", "mock" });

        var lbl3 = new Label { Text = "授权有效期至：", Left = 14, Top = 188, AutoSize = true };
        _dtExpiry = new DateTimePicker { Left = 120, Top = 184, Width = 200, Format = DateTimePickerFormat.Short };
        _dtExpiry.Value = DateTime.Now.AddYears(1);

        _btnGenerate = new Button { Text = "生成授权", Left = 340, Top = 182, Width = 88 };
        _btnGenerate.Click += (s, e) => GenerateLicense();

        var lbl4 = new Label { Text = "生成的授权内容（JSON）：", Left = 14, Top = 222, AutoSize = true };
        _txtOutput = new TextBox { Left = 14, Top = 246, Width = 500, Height = 160, Multiline = true, ScrollBars = ScrollBars.Vertical, ReadOnly = true, WordWrap = false };

        _btnSave = new Button { Text = "保存为 license.key", Left = 14, Top = 420, Width = 140, Enabled = false };
        _btnSave.Click += (s, e) => SaveLicense();

        var btnCopy = new Button { Text = "复制到剪贴板", Left = 160, Top = 420, Width = 120 };
        btnCopy.Click += (s, e) =>
        {
            if (!string.IsNullOrEmpty(_generatedLicense)) Clipboard.SetText(_generatedLicense);
        };

        var btnClose = new Button { Text = "关闭", Left = 440, Top = 420, Width = 74 };
        btnClose.Click += (s, e) => Close();

        Controls.Add(lbl1);
        Controls.Add(_txtMachineCode);
        Controls.Add(lbl2);
        Controls.Add(_lstPlatforms);
        Controls.Add(lbl3);
        Controls.Add(_dtExpiry);
        Controls.Add(_btnGenerate);
        Controls.Add(lbl4);
        Controls.Add(_txtOutput);
        Controls.Add(_btnSave);
        Controls.Add(btnCopy);
        Controls.Add(btnClose);
    }

    private void GenerateLicense()
    {
        var mc = _txtMachineCode.Text.Trim();
        if (string.IsNullOrEmpty(mc) || mc.Length < 20)
        {
            MessageBox.Show("请输入有效的机器码（至少20字符）。", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var platforms = _lstPlatforms.CheckedItems.Cast<string>().ToList();
        if (platforms.Count == 0)
        {
            MessageBox.Show("请至少勾选一个授权平台。", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        try
        {
            var req = new LicenseIssueRequest
            {
                MachineCode = mc,
                Expiry = _dtExpiry.Value.Date,
                Platforms = platforms,
            };
            _generatedLicense = LicenseIssuer.Issue(req);
            _txtOutput.Text = _generatedLicense;
            _btnSave.Enabled = true;
            MessageBox.Show("授权生成成功。请复制授权内容或保存到文件，提供给用户。", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show("生成失败：" + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void SaveLicense()
    {
        using var sfd = new SaveFileDialog
        {
            Filter = "License Key (*.key)|*.key|JSON (*.json)|*.json|所有文件|*.*",
            FileName = "license.key",
            Title = "保存授权文件"
        };
        if (sfd.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            File.WriteAllText(sfd.FileName, _generatedLicense);
            MessageBox.Show("授权已保存到 " + sfd.FileName, Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show("保存失败：" + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
