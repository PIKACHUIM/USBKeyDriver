using System.Windows.Forms;
using USBKey.Core.Common;
using USBKey.Core.Configuration;
using USBKey.Core.Licensing;

namespace USBKey.Manager;

/// <summary>
/// 系统设置窗体：包含【用户设置】与【系统设置(管理)】两个页签。
/// 管理页签仅管理员模式可见。
/// </summary>
internal sealed class SettingsForm : Form
{
    private readonly AppContext _ctx;

    // 用户设置控件
    private CheckBox _chkDeleteCert = new(), _chkChangePin = new(), _chkAutoStart = new(), _chkAutoRegister = new();
    private NumericUpDown _numTimeout = new();
    private TextBox _txtCloud = new();

    // 系统/管理设置控件
    private CheckBox _sysDeleteCert = new(), _sysCloudImport = new(), _sysUnlock = new(), _sysExport = new();
    private Label _machineCode = new(), _licenseStatus = new(), _licenseExpiry = new();

    public SettingsForm(AppContext ctx)
    {
        _ctx = ctx;
        Text = "系统设置";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(520, 400);
        Font = new Font("Microsoft YaHei UI", 9F);

        var tabs = new TabControl { Dock = DockStyle.Fill, Font = new Font("Microsoft YaHei UI", 9F) };
        tabs.TabPages.Add(BuildUserTab());
        if (_ctx.IsAdminMode) tabs.TabPages.Add(BuildAdminTab());
        Controls.Add(tabs);

        var btnSave = new Button { Text = "保存", Left = 420, Top = 365, Width = 84, DialogResult = DialogResult.OK };
        btnSave.Click += (s, e) => SaveAll();
        Controls.Add(btnSave);
    }

    private TabPage BuildUserTab()
    {
        var page = new TabPage("用户设置") { Padding = new Padding(12) };

        var s = _ctx.Config.Settings;
        // 读取：允许修改密码/删除证书来自 features + settings(仅存pref, 功能可用性由features+settings共同判定)
        _chkDeleteCert = new CheckBox { Text = "允许删除证书", Left = 14, Top = 14, AutoSize = true, Checked = s.AllowDeleteCert };
        _chkChangePin = new CheckBox { Text = "允许修改密码", Left = 14, Top = 44, AutoSize = true, Checked = s.AllowChangePin };

        var lblTimeout = new Label { Text = "登录有效期（分钟）", Left = 14, Top = 78, AutoSize = true };
        _numTimeout = new NumericUpDown { Left = 150, Top = 74, Width = 70, Minimum = 1, Maximum = 1440, Value = s.LoginTimeoutMinutes };

        var lblCloud = new Label { Text = "云端证书导入地址", Left = 14, Top = 108, AutoSize = true };
        _txtCloud = new TextBox { Left = 150, Top = 104, Width = 220, Text = s.CloudEndpoint };

        _chkAutoStart = new CheckBox { Text = "开机自启动", Left = 14, Top = 138, AutoSize = true, Checked = s.AutoStart };
        _chkAutoRegister = new CheckBox
        {
            Text = "证书自动注册到系统（含私钥关联）",
            Left = 14, Top = 168, AutoSize = true, Checked = s.AutoRegisterCert,
        };
        var lblAutoRegHint = new Label
        {
            Left = 32, Top = 190, AutoSize = true,
            ForeColor = System.Drawing.Color.DimGray,
            Font = new Font("Microsoft YaHei UI", 8.25F),
            Text = "默认开启：新识别的 USB Key 会自动注册其上证书，注册时把卡内私钥容器一并写入系统，\n" +
                   "注册记录持久化保存，下次启动若证书库中缺失会自动重新注册。\n" +
                   "手动「注销」过的证书不会被自动加回来；解析不到厂商 CSP/KSP 时会报错而不会写入空壳证书。",
        };

        // 软件信息
        var group = new GroupBox { Text = "软件信息", Left = 14, Top = 226, Width = 470, Height = 140 };
        var lblName = new Label { Left = 20, Top = 26, AutoSize = true, Text = "名称：" + AppConfig.SoftwareName + "  v" + AppConfig.Version };
        var lblCopy = new Label { Left = 20, Top = 52, AutoSize = true, Text = "版权：" + AppConfig.Copyright };
        var lblBuild = new Label { Left = 20, Top = 78, AutoSize = true, Text = "构建日期：" + AppConfig.BuildDate };
        var lblPlat = new Label { Left = 20, Top = 104, AutoSize = true, Text = "支持平台：" + string.Join(", ", _ctx.Config.Platform ?? new()) };
        group.Controls.Add(lblName);
        group.Controls.Add(lblCopy);
        group.Controls.Add(lblBuild);
        group.Controls.Add(lblPlat);

        page.Controls.AddRange(new Control[] { _chkDeleteCert, _chkChangePin, lblTimeout, _numTimeout, lblCloud, _txtCloud, _chkAutoStart, _chkAutoRegister, lblAutoRegHint, group });
        return page;
    }

    private TabPage BuildAdminTab()
    {
        var page = new TabPage("系统设置(管理)") { Padding = new Padding(12) };
        var g = new GroupBox { Text = "用户权限配置（生成用户客户端 config）", Left = 14, Top = 14, Width = 470, Height = 130 };

        _sysDeleteCert = AddFeatureCheck(g, "允许用户删除证书", "delcert", 1);
        _sysCloudImport = AddFeatureCheck(g, "允许用户云端导入证书", "cloudimport", 2);
        _sysUnlock = AddFeatureCheck(g, "允许用户解锁设备", "unlock", 3);
        _sysExport = AddFeatureCheck(g, "允许用户导出证书", "exportcert", 4);

        // 授权信息
        var g2 = new GroupBox { Text = "授权信息", Left = 14, Top = 152, Width = 470, Height = 150 };
        _machineCode = new Label { Left = 20, Top = 26, AutoSize = true, Text = "机器码：" + MachineCode.Get() };
        bool hasLic = _ctx.License?.IsValid == true;
        _licenseStatus = new Label
        {
            Left = 20, Top = 50, AutoSize = true,
            Text = hasLic ? "授权状态：已授权" : "授权状态：无有效授权",
            ForeColor = hasLic ? System.Drawing.Color.ForestGreen : System.Drawing.Color.DarkRed,
        };
        _licenseExpiry = new Label { Left = 20, Top = 74, AutoSize = true, Text = "授权有效期：" + (_ctx.License?.ValidUntilUtc.ToString("yyyy-MM-dd") ?? "—") };
        var btnUpdate = new Button { Left = 20, Top = 108, Width = 140, Text = "更新授权" };
        btnUpdate.Click += (s, e) => { MessageBox.Show("请在软件目录 config/license.key 中更新授权文件，重启软件生效。", AppConfig.SoftwareName); };
        g2.Controls.Add(_machineCode);
        g2.Controls.Add(_licenseStatus);
        g2.Controls.Add(_licenseExpiry);
        g2.Controls.Add(btnUpdate);

        page.Controls.Add(g);
        page.Controls.Add(g2);
        return page;
    }

    private static CheckBox AddFeatureCheck(Control parent, string text, string feature, int row)
    {
        var cb = new CheckBox { Text = text, Left = 20, Top = 24 + (row - 1) * 26, AutoSize = true, Tag = feature };
        parent.Controls.Add(cb);
        return cb;
    }

    private void SaveAll()
    {
        var s = _ctx.Config.Settings;
        s.AllowDeleteCert = _chkDeleteCert.Checked;
        s.AllowChangePin = _chkChangePin.Checked;
        s.LoginTimeoutMinutes = (int)_numTimeout.Value;
        s.CloudEndpoint = _txtCloud.Text.Trim();
        s.AutoStart = _chkAutoStart.Checked;

        // 自动注册开关变化时立即生效（不必重启）：主窗体收到请求后会补跑一轮
        var autoRegisterChanged = s.AutoRegisterCert != _chkAutoRegister.Checked;
        s.AutoRegisterCert = _chkAutoRegister.Checked;
        if (autoRegisterChanged && s.AutoRegisterCert) _ctx.CertAutoRegisterRequested = true;

        // 管理模式：把用户权限反馈到 features 配置
        if (_ctx.IsAdminMode)
        {
            _ctx.Config.Features[FeatureKeys.DeleteCert] = _sysDeleteCert.Checked ? "enabled" : "disabled";
            _ctx.Config.Features[FeatureKeys.CloudImport] = _sysCloudImport.Checked ? "enabled" : "hidden";
            _ctx.Config.Features[FeatureKeys.UnlockDevice] = _sysUnlock.Checked ? "enabled" : "disabled";
            _ctx.Config.Features[FeatureKeys.ExportCert] = _sysExport.Checked ? "enabled" : "disabled";
        }

        try { _ctx.Config.Save(AppPaths.ConfigFile); }
        catch (Exception ex) { MessageBox.Show("保存配置失败：" + ex.Message); return; }
        MessageBox.Show("设置已保存。", AppConfig.SoftwareName, MessageBoxButtons.OK, MessageBoxIcon.Information);
        _ctx.RaiseStateChanged();
        DialogResult = DialogResult.OK;
    }
}
