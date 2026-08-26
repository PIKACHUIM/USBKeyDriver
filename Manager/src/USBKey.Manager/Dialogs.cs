using System.Windows.Forms;

namespace USBKey.Manager;

/// <summary>通用输入对话框（PIN/密码/挑战码响应/新PIN 等）。</summary>
internal sealed class InputDialog : Form
{
    private readonly TextBox _tb;
    private readonly bool _masked;

    public string Value => _tb.Text;

    public InputDialog(string title, string prompt, bool masked = true, string defaultValue = "")
    {
        _masked = masked;
        Text = title;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(320, 100);
        Font = new Font("Microsoft YaHei UI", 9F);

        var lbl = new Label { Text = prompt, Left = 14, Top = 12, AutoSize = true };
        _tb = new TextBox { Left = 14, Top = 36, Width = 292 };
        if (masked) _tb.UseSystemPasswordChar = true;
        _tb.Text = defaultValue;

        var ok = new Button { Text = "确定", Left = 130, Top = 66, Width = 88, DialogResult = DialogResult.OK };
        var cancel = new Button { Text = "取消", Left = 224, Top = 66, Width = 82, DialogResult = DialogResult.Cancel };
        ok.Click += (s, e) => { if (string.IsNullOrEmpty(_tb.Text)) { MessageBox.Show("请输入内容"); DialogResult = DialogResult.None; } };

        Controls.Add(lbl);
        Controls.Add(_tb);
        Controls.Add(ok);
        Controls.Add(cancel);
        AcceptButton = ok;
        CancelButton = cancel;
    }

    public static string? Ask(IWin32Window owner, string title, string prompt, bool masked = true, string defaultValue = "")
    {
        using var dlg = new InputDialog(title, prompt, masked, defaultValue);
        return dlg.ShowDialog(owner) == DialogResult.OK ? dlg.Value : null;
    }
}

/// <summary>选择对话框（从选项列表中选择）。</summary>
internal sealed class ChoiceDialog : Form
{
    private readonly ListBox _list;
    public string Selected => _list.SelectedItem as string ?? "";
    public int SelectedIndex => _list.SelectedIndex;

    public ChoiceDialog(string title, string prompt, string[] items)
    {
        Text = title;
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ClientSize = new Size(340, 220);
        Font = new Font("Microsoft YaHei UI", 9F);

        var lbl = new Label { Text = prompt, Left = 14, Top = 10, AutoSize = true };
        _list = new ListBox { Left = 14, Top = 34, Width = 312, Height = 150 };
        _list.Items.AddRange(items);

        var ok = new Button { Text = "确定", Left = 150, Top = 192, Width = 88, DialogResult = DialogResult.OK, Enabled = items.Length > 0 };
        var cancel = new Button { Text = "取消", Left = 244, Top = 192, Width = 82, DialogResult = DialogResult.Cancel };
        _list.DoubleClick += (s, e) => { if (_list.SelectedItem != null) DialogResult = DialogResult.OK; };
        ok.Click += (s, e) => { if (_list.SelectedItem == null) DialogResult = DialogResult.None; };

        Controls.Add(lbl);
        Controls.Add(_list);
        Controls.Add(ok);
        Controls.Add(cancel);
        AcceptButton = ok;
        CancelButton = cancel;
    }
}
