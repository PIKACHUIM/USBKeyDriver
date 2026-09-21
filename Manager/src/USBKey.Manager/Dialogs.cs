using System.Windows.Forms;

namespace USBKey.Manager;

/// <summary>通用输入对话框（PIN/密码/挑战码响应/新PIN 等）。</summary>
internal sealed class InputDialog : Form
{
    /// <summary>对话框内边距。</summary>
    private const int Pad = 16;
    /// <summary>按钮高度。</summary>
    private const int BtnH = 30;
    private const int MinClientWidth = 360;
    private const int MaxClientWidth = 560;

    private readonly TextBox _tb;

    public string Value => _tb.Text;

    /// <param name="prompt">提示文字，可含换行。</param>
    /// <param name="allowEmpty">是否允许留空后确定（凡是提示里写明"留空=使用默认值/跳过"的场景都必须传 true，
    /// 否则用户按提示留空会被"请输入内容"挡住）。</param>
    public InputDialog(string title, string prompt, bool masked = true, string defaultValue = "", bool allowEmpty = false)
    {
        Text = title;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.CenterParent;

        // 显式给每个子控件设同一字体：这样下面按 PreferredHeight 推算出来的行高与最终渲染一致，
        // 不依赖"加入控件树后继承父字体"的时序。
        var uiFont = new Font("Microsoft YaHei UI", 9F);
        Font = uiFont;

        // 尺寸按提示文字的实际占位推算（旧实现写死 ClientSize = 320x100）：
        // 提示有多行时标签会向下长高、直接压住输入框，用户看到的输入位置就没了。
        // 宽度取最长一行的实测宽度（封顶后自动换行），高度由换行后的标签高度推出。
        int longest = 0;
        foreach (var line in prompt.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
            longest = Math.Max(longest, TextRenderer.MeasureText(line, uiFont).Width);
        int clientW = Math.Clamp(longest + Pad * 2, MinClientWidth, MaxClientWidth);
        int contentW = clientW - Pad * 2;

        var lbl = new Label
        {
            AutoSize = true,
            MaximumSize = new Size(contentW, 0),   // 超过宽度即自动换行
            Font = uiFont,
            Text = prompt,
            Left = Pad,
            Top = Pad,
        };

        _tb = new TextBox { Font = uiFont, Left = Pad, Width = contentW, Text = defaultValue };
        if (masked) _tb.UseSystemPasswordChar = true;

        // 输入框排在标签实际高度之后（Label.PreferredHeight 已经计入 MaximumSize 引起的换行）
        _tb.Top = Pad + lbl.PreferredHeight + 8;
        _tb.Height = _tb.PreferredHeight;

        int btnTop = _tb.Bottom + 14;
        var ok = new Button
        {
            Text = "确定", Font = uiFont, Width = 88, Height = BtnH, Top = btnTop,
            Left = clientW - Pad - 88, DialogResult = DialogResult.OK,
        };
        var cancel = new Button
        {
            Text = "取消", Font = uiFont, Width = 82, Height = BtnH, Top = btnTop,
            Left = ok.Left - 8 - 82, DialogResult = DialogResult.Cancel,
        };
        ok.Click += (s, e) =>
        {
            if (allowEmpty || !string.IsNullOrEmpty(_tb.Text)) return;
            MessageBox.Show("请输入内容");
            DialogResult = DialogResult.None;
        };

        ClientSize = new Size(clientW, btnTop + BtnH + Pad);

        Controls.Add(lbl);
        Controls.Add(_tb);
        Controls.Add(ok);
        Controls.Add(cancel);
        AcceptButton = ok;
        CancelButton = cancel;
    }

    public static string? Ask(IWin32Window owner, string title, string prompt, bool masked = true,
        string defaultValue = "", bool allowEmpty = false)
    {
        using var dlg = new InputDialog(title, prompt, masked, defaultValue, allowEmpty);
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
