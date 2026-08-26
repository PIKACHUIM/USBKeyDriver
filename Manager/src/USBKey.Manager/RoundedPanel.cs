using System.Drawing.Drawing2D;

namespace USBKey.Manager;

/// <summary>圆角卡片面板，用于现代化卡片式布局。</summary>
internal sealed class RoundedPanel : Panel
{
    public int CornerRadius { get; set; } = 12;

    public Color BorderColor { get; set; } = Color.FromArgb(0xD9, 0xDE, 0xE5);

    public int BorderThickness { get; set; } = 1;

    public RoundedPanel()
    {
        SetStyle(ControlStyles.UserPaint |
                 ControlStyles.AllPaintingInWmPaint |
                 ControlStyles.OptimizedDoubleBuffer |
                 ControlStyles.ResizeRedraw, true);
        BackColor = Color.White;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        var rect = new Rectangle(0, 0, Width - 1, Height - 1);
        using var path = CreateRoundedPath(rect, CornerRadius);
        using var brush = new SolidBrush(BackColor);
        e.Graphics.FillPath(brush, path);
        if (BorderThickness > 0)
        {
            using var pen = new Pen(BorderColor, BorderThickness);
            e.Graphics.DrawPath(pen, path);
        }
    }

    protected override void OnResize(EventArgs eventargs)
    {
        base.OnResize(eventargs);
        if (Width < 4 || Height < 4) return;
        using var path = CreateRoundedPath(new Rectangle(0, 0, Width, Height), CornerRadius + 1);
        Region = new Region(path);
    }

    private static GraphicsPath CreateRoundedPath(Rectangle rect, int radius)
    {
        int d = Math.Min(rect.Width, rect.Height);
        int r = Math.Clamp(radius, 1, d / 2);
        int dd = r * 2;
        var path = new GraphicsPath();
        path.AddArc(rect.X, rect.Y, dd, dd, 180, 90);
        path.AddArc(rect.Right - dd, rect.Y, dd, dd, 270, 90);
        path.AddArc(rect.Right - dd, rect.Bottom - dd, dd, dd, 0, 90);
        path.AddArc(rect.X, rect.Bottom - dd, dd, dd, 90, 90);
        path.CloseFigure();
        return path;
    }
}
