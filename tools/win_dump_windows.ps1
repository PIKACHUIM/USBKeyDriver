# Dump the window/control text tree of a process, to inspect a GUI app's state
# without being able to see the screen.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File win_dump_windows.ps1 -ProcessName GM3000Admin
#
# Notes: keep this file pure ASCII (Windows PowerShell 5.1 reads BOM-less .ps1 as ANSI).
param(
    [string]$ProcessName = 'GM3000Admin',
    [int]$MaxDepth = 6
)

$src = @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class WinDump
{
    delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr p);
    [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);

    public static List<string> Dump(uint targetPid, int maxDepth)
    {
        var lines = new List<string>();
        EnumWindows((h, p) =>
        {
            uint pid;
            GetWindowThreadProcessId(h, out pid);
            if (pid == targetPid) Walk(h, 0, maxDepth, lines);
            return true;
        }, IntPtr.Zero);
        return lines;
    }

    static void Walk(IntPtr h, int depth, int maxDepth, List<string> lines)
    {
        var cls = new StringBuilder(256); GetClassNameW(h, cls, 256);
        var txt = new StringBuilder(1024); GetWindowTextW(h, txt, 1024);
        string text = txt.ToString().Replace("\r", " ").Replace("\n", " ");
        if (text.Length > 200) text = text.Substring(0, 200) + "...";
        lines.Add(new string(' ', depth * 2) + "[" + cls + "] handle=0x" + h.ToString("X") +
                  " visible=" + (IsWindowVisible(h) ? "1" : "0") + " text='" + text + "'");
        if (depth < maxDepth)
            EnumChildWindows(h, (c, p) => { Walk(c, depth + 1, maxDepth, lines); return true; }, IntPtr.Zero);
    }
}
'@

Add-Type -TypeDefinition $src -Language CSharp

$proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $proc) {
    Write-Output "[x] process '$ProcessName' not found"
    exit 1
}
Write-Output ("[i] pid=" + $proc.Id + " title='" + $proc.MainWindowTitle + "'")

$lines = [WinDump]::Dump([uint32]$proc.Id, $MaxDepth)
Write-Output ("[i] window nodes = " + $lines.Count)
foreach ($l in $lines) { Write-Output $l }
