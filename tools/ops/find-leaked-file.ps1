# Name the file behind a kernel handle leak in the System process.
#
# Diagnosed on 2026-08-18: System (PID 4) held 16,705,584 File handles, all
# pointing at ONE FILE_OBJECT, granted 0x00120089 (read-only). That is a driver
# calling ZwCreateFile in a loop with no matching ZwClose. 78 GB of paged plus
# nonpaged pool went with it.
#
# This script finds the dominant FILE_OBJECT, duplicates one handle out of the
# System process, and asks the object manager for its name. Knowing the path
# usually names the driver immediately.
#
# MUST RUN ELEVATED. Duplicating a handle out of PID 4 needs SeDebugPrivilege.
# Run it BEFORE rebooting: a reboot reclaims the pool and destroys the evidence.
$ErrorActionPreference = 'Stop'

$admin = ([Security.Principal.WindowsPrincipal] `
          [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Write-Warning "NOT ELEVATED. Re-run from an admin PowerShell:"
    Write-Warning "  powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit 2
}

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class LeakFinder {
  [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int c, IntPtr b, int l, out int n);
  [DllImport("ntdll.dll")] static extern int NtQueryObject(IntPtr h, int c, IntPtr b, int l, out int n);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint a, bool i, int pid);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool DuplicateHandle(IntPtr sp, IntPtr sh, IntPtr tp, out IntPtr th, uint acc, bool inh, uint opt);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [StructLayout(LayoutKind.Sequential)]
  struct EntryEx { public IntPtr Object; public IntPtr Pid; public IntPtr Handle;
                   public uint Access; public ushort Trace; public ushort TypeIndex;
                   public uint Attrs; public uint Reserved; }

  public static string Find(int pid, ushort fileTypeIndex) {
    int len = 1 << 20; IntPtr buf = IntPtr.Zero; 
    for (int a = 0; a < 24; a++) {
      buf = Marshal.AllocHGlobal(len);
      int need; int st = NtQuerySystemInformation(64, buf, len, out need);
      if (st != 0) {
        Marshal.FreeHGlobal(buf); buf = IntPtr.Zero;
        if (st == unchecked((int)0xC0000004)) { len = Math.Max(need + need/8 + (1<<20), len*2); continue; }
        return "NtQuerySystemInformation failed: 0x" + st.ToString("X8");
      }
      long n = Marshal.ReadIntPtr(buf).ToInt64();
      int stride = Marshal.SizeOf(typeof(EntryEx)); long off = IntPtr.Size*2;
      // Find the most-repeated FILE_OBJECT and one handle value for it.
      var tally = new Dictionary<long,long>(); var sample = new Dictionary<long,IntPtr>();
      for (long i = 0; i < n; i++) {
        var e = (EntryEx)Marshal.PtrToStructure(new IntPtr(buf.ToInt64()+off+i*stride), typeof(EntryEx));
        if (e.Pid.ToInt64() != pid || e.TypeIndex != fileTypeIndex) continue;
        long k = e.Object.ToInt64();
        if (tally.ContainsKey(k)) tally[k]++; else { tally[k] = 1; sample[k] = e.Handle; }
      }
      Marshal.FreeHGlobal(buf); buf = IntPtr.Zero;
      long best = 0, bestN = 0;
      foreach (var kv in tally) if (kv.Value > bestN) { bestN = kv.Value; best = kv.Key; }
      if (bestN == 0) return "no File handles found in pid " + pid;

      IntPtr hProc = OpenProcess(0x0040, false, pid);           // PROCESS_DUP_HANDLE
      if (hProc == IntPtr.Zero)
        return String.Format("FILE_OBJECT 0x{0:X} held by {1:N0} handles; OpenProcess failed (err {2}) - are you elevated?",
                             best, bestN, Marshal.GetLastWin32Error());
      IntPtr dup;
      bool ok = DuplicateHandle(hProc, sample[best], GetCurrentProcess(), out dup, 0, false, 2);
      if (!ok) { CloseHandle(hProc);
        return String.Format("FILE_OBJECT 0x{0:X} held by {1:N0} handles; DuplicateHandle failed (err {2})",
                             best, bestN, Marshal.GetLastWin32Error()); }
      string name = "<unnamed>";
      IntPtr nb = Marshal.AllocHGlobal(8192);
      try {
        int need2; int s2 = NtQueryObject(dup, 1, nb, 8192, out need2);   // ObjectNameInformation
        if (s2 == 0) {
          short sl = Marshal.ReadInt16(nb);
          IntPtr sp = Marshal.ReadIntPtr(nb, IntPtr.Size);
          if (sp != IntPtr.Zero && sl > 0) name = Marshal.PtrToStringUni(sp, sl/2);
        } else name = "NtQueryObject failed 0x" + s2.ToString("X8");
      } finally { Marshal.FreeHGlobal(nb); CloseHandle(dup); CloseHandle(hProc); }

      return String.Format("LEAKED FILE\n  handles : {0:N0}\n  object  : 0x{1:X}\n  name    : {2}", bestN, best, name);
    }
    if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
    return "buffer never large enough";
  }
}
'@
Write-Output "Enumerating the system handle table (allocates ~700 MB briefly)..."
Write-Output ([LeakFinder]::Find(4, 42))
