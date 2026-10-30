using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinGuard.Core.Abstractions;
using WinGuard.Core.Config;
using WinGuard.Core.Detection;
using WinGuard.Core.Engine;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;

namespace WinGuard.Service.Ipc;

/// <summary>Secured named-pipe creation (P/Invoke DACL) and the bounded line reader.</summary>
public sealed partial class PipeServer
{
    // ---- secured pipe creation (review S-M2) ----

    private const int MaxLineBytes = 1024 * 1024;
    private const int SecurityDescriptorRevision = 1;
    private const int PipeUnlimitedInstances = 255;
    private const int PipeAccessDuplex = 0x00000003;
    private const int FileFlagOverlapped = 0x40000000;
    private const int PipeFirstPipeInstance = 0x00080000;
    private const int PipeTypeByte = 0x00000000;
    private const int PipeReadmodeByte = 0x00000000;
    private const int PipeWait = 0x00000000;
    private const int PipeRejectRemoteClients = 0x00000008;
    private const int ErrorAccessDenied = 5;
    private const int ErrorPipeBusy = 231;

    /// <summary>
    /// SYSTEM + Administrators only. Nothing is granted to other accounts: on a named pipe,
    /// write access includes the right to create further instances of the pipe, which would let
    /// any local user stand up a fake WinGuard endpoint for the (elevated) GUI to connect to.
    /// Identity is verified again per connection in <see cref="Authorize"/>.
    /// </summary>
    internal const string PipeSddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

    private NamedPipeServerStream CreateSecuredPipe()
    {
        var pipe = CreateSecuredPipe(PipeConstants.PipeName, PipeSddl, firstInstance: !_firstPipeInstanceCreated);
        _firstPipeInstanceCreated = true;
        return pipe;
    }

    /// <summary>
    /// Creates one instance of the pipe under the given security descriptor, or throws. There is no
    /// fallback: a pipe with the default DACL would let any local user talk to the service, so with
    /// no descriptor there is no pipe.
    /// </summary>
    /// <param name="pipeName">Pipe name without the <c>\\.\pipe\</c> prefix.</param>
    /// <param name="sddl">The descriptor, in SDDL.</param>
    /// <param name="firstInstance">Fail instead of silently adding an instance to a squatted name.</param>
    internal static NamedPipeServerStream CreateSecuredPipe(string pipeName, string sddl, bool firstInstance)
    {
        var openMode = PipeAccessDuplex | FileFlagOverlapped;
        if (firstInstance)
        {
            openMode |= PipeFirstPipeInstance;
        }

        var pipeMode = PipeTypeByte | PipeReadmodeByte | PipeWait | PipeRejectRemoteClients;
        var securityDescriptor = CreateSecurityDescriptor(sddl);

        try
        {
            var securityAttributes = new SecurityAttributes
            {
                nLength = Marshal.SizeOf<SecurityAttributes>(),
                lpSecurityDescriptor = securityDescriptor,
                bInheritHandle = false,
            };

            var handle = NativeMethods.CreateNamedPipe(
                @"\\.\pipe\" + pipeName,
                openMode,
                pipeMode,
                PipeUnlimitedInstances,
                4096,
                4096,
                0,
                ref securityAttributes);

            if (handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                handle.Dispose();
                throw new IOException(firstInstance && error is ErrorAccessDenied or ErrorPipeBusy
                    ? $@"The pipe name \\.\pipe\{pipeName} is already in use by another process (possible name squatting); WinGuard IPC cannot start."
                    : $"CreateNamedPipe failed with Win32 error {error}.");
            }

            return new NamedPipeServerStream(PipeDirection.InOut, isAsync: true, isConnected: false, handle);
        }
        finally
        {
            // The pipe object keeps its own copy of the descriptor.
            NativeMethods.LocalFree(securityDescriptor);
        }
    }

    private static IntPtr CreateSecurityDescriptor(string sddl)
    {
        if (NativeMethods.ConvertStringSecurityDescriptorToSecurityDescriptor(
                sddl, SecurityDescriptorRevision, out var securityDescriptor, IntPtr.Zero)
            && securityDescriptor != IntPtr.Zero)
        {
            return securityDescriptor;
        }

        throw new InvalidOperationException(
            $"Could not build the pipe's security descriptor (Win32 error {Marshal.GetLastWin32Error()}), " +
            "so the pipe was not opened: WinGuard IPC cannot start without it. Consoles cannot connect until this is resolved.");
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    private static class NativeMethods
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern SafePipeHandle CreateNamedPipe(
            string lpName,
            int dwOpenMode,
            int dwPipeMode,
            int nMaxInstances,
            int nOutBufferSize,
            int nInBufferSize,
            int nDefaultTimeOut,
            ref SecurityAttributes lpSecurityAttributes);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string stringSecurityDescriptor,
            int stringSDRevision,
            out IntPtr securityDescriptor,
            IntPtr securityDescriptorSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr LocalFree(IntPtr hMem);
    }

    /// <summary>UTF-8 line reader with a hard per-line byte cap (review S-N3).</summary>
    private sealed class BoundedLineReader
    {
        private readonly Stream _stream;
        private readonly ILogger _logger;
        private readonly byte[] _buffer = new byte[8192];
        private readonly MemoryStream _line = new();
        private int _start;
        private int _count;

        public BoundedLineReader(Stream stream, ILogger logger)
        {
            _stream = stream;
            _logger = logger;
        }

        /// <summary>
        /// Reads the next '\n'-terminated line (a trailing '\r' is trimmed). Returns null at
        /// EOF; throws <see cref="IOException"/> when a line exceeds <see cref="MaxLineBytes"/>.
        /// </summary>
        public async Task<string?> ReadLineAsync(CancellationToken ct)
        {
            while (true)
            {
                if (_start >= _count)
                {
                    _count = await _stream.ReadAsync(_buffer.AsMemory(0, _buffer.Length), ct).ConfigureAwait(false);
                    _start = 0;
                    if (_count == 0)
                    {
                        return _line.Length == 0 ? null : TakeLine();
                    }
                }

                var newline = Array.IndexOf(_buffer, (byte)'\n', _start, _count - _start);
                var end = newline >= 0 ? newline : _count;
                if (end > _start)
                {
                    _line.Write(_buffer, _start, end - _start);
                    _start = end;
                    if (_line.Length > MaxLineBytes)
                    {
                        _logger.LogWarning("IPC client exceeded the {Cap}-byte line cap; disconnecting it.", MaxLineBytes);
                        _line.SetLength(0);
                        throw new IOException($"IPC line exceeded the {MaxLineBytes}-byte cap.");
                    }
                }

                if (newline >= 0)
                {
                    _start++; // consume '\n'
                    return TakeLine();
                }
            }
        }

        private string TakeLine()
        {
            var text = Encoding.UTF8.GetString(_line.GetBuffer(), 0, (int)_line.Length);
            _line.SetLength(0);
            return text.EndsWith('\r') ? text[..^1] : text;
        }
    }
}
