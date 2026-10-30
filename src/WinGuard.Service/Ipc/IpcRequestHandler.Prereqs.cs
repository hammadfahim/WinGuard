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
using WinGuard.Core.Firewall;
using WinGuard.Core.Ipc;
using WinGuard.Core.Model;

namespace WinGuard.Service.Ipc;

/// <summary>Prerequisite checks (audit policy, firewall service, event channels) for the CheckPrereqs IPC call.</summary>
public sealed partial class IpcRequestHandler
{
    // ---- prerequisites ----

    private async Task<PrereqsDto> CheckPrereqsAsync(CancellationToken ct)
    {
        var dto = new PrereqsDto();

        var auditEnabled = await QueryAuditLogonFailureAsync(ct).ConfigureAwait(false);
        dto.AuditLogonFailureEnabled = auditEnabled;

        var firewallRunning = false;
        try
        {
            firewallRunning = _firewall.IsServiceRunning();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Firewall service probe failed.");
        }

        dto.FirewallServiceRunning = firewallRunning;

        string? channelWarning = null;
        try
        {
            using var session = new EventLogSession();
            using var configuration = new EventLogConfiguration(RdpCoreTsDetector.ChannelName, session);
            dto.RdpCoreTsChannelEnabled = configuration.IsEnabled;
        }
        catch (Exception ex)
        {
            // Channel does not exist when the RDP role is not installed.
            dto.RdpCoreTsChannelEnabled = false;
            channelWarning = $"RdpCoreTS/Operational channel is not available: {ex.Message}";
        }

        var warnings = new List<string>();
        if (!auditEnabled)
        {
            warnings.Add("Logon failure auditing is disabled; RDP 4625 events will not be recorded. Enable it with: auditpol /set /subcategory:\"{0CCE9215-69AE-11D9-BED3-505054503030}\" /success:enable /failure:enable (the GUID form also works on localized Windows)");
        }

        if (!firewallRunning)
        {
            warnings.Add("Windows Defender Firewall service (MpsSvc) is not running; block rules will not take effect.");
        }

        if (channelWarning is not null)
        {
            warnings.Add(channelWarning);
        }
        else if (!dto.RdpCoreTsChannelEnabled)
        {
            warnings.Add("RdpCoreTS/Operational channel is disabled; the RDP TLS/NLA fallback detector will not see event 140.");
        }

        dto.FirewallPolicy = FirewallPolicyEvaluator.ReadSafely(_firewallPolicy);
        warnings.AddRange(dto.FirewallPolicy.Warnings);

        if (_settings.UndecryptableSecrets is { Count: > 0 } secrets)
        {
            warnings.Add($"The stored {string.Join(", ", secrets)} could not be decrypted here, so those notifications stay off. Enter the value again, or run under the account that stored it.");
        }

        dto.Warnings = warnings;
        return dto;
    }

    private async Task<bool> QueryAuditLogonFailureAsync(CancellationToken ct)
    {
        try
        {
            var auditpol = Path.Combine(Environment.SystemDirectory, "auditpol.exe");
            var startInfo = new ProcessStartInfo
            {
                FileName = auditpol,
                RedirectStandardOutput = true,
                RedirectStandardError = false,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            startInfo.ArgumentList.Add("/get");
            // Locale-independent subcategory GUID for "Logon" — the English name fails on
            // localized Windows (review P-M4).
            startInfo.ArgumentList.Add("/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}");
            startInfo.ArgumentList.Add("/r");

            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return false;
            }

            string output;
            try
            {
                output = await process.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
                await process.WaitForExitAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (Exception)
                {
                    // Already gone.
                }

                throw;
            }

            // Tolerate UTF-16 output on some builds.
            output = output.Replace("\0", string.Empty);
            return ParseAuditCsv(output);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not query the audit policy with auditpol.");
            return false;
        }
    }

    private static bool ParseAuditCsv(string csv)
    {
        var lines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length == 0)
        {
            return false;
        }

        var header = SplitCsvLine(lines[0]);
        var subcategoryIndex = FindColumn(header, "Subcategory");
        var inclusionIndex = FindColumn(header, "Inclusion Setting");
        var settingValueIndex = FindColumn(header, "Setting Value");

        for (var i = 1; i < lines.Length; i++)
        {
            var cells = SplitCsvLine(lines[i]);
            if (cells.Length == 0)
            {
                continue;
            }

            // The query is scoped by the locale-independent Logon subcategory GUID, so every
            // data row belongs to Logon regardless of its localized display name; only skip
            // structurally malformed rows.
            if (subcategoryIndex >= cells.Length)
            {
                continue;
            }

            // Prefer the numeric Setting Value (0=none,1=success,2=failure,3=both): it is
            // locale-independent, unlike the "Failure" text.
            if (settingValueIndex >= 0 && settingValueIndex < cells.Length
                && int.TryParse(cells[settingValueIndex].Trim(), out var settingValue))
            {
                return (settingValue & 2) != 0;
            }

            var inclusion = inclusionIndex >= 0 && inclusionIndex < cells.Length
                ? cells[inclusionIndex]
                : string.Join(",", cells);
            if (inclusion.Contains("Failure", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static string[] SplitCsvLine(string line)
    {
        if (string.IsNullOrEmpty(line))
        {
            return [];
        }

        var cells = new List<string>();
        var builder = new StringBuilder();
        var inQuotes = false;

        foreach (var c in line)
        {
            switch (c)
            {
                case '"':
                    inQuotes = !inQuotes;
                    break;
                case ',' when !inQuotes:
                    cells.Add(builder.ToString());
                    builder.Clear();
                    break;
                case '\r':
                    break;
                default:
                    builder.Append(c);
                    break;
            }
        }

        cells.Add(builder.ToString());
        return cells.ToArray();
    }

    private static int FindColumn(string[] header, string name)
    {
        for (var i = 0; i < header.Length; i++)
        {
            if (header[i].Trim().Contains(name, StringComparison.OrdinalIgnoreCase))
            {
                return i;
            }
        }

        return -1;
    }
}
