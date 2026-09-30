# vm_listener.ps1 - persistent HTTP bridge inside the lab VM.
# POST /rpcmcp/ {"ps":"<script>"} + X-Token: rpcmcp-bridge -> runs the script in
# a PERSISTENT guest runspace (NtObjectManager pre-imported once), returns
# {"output":"<stdout>"}.
#
# Stateful by design: variables, connected RPC clients and any objects created by
# one call survive into the next call (same runspace for the whole listener
# lifetime), mirroring the host engine in ps_engine.py. A fresh shell per request
# would drop the RPC client you just connected; that is exactly what this avoids.
#
# Research lab only: trusts the host-only/NAT network segment it is bound to.

$ErrorActionPreference = 'Continue'
$port = 8765
$token = 'rpcmcp-bridge'
$logDir = 'C:\rpcmcp'
$logFile = Join-Path $logDir 'listener.log'
$script:GuestTimeoutMs = 120000

function Write-Log([string]$msg) {
    try {
        if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        [System.IO.File]::AppendAllText($logFile, "$(Get-Date -Format s) $msg`r`n")
    } catch {}
}

# ---------------------------------------------------------------------------
# One persistent guest engine. A single runspace is created at startup and
# reused for every request; only the thin PowerShell wrapper the runspace is
# bound to is refreshed (e.g. after a timeout), so session state is preserved.
# ---------------------------------------------------------------------------
$script:GuestRunspace = $null
$script:GuestPs = $null

function Initialize-GuestEngine {
    $rs = [runspacefactory]::CreateRunspace()
    try { $rs.ApartmentState = [System.Threading.ApartmentState]::STA } catch {}
    try { $rs.ThreadOptions = [System.Management.Automation.PSThreadOptions]::ReuseThread } catch {}
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript("Import-Module NtObjectManager -ErrorAction SilentlyContinue")
    try { [void]$ps.Invoke() } catch {}
    $ps.Commands.Clear()
    try { $ps.Streams.Error.Clear() } catch {}
    try { $ps.Streams.Warning.Clear() } catch {}
    $script:GuestRunspace = $rs
    $script:GuestPs = $ps
}

function New-GuestPipeline {
    # Rebind a fresh wrapper to the SAME runspace (state preserved).
    if ($script:GuestPs) { try { $script:GuestPs.Dispose() } catch {} }
    $ps = [powershell]::Create()
    $ps.Runspace = $script:GuestRunspace
    $script:GuestPs = $ps
}

function Invoke-GuestScript([string]$psText) {
    $ps = $script:GuestPs
    if (-not $ps) { return "__ERROR__ guest engine not initialized" }

    $ps.Commands.Clear()
    foreach ($s in @($ps.Streams.Error, $ps.Streams.Warning, $ps.Streams.Verbose, $ps.Streams.Debug, $ps.Streams.Information)) {
        if ($null -ne $s) { try { $s.Clear() } catch {} }
    }

    [void]$ps.AddScript($psText)
    $async = $ps.BeginInvoke()
    if (-not $async.AsyncWaitHandle.WaitOne($script:GuestTimeoutMs)) {
        try { $ps.Stop() } catch {}
        try { [void]$ps.EndInvoke($async) } catch {}
        # Give the runspace a chance to free up before reusing it.
        $deadline = (Get-Date).AddSeconds(10)
        while ($script:GuestRunspace.RunspaceAvailability -ne 'Available' -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 200
        }
        if ($script:GuestRunspace.RunspaceAvailability -ne 'Available') {
            Write-Log "WARN: runspace stuck after timeout; recreating engine (state lost)"
            try { $script:GuestRunspace.Close() } catch {}
            try { $script:GuestRunspace.Dispose() } catch {}
            Initialize-GuestEngine
        } else {
            New-GuestPipeline
        }
        return "__TIMEOUT__"
    }

    $out = ''
    try {
        $result = $ps.EndInvoke($async)
        if ($null -ne $result) { $out = (($result | Out-String -Width 8192)).TrimEnd() }
    } catch {
        try { $ps.Stop() } catch {}
        $errMsg = $_.Exception.Message
        if ($_.Exception.InnerException -and $_.Exception.InnerException.Message) { $errMsg = $_.Exception.InnerException.Message }
        New-GuestPipeline
        return "__ERROR__ " + $errMsg
    }
    if (-not $out) {
        $errs = @($ps.Streams.Error | ForEach-Object { "$_" } | Where-Object { $_ })
        if ($errs.Count) { $out = "__ERROR__ " + ($errs -join "`n") }
    }
    $ps.Commands.Clear()
    return $out
}

Write-Log "boot: preparing persistent guest engine"
try {
    Initialize-GuestEngine
    Write-Log "guest engine ready (persistent runspace)"
} catch {
    Write-Log "FATAL: guest engine init failed: $($_.Exception.Message)"
    exit 1
}

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://+:$port/rpcmcp/")
try {
    $listener.Start()
} catch {
    Write-Log "FATAL: $($_.Exception.Message)"
    exit 1
}
Write-Log "listening on :$port (persistent guest engine) since $(Get-Date -Format s)"

while ($listener.IsListening) {
    $ctx = $listener.GetContext()
    try {
        $resp = $ctx.Response
        $resp.ContentType = 'application/json; charset=utf-8'
        $resp.Headers['Access-Control-Allow-Origin'] = '*'
        if ($ctx.Request.HttpMethod -eq 'GET') {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes('{"output":"rpcmcp bridge alive"}')
            $resp.ContentLength64 = $bytes.Length
            $resp.OutputStream.Write($bytes, 0, $bytes.Length)
            $resp.Close()
            continue
        }
        if ($ctx.Request.HttpMethod -ne 'POST' -or $ctx.Request.Url.AbsolutePath -notlike '*rpcmcp*') {
            $resp.StatusCode = 404
            $resp.Close()
            continue
        }
        if ($ctx.Request.Headers['X-Token'] -ne $token) {
            $resp.StatusCode = 403
            $bytes = [System.Text.Encoding]::UTF8.GetBytes('{"error":"bad token"}')
            $resp.ContentLength64 = $bytes.Length
            $resp.OutputStream.Write($bytes, 0, $bytes.Length)
            $resp.Close()
            continue
        }
        $reader = New-Object System.IO.StreamReader($ctx.Request.InputStream, [System.Text.Encoding]::UTF8)
        $bodyRaw = $reader.ReadToEnd()
        $psBody = $null
        try { $psBody = ([regex]::Unescape(($bodyRaw | ConvertFrom-Json).ps)) } catch { $psBody = $null }
        if (-not $psBody) {
            try { $psBody = $bodyRaw | ConvertFrom-Json | Select-Object -ExpandProperty ps } catch {}
        }
        if (-not $psBody) { $psBody = $bodyRaw }
        $out = Invoke-GuestScript $psBody
        $payload = @{ output = $out } | ConvertTo-Json -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
        $resp.ContentLength64 = $bytes.Length
        $resp.OutputStream.Write($bytes, 0, $bytes.Length)
        $resp.Close()
        Write-Log "ok len=$($out.Length)"
    } catch {
        try { $ctx.Response.Close() } catch {}
        Write-Log "ERR $($_.Exception.Message)"
    }
}
