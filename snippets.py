"""PowerShell command templates for the NtObjectManager MCP tools.

Every template uses @@TOKEN@@ placeholders rendered by render(). Strings are
single-quoted PS literals produced by ps_str() (quotes escaped by doubling).
JSON literals are inlined verbatim (JSON arrays are valid PS array literals
for our limited use: we always pass them as strings for ConvertFrom-Json).
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

_TOKEN_RE = re.compile(r"@@([A-Z0-9_]+)@@")


def ps_str(value: Optional[str]) -> str:
    """Render a Python string (or None) as a PowerShell single-quoted literal / $null."""
    if value is None:
        return "$null"
    return "'" + str(value).replace("'", "''") + "'"


def ps_bool(value: Any) -> str:
    return "$true" if value else "$false"


def render(template: str, **tokens: str) -> str:
    def sub(m: "re.Match[str]") -> str:
        name = m.group(1)
        if name not in tokens:
            raise KeyError(f"missing token {name} for template")
        return tokens[name]

    out = _TOKEN_RE.sub(sub, template)
    leftover = _TOKEN_RE.search(out)
    if leftover:
        raise KeyError(f"unresolved token {leftover.group(0)}")
    return out


# --------------------------------------------------------------------------
# Session init: import module, define state + helpers. Emits JSON readiness.
# --------------------------------------------------------------------------
INIT = r"""
$RPCMCP = @{ Servers = @{}; Clients = @{}; Order = (New-Object System.Collections.ArrayList) }
function __McpEvict {
  while ($RPCMCP.Servers.Count -ge 150 -and $RPCMCP.Order.Count -gt 0) {
    $old = $RPCMCP.Order[0]
    $RPCMCP.Order.RemoveAt(0)
    if ($old -and $RPCMCP.Servers.ContainsKey($old)) { $RPCMCP.Servers.Remove($old) | Out-Null }
  }
}
function __McpCache { param($key, $s, $file)
  __McpEvict
  $RPCMCP.Servers[$key] = @{ key = $key; server = $s; file = $file }
  $null = $RPCMCP.Order.Add($key)
}
function __McpIfJson { param($s, $key)
  [PSCustomObject]@{
    key = $key
    file = [string]$s.FilePath
    interface_id = [string]$s.InterfaceId
    version = ('{0}.{1}' -f $s.InterfaceVersion.Major, $s.InterfaceVersion.Minor)
    name = [string]$s.Name
    service = [string]$s.ServiceName
    service_display = [string]$s.ServiceDisplayName
    service_running = [bool]$s.IsServiceRunning
    procedure_count = [int]$s.ProcedureCount
    static_endpoints = @($s.Endpoints | ForEach-Object { $_.ToString() })
  }
}
function __McpParamJson { param($prm)
  $t = $prm.Type
  $tname = ''
  if ($null -ne $t) { $tname = $t.GetType().Name }
  $dir = 'in'
  if ($prm.IsIn -and $prm.IsOut) { $dir = 'inout' } elseif ($prm.IsOut) { $dir = 'out' }
  $isch = $false; $strict = $null
  if ($null -ne $t -and $t -is [NtCoreLib.Ndr.Dce.NdrContextHandleTypeReference]) { $isch = $true; $strict = [bool]$t.IsStrict }
  [PSCustomObject]@{ name = [string]$prm.Name; direction = $dir; ndr_type = $tname; is_context_handle = $isch; strict_context = $strict }
}
function __McpEpJson { param($e)
  $o = [ordered]@{ binding = $e.ToString() }
  foreach ($n in @('InterfaceId','ProtocolSequence','EndpointPath','Endpoint','Annotation','ProcessId')) {
    $p = $e.PSObject.Properties[$n]
    if ($null -ne $p) { try { $o[$n] = [string]$p.Value } catch { } }
  }
  [PSCustomObject]$o
}
function __McpEpBinding { param($e)
  $bs = $e.PSObject.Properties['BindingString']
  if ($bs -and $bs.Value) { return [string]$bs.Value }
  $proto = $e.PSObject.Properties['ProtocolSequence']
  $ep = $e.PSObject.Properties['EndpointPath']; if (-not $ep) { $ep = $e.PSObject.Properties['Endpoint'] }
  if ($proto -and $ep) { return ('{0}:[{1}]' -f [string]$proto.Value, [string]$ep.Value) }
  return $null
}
$ErrorActionPreference = 'Continue'
try { Import-Module NtObjectManager -ErrorAction Stop } catch { }
$m = Get-Module NtObjectManager
if ($m) {
  ('{"ready": true, "version": "' + $m.Version.ToString() + '"}')
} else {
  ('{"ready": false, "error": "NtObjectManager module not found. Install it first: Install-Module NtObjectManager -Scope CurrentUser"}')
}
"""

# --------------------------------------------------------------------------
# rpc_parse: parse a PE file, cache servers, return summary JSON.
# --------------------------------------------------------------------------
PARSE = r"""
$path = @@PATH@@
$prefix = @@PREFIX@@
$symbolPath = @@SYMBOLPATH@@
try {
  $servers = @()
  if ($symbolPath) { $servers = @(Get-RpcServer -Path $path -SymbolPath $symbolPath) }
  else { $servers = @(Get-RpcServer -Path $path) }
  $out = @()
  $i = 0
  foreach ($s in $servers) {
    $key = ('{0}_{1}' -f $prefix, $i)
    __McpCache $key $s $path
    $out += ,(__McpIfJson $s $key)
    $i++
  }
  [PSCustomObject]@{ file = $path; count = $out.Count; servers = $out } | ConvertTo-Json -Depth 5 -Compress
} catch {
  [PSCustomObject]@{ error = [string]$_.Exception.Message } | ConvertTo-Json -Compress
}
"""

# --------------------------------------------------------------------------
# rpc_state: dump cached servers + sessions.
# --------------------------------------------------------------------------
STATE = r"""
$servers = @($RPCMCP.Servers.Keys | Sort-Object | ForEach-Object { __McpIfJson $RPCMCP.Servers[$_].server $_ })
$clients = @($RPCMCP.Clients.Keys | Sort-Object | ForEach-Object {
  $e = $RPCMCP.Clients[$_]
  $vk = @()
  if ($e.vars) { $vk = @($e.vars.Keys | Sort-Object) }
  [PSCustomObject]@{ session = $_; server_key = [string]$e.key; interface_id = [string]$e.interface; binding = [string]$e.binding; connected_at = [string]$e.connected_at; vars = $vk }
})
[PSCustomObject]@{ module_loaded = [bool](Get-Module NtObjectManager); servers = $servers; sessions = $clients } | ConvertTo-Json -Depth 5 -Compress
"""

# --------------------------------------------------------------------------
# rpc_get_interface: full procedure/parameter detail for a cached server.
# --------------------------------------------------------------------------
GET_INTERFACE = r"""
$key = @@KEY@@
$e = $RPCMCP.Servers[$key]
if (-not $e) {
  [PSCustomObject]@{ error = ('unknown server key: ' + $key + ' (see rpc_state)') } | ConvertTo-Json -Compress
} else {
  $s = $e.server
  $procs = @()
  foreach ($p in @($s.Procedures)) {
    $pname = [string]$p.Name
    if (-not $pname) { $pname = 'Proc' + $p.ProcNum }
    $params = @()
    foreach ($prm in @($p.Params)) { $params += ,(__McpParamJson $prm) }
    $ret = $null
    if ($null -ne $p.ReturnValue) { $ret = __McpParamJson $p.ReturnValue }
    $procs += ,[PSCustomObject]@{ proc_num = [int]$p.ProcNum; name = $pname; params = $params; return_value = $ret }
  }
  $total = @($procs).Count
  $trunc = $false
  if ($total -gt 100) { $procs = @($procs | Select-Object -First 100); $trunc = $true }
  [PSCustomObject]@{
    key = $key; file = [string]$s.FilePath
    interface_id = [string]$s.InterfaceId
    version = ('{0}.{1}' -f $s.InterfaceVersion.Major, $s.InterfaceVersion.Minor)
    name = [string]$s.Name
    service = [string]$s.ServiceName
    service_running = [bool]$s.IsServiceRunning
    procedure_count = [int]$s.ProcedureCount
    procedures_truncated = $trunc
    procedures = $procs
  } | ConvertTo-Json -Depth 7 -Compress
}
"""

# --------------------------------------------------------------------------
# rpc_query_endpoints: endpoint mapper query (local or remote via -SearchBinding).
# --------------------------------------------------------------------------
QUERY_ENDPOINTS = r"""
$ifid = @@IFID@@
$searchBinding = @@SEARCHBIND@@
$findAlpc = @@FINDALPC@@
$limit = @@LIMIT@@
try {
  $pargs = @{}
  if ($ifid) { $pargs.InterfaceId = [guid]$ifid }
  if ($searchBinding) { $pargs.SearchBinding = $searchBinding }
  if ($findAlpc -and $ifid) { $pargs.FindAlpcPort = $true }
  $eps = @(Get-RpcEndpoint @pargs)
  $total = $eps.Count
  if ($limit -gt 0 -and $total -gt $limit) { $eps = @($eps | Select-Object -First $limit) }
  $out = @(); foreach ($e in $eps) { $out += ,(__McpEpJson $e) }
  [PSCustomObject]@{ total = $total; returned = $out.Count; endpoints = $out } | ConvertTo-Json -Depth 5 -Compress
} catch {
  [PSCustomObject]@{ error = [string]$_.Exception.Message } | ConvertTo-Json -Compress
}
"""

# --------------------------------------------------------------------------
# rpc_running_servers: enumerate RPC servers in a live process or service.
# --------------------------------------------------------------------------
RUNNING_SERVERS = r"""
$pid = @@PID@@
$svc = @@SVCNAME@@
try {
  $servers = @()
  $tag = ''
  if ($pid) { $servers = @(Get-RpcServer -ProcessId $pid); $tag = 'pid' + $pid }
  else { $servers = @(Get-RpcServer -ServiceName $svc); $tag = 'svc' + $svc }
  $out = @(); $i = 0
  foreach ($s in $servers) {
    $key = ('{0}_{1}' -f $tag, $i)
    __McpCache $key $s ([string]$s.FilePath)
    $out += ,(__McpIfJson $s $key)
    $i++
  }
  $eps = @()
  if ($pid) { try { $eps = @(Get-RpcEndpoint -ProcessId $pid) } catch { } }
  $epJson = @(); foreach ($e in $eps) { $epJson += ,(__McpEpJson $e) }
  [PSCustomObject]@{ count = $out.Count; servers = $out; process_endpoints = $epJson } | ConvertTo-Json -Depth 5 -Compress
} catch {
  [PSCustomObject]@{ error = [string]$_.Exception.Message } | ConvertTo-Json -Compress
}
"""

# --------------------------------------------------------------------------
# rpc_connect: build client from cached server and connect (stateful session).
# --------------------------------------------------------------------------
CONNECT = r"""
$session = @@SESSION@@
$key = @@KEY@@
$binding = @@BINDING@@
$authLevel = @@AUTHLEVEL@@
$authType = @@AUTHTYPE@@
$findAlpc = @@FINDALPC@@
$e = $RPCMCP.Servers[$key]
if (-not $e) {
  [PSCustomObject]@{ error = ('unknown server key: ' + $key + ' (see rpc_state)') } | ConvertTo-Json -Compress
} else {
  try {
    $s = $e.server
    if (-not $binding -and -not $findAlpc) {
      $eps = @(Get-RpcEndpoint -InterfaceId $s.InterfaceId)
      foreach ($ep in $eps) { $b = __McpEpBinding $ep; if ($b) { $binding = $b; break } }
    }
    $c = $s | Get-RpcClient
    $pargs = @{ Client = $c }
    if ($binding) { $pargs.StringBinding = $binding }
    if ($findAlpc) { $pargs.FindAlpcPort = $true }
    if ($authLevel) { $pargs.AuthenticationLevel = $authLevel }
    if ($authType) { $pargs.AuthenticationType = $authType }
    Connect-RpcClient @pargs
    $RPCMCP.Clients[$session] = @{ client = $c; key = $key; interface = [string]$s.InterfaceId; binding = [string]$binding; connected_at = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'); vars = @{} }
    [PSCustomObject]@{ session = $session; interface_id = [string]$s.InterfaceId; binding = [string]$binding; note = 'use rpc_methods to list callable methods' } | ConvertTo-Json -Compress
  } catch {
    [PSCustomObject]@{ error = [string]$_.Exception.Message } | ConvertTo-Json -Compress
  }
}
"""

# --------------------------------------------------------------------------
# rpc_methods: reflection listing of generated client methods.
# --------------------------------------------------------------------------
METHODS = r"""
$session = @@SESSION@@
$entry = $RPCMCP.Clients[$session]
if (-not $entry) {
  [PSCustomObject]@{ error = ('unknown session: ' + $session + ' (see rpc_state)') } | ConvertTo-Json -Compress
} else {
  $c = $entry.client
  $t = $c.GetType()
  $procMap = @{}
  $srvEntry = $RPCMCP.Servers[$entry.key]
  if ($srvEntry) {
    foreach ($p in @($srvEntry.server.Procedures)) {
      $pn = [string]$p.Name
      if (-not $pn) { $pn = 'Proc' + $p.ProcNum }
      if (-not $procMap.ContainsKey($pn)) { $procMap[$pn] = [int]$p.ProcNum }
    }
  }
  $ms = @($t.GetMethods() | Where-Object { $_.DeclaringType -eq $t -and -not $_.IsSpecialName -and $_.Name -notmatch '^(Dispose|Connect|Disconnect)' } | Select-Object -First 300)
  $out = @()
  foreach ($m in $ms) {
    $ps = @($m.GetParameters() | ForEach-Object { $_.ParameterType.Name + ' ' + $_.Name })
    $opnum = $null
    if ($m.Name -cmatch '_(\d+)$') { $opnum = [int]$Matches[1] }
    elseif ($procMap.ContainsKey($m.Name)) { $opnum = $procMap[$m.Name] }
    $out += ,[PSCustomObject]@{ name = $m.Name; return_type = $m.ReturnType.Name; params = $ps; opnum = $opnum }
  }
  [PSCustomObject]@{ session = $session; count = $out.Count; methods = $out } | ConvertTo-Json -Depth 5 -Compress
}
"""

# --------------------------------------------------------------------------
# rpc_call: reflection invoke of a generated client method.
# ARGS is a PS single-quoted JSON string; objects may use {"__ps__": "expr"}.
# --------------------------------------------------------------------------
CALL = r"""
$session = @@SESSION@@
$method = @@METHOD@@
$aj = @@ARGS@@
$storeAs = @@STOREAS@@
$entry = $RPCMCP.Clients[$session]
if (-not $entry) {
  [PSCustomObject]@{ error = ('unknown session: ' + $session + ' (see rpc_state)') } | ConvertTo-Json -Compress
} else {
  $c = $entry.client
  try {
    $rawArgs = @()
    if ($aj -and $aj -ne '[]') {
      $parsed = ConvertFrom-Json $aj
      $rawArgs = @($parsed)
    }
    $objArgs = @()
    foreach ($a in $rawArgs) {
      if ($null -eq $a) { continue }
      $isVar = $false; $isPs = $false
      if ($a -is [System.Management.Automation.PSCustomObject]) {
        if ($a.PSObject.Properties['__var__']) { $isVar = $true }
        elseif ($a.PSObject.Properties['__ps__']) { $isPs = $true }
      }
      if ($isVar) {
        $vn = [string]$a.__var__
        if (-not $entry.vars -or -not $entry.vars.ContainsKey($vn)) { throw ('unknown stored var: ' + $vn + ' (set one via store_as)') }
        $objArgs += ,([object]$entry.vars[$vn])
      } elseif ($isPs) {
        $objArgs += ,([object](Invoke-Expression ([string]$a.__ps__)))
      } else {
        $objArgs += ,([object]$a.PSObject.BaseObject)
      }
    }
    $mi = $c.GetType().GetMethods() | Where-Object { $_.Name -eq $method -and $_.DeclaringType -eq $c.GetType() } | Select-Object -First 1
    if (-not $mi) { throw ('method not found: ' + $method + ' (see rpc_methods)') }
    $r = $mi.Invoke($c, [object[]]$objArgs)
    $storedAs = $null
    if ($storeAs) {
      if (-not $entry.vars) { $entry.vars = @{} }
      $entry.vars[$storeAs] = $r
      $storedAs = $storeAs
    }
    $rjson = $null; $rtype = ''
    if ($null -ne $r) {
      $rtype = $r.GetType().FullName
      if ($r -is [string] -or $r.GetType().IsPrimitive) { $rjson = $r }
      else { try { $rjson = ($r | ConvertTo-Json -Depth 4 -Compress) } catch { $rjson = [string]$r } }
    }
    [PSCustomObject]@{ method = $method; result_type = $rtype; result = $rjson; stored_as = $storedAs } | ConvertTo-Json -Depth 5 -Compress
  } catch {
    $ie = $_.Exception
    if ($ie -is [System.Reflection.TargetInvocationException] -and $ie.InnerException) { $ie = $ie.InnerException }
    $status = $null
    $sp = $ie.GetType().GetProperty('StatusCode')
    if ($sp) { try { $status = [string]$sp.GetValue($ie, $null) } catch { } }
    [PSCustomObject]@{ ok = $false; error = [string]$ie.Message; error_type = $ie.GetType().FullName; rpc_status = $status } | ConvertTo-Json -Depth 4 -Compress
  }
}
"""

# --------------------------------------------------------------------------
# rpc_disconnect: drop a session.
# --------------------------------------------------------------------------
DISCONNECT = r"""
$session = @@SESSION@@
$e = $RPCMCP.Clients[$session]
if ($e) {
  try { $null = $e.client.Disconnect() } catch { }
  $RPCMCP.Clients.Remove($session) | Out-Null
  [PSCustomObject]@{ disconnected = $session } | ConvertTo-Json -Compress
} else {
  [PSCustomObject]@{ error = ('unknown session: ' + $session) } | ConvertTo-Json -Compress
}
"""

# --------------------------------------------------------------------------
# rpc_scan_context_handles (per file): flat context-handle records.
# --------------------------------------------------------------------------
CTX_SCAN = r"""
$path = @@PATH@@
try {
  $servers = @(Get-RpcServer -Path $path)
  $out = @()
  foreach ($s in $servers) {
    $recs = @()
    foreach ($p in @($s.Procedures)) {
      $pname = [string]$p.Name
      if (-not $pname) { $pname = 'Proc' + $p.ProcNum }
      foreach ($prm in @($p.Params)) {
        $t = $prm.Type
        if ($null -ne $t -and $t -is [NtCoreLib.Ndr.Dce.NdrContextHandleTypeReference]) {
          $dir = 'in'
          if ($prm.IsIn -and $prm.IsOut) { $dir = 'inout' } elseif ($prm.IsOut) { $dir = 'out' }
          $nm = [string]$prm.Name
          if (-not $nm) { $nm = 'unnamed' }
          $recs += ,[PSCustomObject]@{ proc_num = [int]$p.ProcNum; proc = $pname; param = $nm; direction = $dir; strict = [bool]$t.IsStrict }
        }
      }
    }
    if (@($recs).Count -gt 0) {
      $out += ,[PSCustomObject]@{
        file = $path
        interface_id = [string]$s.InterfaceId
        version = ('{0}.{1}' -f $s.InterfaceVersion.Major, $s.InterfaceVersion.Minor)
        service = [string]$s.ServiceName
        service_running = [bool]$s.IsServiceRunning
        procedure_count = [int]$s.ProcedureCount
        context_handle_params = $recs
      }
    }
  }
  [PSCustomObject]@{ file = $path; interfaces_with_ctx = @($out).Count; interfaces = $out } | ConvertTo-Json -Depth 7 -Compress
} catch {
  [PSCustomObject]@{ file = $path; error = [string]$_.Exception.Message } | ConvertTo-Json -Compress
}
"""

# --------------------------------------------------------------------------
# EPM registration check for one interface UUID.
# --------------------------------------------------------------------------
EPM_REGISTERED = r"""
$eps = @(Get-RpcEndpoint -InterfaceId ([guid]@@IFID@@) -ErrorAction SilentlyContinue)
$bindings = @(); foreach ($e in $eps) { $bindings += ,($e.ToString()) }
[PSCustomObject]@{ count = $eps.Count; bindings = $bindings } | ConvertTo-Json -Compress
"""

# --------------------------------------------------------------------------
# rpc_find_hijackable step 1: non-running services.
# --------------------------------------------------------------------------
SERVICES_LIST = r"""
$svcs = @(Get-CimInstance Win32_Service | Where-Object { $_.State -ne 'Running' } | Select-Object Name, DisplayName, StartMode, PathName)
$out = @()
foreach ($s in $svcs) {
  $out += ,[PSCustomObject]@{ name = [string]$s.Name; display = [string]$s.DisplayName; start = [string]$s.StartMode; path = [string]$s.PathName }
}
[PSCustomObject]@{ services = $out } | ConvertTo-Json -Depth 3 -Compress
"""

# --------------------------------------------------------------------------
# rpc_find_hijackable step 2: ServiceDll + DelayedAutoStart from registry.
# NAMES is a PS single-quoted JSON array string.
# --------------------------------------------------------------------------
SERVICE_REGISTRY = r"""
$names = ConvertFrom-Json @@NAMES@@
$out = @()
foreach ($n in $names) {
  $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $n
  $dll = $null; $delayed = $false
  try { $v = (Get-ItemProperty -Path ($base + '\Parameters') -Name ServiceDll -ErrorAction SilentlyContinue).ServiceDll; if ($v) { $dll = [Environment]::ExpandEnvironmentVariables([string]$v) } } catch { }
  try { $delayed = (((Get-ItemProperty -Path $base -Name DelayedAutoStart -ErrorAction SilentlyContinue).DelayedAutoStart) -eq 1) } catch { }
  $out += ,[PSCustomObject]@{ name = [string]$n; service_dll = $dll; delayed_autostart = $delayed }
}
[PSCustomObject]@{ services = $out } | ConvertTo-Json -Depth 3 -Compress
"""

# --------------------------------------------------------------------------
# rpc_interface_security: EPM state + ALPC SD (best effort) for cached server.
# --------------------------------------------------------------------------
INTERFACE_SECURITY = r"""
$key = @@KEY@@
$e = $RPCMCP.Servers[$key]
if (-not $e) {
  [PSCustomObject]@{ error = ('unknown server key: ' + $key + ' (see rpc_state)') } | ConvertTo-Json -Compress
} else {
  $s = $e.server
  $eps = @(); $epErr = ''
  try { $eps = @(Get-RpcEndpoint -InterfaceId $s.InterfaceId) } catch { $epErr = [string]$_.Exception.Message }
  $epJson = @(); foreach ($ep in $eps) { $epJson += ,(__McpEpJson $ep) }
  $alpcName = $null; $alpcSd = $null; $alpcErr = ''
  $alpc = @($eps | Where-Object { $_.ToString() -match 'ncalrpc' } | Select-Object -First 1)
  if ($alpc) {
    $b = __McpEpBinding $alpc[0]
    if ($b) { $alpcName = $b -replace '^ncalrpc:\[', '' -replace '\]$', '' }
  }
  if ($alpcName) {
    try {
      $ports = @(Get-AccessibleAlpcPort -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $alpcName } | Select-Object -First 1)
      if ($ports) {
        $sd = $ports[0].PSObject.Properties['SecurityDescriptor']
        if ($sd -and $sd.Value) {
          $sddl = $sd.Value.PSObject.Properties['Sddl']
          if ($sddl) { $alpcSd = [string]$sddl.Value } else { $alpcSd = [string]$sd.Value }
        }
      }
      if (-not $alpcSd) { $alpcErr = 'ALPC port SD not readable from this context: requires admin/SeDebugPrivilege (Get-AccessibleAlpcPort duplicates handles). Run the agent elevated to read SDDL.' }
    } catch { $alpcErr = [string]$_.Exception.Message }
  }
  [PSCustomObject]@{
    key = $key
    interface_id = [string]$s.InterfaceId
    service = [string]$s.ServiceName
    service_running = [bool]$s.IsServiceRunning
    epm_error = $epErr
    epm_endpoint_count = @($eps).Count
    epm_endpoints = $epJson
    alpc_port = $alpcName
    alpc_security_descriptor_sddl = $alpcSd
    alpc_error = $alpcErr
    note = 'Static parse cannot read runtime registration flags/security callback. Get the flags value via RE (RpcServerRegisterIf3 xref in IDA/Ghidra) then rpc_decode_flags. Check the ALPC SDDL for anonymous/everyone access like the MS-NRPC null-session research (Securelist 2025).'
  } | ConvertTo-Json -Depth 6 -Compress
}
"""

# --------------------------------------------------------------------------
# rpc_etw_unreachable: PhantomRPC-style ETW scan for RPC_S_SERVER_UNAVAILABLE.
# --------------------------------------------------------------------------
ETW_UNREACHABLE = r"""
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$traceName = @@NAME@@
$etl = Join-Path $env:TEMP ($traceName + '.etl')
$dur = @@DUR@@
$pattern = @@STATUSREGEX@@
$maxRes = @@MAXRES@@
try {
  $null = (logman stop $traceName -ets 2>&1)
  $createOut = (logman create trace $traceName -p 'Microsoft-Windows-RPC' -o $etl -ets 2>&1 | Out-String)
  if (-not (Test-Path $etl)) {
    [PSCustomObject]@{ admin = [bool]$admin; error = ('logman failed to start the trace: ' + $createOut.Trim()); hint = 'run the MCP agent as Administrator - ETW trace sessions require elevation' } | ConvertTo-Json -Depth 3 -Compress
  } else {
  $trigger = @@TRIGGER@@
  if ($trigger) { try { $null = (Invoke-Expression $trigger 2>&1 | Out-String) } catch { } }
  Start-Sleep -Seconds $dur
  $null = (logman stop $traceName -ets 2>&1)
  $events = @()
  if (Test-Path $etl) { $events = @(Get-WinEvent -Path $etl -Oldest -ErrorAction SilentlyContinue | Where-Object { $_.Id -in @(1, 5) } | Select-Object -First 20000) }
  $starts = @{}
  $hits = @()
  foreach ($ev in $events) {
    $x = $null
    try { $x = [xml]$ev.ToXml() } catch { continue }
    if ($null -eq $x.Event.EventData) { continue }
    $d = @{}
    foreach ($dd in @($x.Event.EventData.Data)) { if ($dd.Name) { $d[$dd.Name] = $dd.'#text' } }
    $act = ''
    if ($x.Event.System.Correlation) { $act = [string]$x.Event.System.Correlation.ActivityID }
    if ($ev.Id -eq 5) { $starts[$act] = $d }
    else {
      $st = [string]$d['Status']
      if ($st -and $st -match $pattern) {
        $sd = $starts[$act]
        if (-not $sd) { $sd = @{} }
        $hits += ,[PSCustomObject]@{
          status = $st; activity = $act
          interface_uuid = [string]$sd['Interface']; opnum = [string]$sd['ProcNum']
          endpoint = [string]$sd['Endpoint']; process_id = [string]$sd['ProcessID']
          network_address = [string]$sd['NetworkAddr']; protocol = [string]$sd['ProtocolSeq']
        }
        if (@($hits).Count -ge $maxRes) { break }
      }
    }
  }
  [PSCustomObject]@{
    admin = [bool]$admin; etl_file = $etl; duration_sec = $dur
    events_scanned = @($events).Count; hit_count = @($hits).Count; hits = $hits
    note = 'EXPERIMENTAL (PhantomRPC methodology, Kaspersky 2026): EventId 5 = RpcCallStart, EventId 1 = RpcCallStop; hits are calls failing with a status matching the regex (default targets RPC_S_SERVER_UNAVAILABLE / 0x6D1). A failing client can be pointed at an attacker-registered server; needs admin for logman.'
  } | ConvertTo-Json -Depth 6 -Compress
  }
} catch {
  [PSCustomObject]@{ admin = [bool]$admin; error = [string]$_.Exception.Message } | ConvertTo-Json -Compress
}
"""

# --------------------------------------------------------------------------
# rpc_format_client: export generated C# client source.
# --------------------------------------------------------------------------
FORMAT_CLIENT = r"""
$key = @@KEY@@
$outPath = @@OUTPATH@@
$e = $RPCMCP.Servers[$key]
if (-not $e) {
  [PSCustomObject]@{ error = ('unknown server key: ' + $key + ' (see rpc_state)') } | ConvertTo-Json -Compress
} else {
  try {
    $src = Format-RpcClient -Server $e.server
    if (-not $outPath) { $outPath = Join-Path (Get-Location).Path ('client_' + $key + '.cs') }
    [System.IO.File]::WriteAllText($outPath, [string]$src)
    [PSCustomObject]@{ key = $key; saved_to = $outPath; length = ([string]$src).Length; preview = ([string]$src).Substring(0, [Math]::Min(1200, ([string]$src).Length)) } | ConvertTo-Json -Depth 3 -Compress
  } catch {
    [PSCustomObject]@{ error = [string]$_.Exception.Message } | ConvertTo-Json -Compress
  }
}
"""

# --------------------------------------------------------------------------
# rpc_fuzz: phase-2-lite. Plan (dry-run) or execute primitive-only calls.
# DRYRUN: $true/$false; MAXPROCS: int.
# --------------------------------------------------------------------------
FUZZ = r"""
$session = @@SESSION@@
$dryRun = @@DRYRUN@@
$maxProcs = @@MAXPROCS@@
$entry = $RPCMCP.Clients[$session]
if (-not $entry) {
  [PSCustomObject]@{ error = ('unknown session: ' + $session + ' (see rpc_state)') } | ConvertTo-Json -Compress
} else {
  $c = $entry.client
  $t = $c.GetType()
  $procMap = @{}
  $srvEntry = $RPCMCP.Servers[$entry.key]
  if ($srvEntry) {
    foreach ($p in @($srvEntry.server.Procedures)) {
      $pn = [string]$p.Name
      if (-not $pn) { $pn = 'Proc' + $p.ProcNum }
      if (-not $procMap.ContainsKey($pn)) { $procMap[$pn] = [int]$p.ProcNum }
    }
  }
  $ms = @($t.GetMethods() | Where-Object { $_.DeclaringType -eq $t -and -not $_.IsSpecialName -and $_.Name -notmatch '^(Dispose|Connect|Disconnect)' })
  $plan = @(); $results = @()
  foreach ($m in $ms) {
    if (@($plan).Count -ge $maxProcs) { break }
    $ps = @($m.GetParameters())
    $allPrim = $true
    foreach ($p in $ps) { if (-not ($p.ParameterType.IsPrimitive -or $p.ParameterType -eq [string])) { $allPrim = $false } }
    $opnum = $null
    if ($m.Name -cmatch '_(\d+)$') { $opnum = [int]$Matches[1] }
    elseif ($procMap.ContainsKey($m.Name)) { $opnum = $procMap[$m.Name] }
    $note = ''
    if (-not $allPrim) { $note = 'complex params - build via rpc_new_struct / __ps__ then rpc_call' }
    $plan += ,[PSCustomObject]@{ method = $m.Name; opnum = $opnum; arg_count = $ps.Count; primitive_only = $allPrim; note = $note }
    if (-not $dryRun -and $allPrim) {
      $objArgs = @()
      foreach ($p in $ps) {
        if ($p.ParameterType -eq [string]) { $objArgs += ,'' }
        elseif ($p.ParameterType -eq [bool]) { $objArgs += ,$false }
        else { $objArgs += ,0 }
      }
      try {
        $r = $m.Invoke($c, [object[]]$objArgs)
        $cls = 'ok'; $det = ''
        if ($null -ne $r) { try { $det = [string]($r | ConvertTo-Json -Depth 2 -Compress) } catch { $det = [string]$r } }
        $results += ,[PSCustomObject]@{ method = $m.Name; opnum = $opnum; classification = $cls; detail = $det }
      } catch {
        $ie = $_.Exception
        if ($ie -is [System.Reflection.TargetInvocationException] -and $ie.InnerException) { $ie = $ie.InnerException }
        $msg = [string]$ie.Message
        $cls = 'error'
        if ($msg -match 'Access is denied|0x80070005|ACCESS_DENIED') { $cls = 'access_denied' }
        $results += ,[PSCustomObject]@{ ok = $false; method = $m.Name; opnum = $opnum; classification = $cls; detail = $msg.Substring(0, [Math]::Min(220, $msg.Length)) }
      }
    }
  }
  $counts = @{ ok = 0; access_denied = 0; error = 0 }
  foreach ($r in $results) { $counts[$r.classification] = $counts[$r.classification] + 1 }
  [PSCustomObject]@{ session = $session; dry_run = [bool]$dryRun; planned = @($plan).Count; executed = @($results).Count; counts = $counts; plan = $plan; results = $results } | ConvertTo-Json -Depth 6 -Compress
}
"""

# --------------------------------------------------------------------------
# rpc_new_struct: build an NDR complex-type instance in the client assembly.
# FIELDS: PS single-quoted JSON object string.
# --------------------------------------------------------------------------
NEW_STRUCT = r"""
$session = @@SESSION@@
$typeName = @@TYPE@@
$fields = @@FIELDS@@
$storeAs = @@STOREAS@@
$entry = $RPCMCP.Clients[$session]
if (-not $entry) {
  [PSCustomObject]@{ error = ('unknown session: ' + $session + ' (see rpc_state)') } | ConvertTo-Json -Compress
} else {
  try {
    $c = $entry.client
    $type = @($c.GetType().Assembly.GetTypes() | Where-Object { $_.Name -eq $typeName } | Select-Object -First 1)
    if (@($type).Count -eq 0) { throw ('type not found in client assembly: ' + $typeName) }
    $obj = [System.Activator]::CreateInstance($type[0])
    $setFields = @()
    if ($fields) {
      $fmap = ConvertFrom-Json $fields
      foreach ($prop in @($fmap.PSObject.Properties)) {
        $done = $false
        $fi = $obj.GetType().GetField($prop.Name)
        if ($fi) { try { $fi.SetValue($obj, ($prop.Value -as $fi.FieldType)); $done = $true } catch { } }
        if (-not $done) {
          $pi = $obj.GetType().GetProperty($prop.Name)
          if ($pi) { try { $pi.SetValue($obj, ($prop.Value -as $pi.PropertyType), $null); $done = $true } catch { } }
        }
        $setFields += ,[PSCustomObject]@{ field = $prop.Name; set = $done }
      }
    }
    if (-not $storeAs) { throw 'store_as is required (pass it back via {"__var__": name})' }
    if (-not $entry.vars) { $entry.vars = @{} }
    $entry.vars[$storeAs] = $obj
    [PSCustomObject]@{ stored_as = $storeAs; type = $type[0].FullName; fields = $setFields } | ConvertTo-Json -Depth 4 -Compress
  } catch {
    [PSCustomObject]@{ error = [string]$_.Exception.Message } | ConvertTo-Json -Compress
  }
}
"""

# --------------------------------------------------------------------------
# rpc_accessible_tasks: Get-AccessibleScheduledTask wrapper (Forshaw).
# --------------------------------------------------------------------------
ACCESSIBLE_TASKS = r"""
try {
  $tasks = @(Get-AccessibleScheduledTask | Select-Object -First 60)
  $out = @()
  foreach ($tk in $tasks) {
    $o = [ordered]@{}
    foreach ($pn in @('Name','FullPath','TaskName','Service','ServiceName','Access','AccessText','Executable','HasReadWrite','ReadWrite')) {
      $p = $tk.PSObject.Properties[$pn]
      if ($null -ne $p) { try { $o[$pn] = [string]$p.Value } catch { } }
    }
    $out += ,[PSCustomObject]$o
  }
  [PSCustomObject]@{ count = $out.Count; tasks = $out } | ConvertTo-Json -Depth 4 -Compress
} catch {
  [PSCustomObject]@{ error = [string]$_.Exception.Message } | ConvertTo-Json -Compress
}
"""

# --------------------------------------------------------------------------
# rpc_vars: list/clear session variables.
# --------------------------------------------------------------------------
VARS = r"""
$session = @@SESSION@@
$clear = @@CLEAR@@
$entry = $RPCMCP.Clients[$session]
if (-not $entry) {
  [PSCustomObject]@{ error = ('unknown session: ' + $session + ' (see rpc_state)') } | ConvertTo-Json -Compress
} else {
  if ($clear) {
    $n = 0
    if ($entry.vars) { $n = $entry.vars.Count; $entry.vars = @{} }
    [PSCustomObject]@{ cleared = $n } | ConvertTo-Json -Compress
  } else {
    $out = @()
    if ($entry.vars) {
      foreach ($k in @($entry.vars.Keys | Sort-Object)) {
        $tn = ''
        if ($null -ne $entry.vars[$k]) { $tn = $entry.vars[$k].GetType().FullName }
        $out += ,[PSCustomObject]@{ name = [string]$k; type = $tn }
      }
    }
    [PSCustomObject]@{ session = $session; vars = $out } | ConvertTo-Json -Depth 3 -Compress
  }
}
"""

# --------------------------------------------------------------------------
# rpc_clear_cache: drop all cached servers (sessions keep live clients).
# --------------------------------------------------------------------------
CLEAR_CACHE = r"""
$n = $RPCMCP.Servers.Count
$RPCMCP.Servers = @{}
$RPCMCP.Order = (New-Object System.Collections.ArrayList)
[PSCustomObject]@{ cleared = $n; note = 'connected sessions keep their clients; re-parse files to refill the cache' } | ConvertTo-Json -Compress
"""

# --------------------------------------------------------------------------
# rpc_alpc_squat: create an ALPC port with a chosen name and capture clients.
# NAME: port name (e.g. the fixed endpoint of a not-yet-running RPC service).
# --------------------------------------------------------------------------
ALPC_SQUAT = r"""
$name = @@NAME@@
$dur = @@DUR@@
$server = $null
try {
  $server = New-NtAlpcServer -Path ('\RPC Control\' + $name)
  $deadline = (Get-Date).AddSeconds($dur)
  $connections = 0
  $clients = @()
  while ((Get-Date) -lt $deadline) {
    $msg = $null
    try { $msg = Receive-NtAlpcMessage -Port $server -TimeoutMs 400 } catch { }
    if ($null -ne $msg) {
      $connections++
      $cid = $null
      foreach ($p in @($msg.PSObject.Properties)) {
        if ($p.Name -match 'ClientId|ClientProcess|ProcessId') { try { $cid = [string]$p.Value } catch { } }
      }
      $clients += ,[PSCustomObject]@{ client_hint = $cid; message_type = [string]$msg.GetType().Name }
    }
  }
  [PSCustomObject]@{ squatted_port = $name; duration_sec = $dur; connections = $connections; clients = @($clients | Select-Object -First 20); note = 'Raw ALPC capture: proves a racing client connected; it cannot complete the RPC handshake against this port. Full rogue-RPC hosting is not available in NtObjectManager 2.0.1 (no server builder); use this to validate races found by rpc_find_hijackable, then weaponize with the RPC-Racer toolset if needed.' } | ConvertTo-Json -Depth 5 -Compress
} catch {
  [PSCustomObject]@{ error = [string]$_.Exception.Message } | ConvertTo-Json -Compress
} finally {
  if ($server) { try { $server.Dispose() } catch { } }
}
"""
