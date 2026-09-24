# Persistent PowerShell loop for the NtObjectManager MCP engine.
# Protocol: one base64(UTF-8) script per line on stdin.
# Output: script result on stdout, then the marker line __MCP_DONE__.
# A line starting with __MCP_ERR__ signals the script threw.
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
while ($true) {
    $line = [Console]::In.ReadLine()
    if ($null -eq $line) { break }
    if ($line.Trim() -eq '') { continue }
    try {
        $script = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($line.Trim()))
    } catch {
        [Console]::Error.WriteLine('base64 decode failed')
        Write-Output '__MCP_DONE__'
        continue
    }
    try {
        $result = Invoke-Expression $script
        if ($null -ne $result) {
            if ($result -is [string]) { Write-Output $result } else { Write-Output ($result | Out-String -Width 8192) }
        }
    } catch {
        Write-Output ('__MCP_ERR__ ' + $_.Exception.Message)
    }
    [Console]::Out.Flush()
    Write-Output '__MCP_DONE__'
    [Console]::Out.Flush()
}
