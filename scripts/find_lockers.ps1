$target = 'sample_dll.dll'
$matches = @()
Get-Process | ForEach-Object {
    try {
        foreach ($m in $_.Modules) {
            if ($m.ModuleName -ieq $target) {
                $matches += [PSCustomObject]@{ Id = $_.Id; ProcessName = $_.ProcessName; Path = $m.FileName }
            }
        }
    } catch { }
}
if ($matches.Count -eq 0) {
    Write-Host 'No process currently has sample_dll.dll loaded.'
} else {
    $matches | Format-Table -AutoSize
}
