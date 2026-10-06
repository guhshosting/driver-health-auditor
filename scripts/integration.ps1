param(
    [string]$Executable = 'build-native/Release/driver-health-auditor.exe',
    [string]$Tests = 'build-native/Release/dha_tests.exe',
    [string]$Output = 'artifacts/integration'
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $Output -Force | Out-Null
$exe = (Resolve-Path -LiteralPath $Executable).Path
$testExe = (Resolve-Path -LiteralPath $Tests).Path
function Assert($condition, [string]$message) { if (-not $condition) { throw $message } }
function Check-Relationships($audit) {
    Assert ($audit.schema_version -eq '1.0') 'Schema version'
    Assert ($audit.application_version -eq '1.0.0') 'Application version'
    Assert ($audit.summary.devices_examined -eq $audit.devices.Count) 'Device count'
    Assert ($audit.summary.drivers_correlated -eq $audit.drivers.Count) 'Driver count'
    $drivers = @{}; $devices = @{}
    foreach ($driver in $audit.drivers) {
        Assert (-not $drivers.ContainsKey($driver.id)) 'Duplicate driver ID'
        $drivers[$driver.id] = $driver
    }
    foreach ($device in $audit.devices) {
        Assert (-not $devices.ContainsKey($device.instance_id)) 'Duplicate device ID'
        $devices[$device.instance_id] = $device
        Assert ($drivers.ContainsKey($device.driver_id)) 'Device references absent driver'
        Assert ($drivers[$device.driver_id].device_ids -contains $device.instance_id) 'Reverse driver link'
    }
    foreach ($driver in $audit.drivers) {
        foreach ($id in $driver.device_ids) {
            Assert ($devices.ContainsKey($id)) 'Driver references absent device'
            Assert ($devices[$id].driver_id -eq $driver.id) 'Reverse device link'
        }
    }
    foreach ($finding in $audit.findings) {
        Assert ($drivers.ContainsKey($finding.driver_id)) 'Finding driver link'
        if ($null -ne $finding.device_id) { Assert ($devices.ContainsKey($finding.device_id)) 'Finding device link' }
    }
}
& $exe --json > "$Output/present.json" 2> "$Output/present.stderr"
Assert ($LASTEXITCODE -eq 0) 'Present audit exit'
$present = Get-Content "$Output/present.json" -Raw -Encoding utf8 | ConvertFrom-Json
Check-Relationships $present
Assert ($present.devices.Count -gt 0) 'Host enumeration empty'
Assert ($null -ne $present.host.elevated) 'Elevation status unavailable'
& $exe --all --json > "$Output/all.json" 2> "$Output/all.stderr"
Assert ($LASTEXITCODE -eq 0) 'All audit exit'
$all = Get-Content "$Output/all.json" -Raw -Encoding utf8 | ConvertFrom-Json
Check-Relationships $all
Assert ($all.devices.Count -ge $present.devices.Count) 'All inventory smaller than present'
$id = $present.devices[0].instance_id
& $exe --device $id.ToLowerInvariant() --json > "$Output/focused.json" 2> "$Output/focused.stderr"
Assert ($LASTEXITCODE -eq 0) 'Focused audit exit'
$focused = Get-Content "$Output/focused.json" -Raw -Encoding utf8 | ConvertFrom-Json
Check-Relationships $focused
Assert ($focused.devices.Count -eq 1 -and $focused.devices[0].instance_id -eq $id) 'Exact case-insensitive selection'
& $exe --device 'ROOT\DHA_NOT_PRESENT\0000' --json > "$Output/notfound.stdout" 2> "$Output/notfound.stderr"
Assert ($LASTEXITCODE -eq 3) 'Missing device exit'
Assert ((Get-Item "$Output/notfound.stdout").Length -eq 0) 'Failure JSON stdout must be clean'
& $exe --device 'ROOT\DHA_不存在_😀\0' --json > "$Output/unicode.stdout" 2> "$Output/unicode.stderr"
Assert ($LASTEXITCODE -eq 2) 'Windows-rejected Unicode instance ID format exit'
Assert ((Get-Item "$Output/unicode.stdout").Length -eq 0) 'Invalid Unicode selector stdout must be clean'
& $exe --invalid --json > "$Output/usage.stdout" 2> "$Output/usage.stderr"
Assert ($LASTEXITCODE -eq 2) 'Usage exit'
Assert ((Get-Item "$Output/usage.stdout").Length -eq 0) 'Usage stdout must be clean'
& $exe > "$Output/human.txt" 2> "$Output/human.stderr"
Assert ($LASTEXITCODE -eq 0) 'Human audit exit'
& $testExe --json-fixture > "$Output/fixture.json"
Assert ($LASTEXITCODE -eq 0) 'Fixture exit'
$fixture = Get-Content "$Output/fixture.json" -Raw -Encoding utf8 | ConvertFrom-Json
Check-Relationships $fixture
Assert ($fixture.devices[0].instance_id -eq 'ROOT\测试😀\1') 'Supplementary-plane Unicode roundtrip'
Assert ($fixture.devices[0].name.Contains("`n测试😀")) 'Escaped newline roundtrip'
Assert ($fixture.devices[0].problem_code -eq 999) 'Unknown problem roundtrip'
Assert ($null -eq $fixture.devices[0].service) 'Missing optional metadata must be null'
Assert ($fixture.drivers[0].catalog_signature.signer -eq '签名者') 'Unicode signer'
Assert ($null -eq $fixture.host.elevated) 'Unknown elevation must be null'
$schema = Join-Path $PSScriptRoot '../docs/json-schema.json'
foreach ($document in @('present', 'all', 'focused', 'fixture')) {
    Assert (Test-Json -Json (Get-Content "$Output/$document.json" -Raw -Encoding utf8) -SchemaFile $schema) "JSON schema: $document"
}
$report = [ordered]@{
    host = $present.host
    present = $present.summary
    all = $all.summary
    packages_resolved = @($present.drivers | Where-Object package_state -eq 'available').Count
    offline_trusted_catalogs = @($present.drivers | Where-Object { $_.catalog_signature.state -eq 'trusted_offline' }).Count
    services_inspected = @($present.drivers.services | Where-Object binary_state -eq 'available').Count
    offline_trusted_embedded = @($present.drivers.services | Where-Object { $_.embedded_signature.state -eq 'trusted_offline' }).Count
    json_relationships = 'passed'
    json_schema = 'passed'
    unicode_roundtrip = 'passed'
    cli_exits = 'passed'
}
$report | ConvertTo-Json -Depth 8 | Tee-Object "$Output/report.json"
