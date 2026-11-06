<#
.SYNOPSIS
    Exports the MDO Mail Anomalies workbook findings to one self-contained HTML report.

.DESCRIPTION
    Reads Workbook\MDO-Mail-Anomalies.json, runs every workbook query against a Log Analytics
    (Microsoft Sentinel) workspace for the chosen time range, and writes a single HTML file with
    one section per workbook tab: tiles, charts (inline SVG), and result tables. The file has no
    external dependencies, so it can be attached to a ticket, emailed, or opened offline.

    The queries are read from the workbook file at run time, so the report always matches the
    workbook version in your copy of the repository.

    Authentication, in this order:
      1. -AccessToken
      2. The current Az PowerShell context (Connect-AzAccount)
      3. The Azure CLI (az login)
    The identity needs read access to the workspace, for example Log Analytics Reader or
    Microsoft Sentinel Reader.

    The report contains mailbox addresses, IP addresses, and message subjects from your tenant.
    Handle it as confidential.

.PARAMETER WorkspaceId
    The Log Analytics workspace ID (a GUID, shown as "Workspace ID" on the workspace overview page).

.PARAMETER TimeRange
    Relative time range ending now: 1h, 4h, 12h, 1d (default), 3d, 7d, 14d or 30d.

.PARAMETER StartTime
    Start of an absolute time range. Use with -EndTime instead of -TimeRange.

.PARAMETER EndTime
    End of an absolute time range. Defaults to now.

.PARAMETER Tab
    Tabs to include, by id (for example 'bombing', 'sequences') or label (for example '01*').
    Wildcards are allowed. Defaults to all tabs.

.PARAMETER OutputPath
    Path of the HTML file to write. Defaults to .\MDO-Anomalies-Report-<yyyyMMdd-HHmm>.html.

.PARAMETER MaxRows
    Maximum rows shown per table (default 250). The full row count is always reported.

.PARAMETER IncludeQueries
    Add the KQL that produced each result, in a collapsed block under it.

.PARAMETER WorkbookPath
    Workbook JSON to read the queries from. Defaults to ..\Workbook\MDO-Mail-Anomalies.json.

.PARAMETER Endpoint
    Log Analytics query endpoint. Defaults to https://api.loganalytics.io. For Azure Government
    use https://api.loganalytics.us.

.PARAMETER AccessToken
    A bearer token for the Log Analytics API, as a SecureString.

.EXAMPLE
    Connect-AzAccount
    .\Report\Export-MDOAnomaliesReport.ps1 -WorkspaceId 00000000-0000-0000-0000-000000000000 -TimeRange 7d

.EXAMPLE
    .\Report\Export-MDOAnomaliesReport.ps1 -WorkspaceId <id> -StartTime '2026-10-01' -EndTime '2026-10-08' -Tab sequences,inboxrules -IncludeQueries -OutputPath .\incident-1234.html
#>
[CmdletBinding(DefaultParameterSetName = 'Relative')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$WorkspaceId,

    [Parameter(ParameterSetName = 'Relative')]
    [ValidateSet('1h', '4h', '12h', '1d', '3d', '7d', '14d', '30d')]
    [string]$TimeRange = '1d',

    [Parameter(Mandatory, ParameterSetName = 'Absolute')]
    [datetime]$StartTime,

    [Parameter(ParameterSetName = 'Absolute')]
    [datetime]$EndTime = (Get-Date),

    [string[]]$Tab = @('*'),

    [string]$OutputPath,

    [ValidateRange(1, 10000)]
    [int]$MaxRows = 250,

    [switch]$IncludeQueries,

    [string]$WorkbookPath = (Join-Path $PSScriptRoot '..\Workbook\MDO-Mail-Anomalies.json'),

    [ValidatePattern('^https://')]
    [string]$Endpoint = 'https://api.loganalytics.io',

    [securestring]$AccessToken
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$inv = [Globalization.CultureInfo]::InvariantCulture
$isoFormat = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'"
$numericTypes = @('long', 'int', 'real', 'decimal', 'double')
$palette = @('#0078d4', '#d13438', '#107c10', '#ff8c00', '#8764b8', '#00b7c3', '#c239b3', '#498205', '#986f0b', '#69797e')

#region Time range
$utcNow = [datetime]::UtcNow
if ($PSCmdlet.ParameterSetName -eq 'Absolute') {
    $rangeEnd = $EndTime.ToUniversalTime()
    $rangeStart = $StartTime.ToUniversalTime()
    if ($rangeStart -ge $rangeEnd) { throw '-StartTime must be earlier than -EndTime.' }
    $rangeLabel = 'Custom'
} else {
    $spans = @{
        '1h' = [timespan]::FromHours(1); '4h' = [timespan]::FromHours(4); '12h' = [timespan]::FromHours(12)
        '1d' = [timespan]::FromDays(1); '3d' = [timespan]::FromDays(3); '7d' = [timespan]::FromDays(7)
        '14d' = [timespan]::FromDays(14); '30d' = [timespan]::FromDays(30)
    }
    $rangeEnd = $utcNow
    $rangeStart = $rangeEnd - $spans[$TimeRange]
    $rangeLabel = "Last $TimeRange"
}
$rangeSpan = $rangeEnd - $rangeStart
$startIso = $rangeStart.ToString($isoFormat, $inv)
$endIso = $rangeEnd.ToString($isoFormat, $inv)

# Approximates the automatic time grain the workbook picks for {TimeRange:grain}.
$grain = switch ($rangeSpan.TotalHours) {
    { $_ -le 1 } { '1m'; break }
    { $_ -le 4 } { '5m'; break }
    { $_ -le 12 } { '15m'; break }
    { $_ -le 24 } { '30m'; break }
    { $_ -le 72 } { '1h'; break }
    { $_ -le 168 } { '3h'; break }
    { $_ -le 336 } { '6h'; break }
    { $_ -le 720 } { '12h'; break }
    default { '1d' }
}
#endregion

#region Helpers
function ConvertTo-HtmlText([object]$Value) {
    if ($null -eq $Value) { return '' }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertFrom-SecureToken([securestring]$Secure) {
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}

function Get-LogAnalyticsToken {
    if ($AccessToken) { return ConvertFrom-SecureToken $AccessToken }
    $resource = $Endpoint.TrimEnd('/')
    if (Get-Command Get-AzAccessToken -ErrorAction SilentlyContinue) {
        try {
            $azToken = Get-AzAccessToken -ResourceUrl $resource -WarningAction SilentlyContinue -ErrorAction Stop
            if ($azToken.Token -is [securestring]) { return ConvertFrom-SecureToken $azToken.Token }
            return [string]$azToken.Token
        } catch {
            Write-Verbose "Az PowerShell token not available: $($_.Exception.Message)"
        }
    }
    if (Get-Command az -ErrorAction SilentlyContinue) {
        $cliToken = & az account get-access-token --resource $resource --query accessToken --output tsv 2>$null
        if ($LASTEXITCODE -eq 0 -and $cliToken) { return ([string]$cliToken).Trim() }
    }
    throw 'Could not get an access token. Run Connect-AzAccount or az login, or pass -AccessToken.'
}

function Get-ApiErrorText($ErrorRecord) {
    $text = $null
    if ($ErrorRecord.ErrorDetails) { $text = $ErrorRecord.ErrorDetails.Message }
    if (-not $text) { return $ErrorRecord.Exception.Message }
    try {
        $json = $text | ConvertFrom-Json
        $parts = New-Object System.Collections.Generic.List[string]
        $node = $json.error
        while ($node) {
            if ($node.PSObject.Properties['message'] -and $node.message) { $parts.Add([string]$node.message) }
            if ($node.PSObject.Properties['innererror']) { $node = $node.innererror } else { $node = $null }
        }
        if ($parts.Count) { return (($parts | Select-Object -Unique) -join ' ') }
    } catch { }
    return $text
}

function Invoke-WorkspaceQuery([string]$Query, [string]$Timespan) {
    $uri = '{0}/v1/workspaces/{1}/query' -f $Endpoint.TrimEnd('/'), $WorkspaceId
    $body = [Text.Encoding]::UTF8.GetBytes((@{ query = $Query; timespan = $Timespan } | ConvertTo-Json -Compress))
    $headers = @{ Authorization = "Bearer $script:token"; Prefer = 'wait=600' }
    for ($attempt = 1; ; $attempt++) {
        try {
            return Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Body $body -ContentType 'application/json' -TimeoutSec 660
        } catch {
            $status = 0
            if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if ($status -in 429, 500, 502, 503, 504 -and $attempt -lt 4) {
                $delay = [int][math]::Pow(2, $attempt) * 2
                Write-Verbose "HTTP $status, retrying in $delay s"
                Start-Sleep -Seconds $delay
                continue
            }
            throw (Get-ApiErrorText $_)
        }
    }
}

function Test-Numeric([string]$Type) { $numericTypes -contains $Type }

function ConvertTo-UtcDate([object]$Value) {
    if ($null -eq $Value -or [string]$Value -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $parsed = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse([string]$Value, $inv, $styles, [ref]$parsed)) { return $parsed }
    return $null
}

function Format-Number([double]$Number) {
    if ([double]::IsNaN($Number) -or [double]::IsInfinity($Number)) { return [string]$Number }
    if ($Number -eq [math]::Floor($Number) -and [math]::Abs($Number) -lt 1e15) { return $Number.ToString('N0', $inv) }
    return $Number.ToString('N2', $inv)
}

function Format-Cell([object]$Value, [string]$Type) {
    if ($null -eq $Value) { return '' }
    if ($Type -eq 'datetime' -or $Value -is [datetime]) {
        $date = ConvertTo-UtcDate $Value
        if ($date) { return $date.ToString('yyyy-MM-dd HH:mm:ss', $inv) }
    }
    if (($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) -or $Value -is [System.Management.Automation.PSCustomObject]) {
        return (ConvertTo-Json -InputObject $Value -Compress -Depth 10)
    }
    if ($Value -is [double] -or $Value -is [decimal]) { return ([double]$Value).ToString('0.##', $inv) }
    $text = [string]$Value
    if ($text.Length -gt 1000) { $text = $text.Substring(0, 1000) + ' ...' }
    return $text
}

function Format-InlineMarkdown([string]$Text) {
    $html = ConvertTo-HtmlText $Text
    $html = [regex]::Replace($html, '`([^`]+)`', '<code>$1</code>')
    $html = [regex]::Replace($html, '\*\*(.+?)\*\*', '<strong>$1</strong>')
    $html = [regex]::Replace($html, '\[([^\]]+)\]\((https?://[^\s)]+)\)', '<a href="$2">$1</a>')
    return $html
}

function ConvertFrom-WorkbookMarkdown([string]$Markdown) {
    $sb = New-Object System.Text.StringBuilder
    $paragraph = New-Object System.Collections.Generic.List[string]
    $inList = $false
    foreach ($line in ($Markdown -split "`r?`n")) {
        $isHeading = $line -match '^(#{1,6})\s+(.*)$'
        $isBullet = (-not $isHeading) -and ($line -match '^\s*[-*]\s+(.*)$')
        if ($isHeading -or $isBullet -or $line.Trim() -eq '') {
            if ($paragraph.Count) { [void]$sb.Append('<p>' + (Format-InlineMarkdown ($paragraph -join ' ')) + "</p>`n"); $paragraph.Clear() }
        }
        if ($inList -and -not $isBullet) { [void]$sb.Append("</ul>`n"); $inList = $false }
        if ($isHeading) {
            $level = [math]::Min($Matches[1].Length + 1, 6)
            [void]$sb.Append("<h$level>" + (Format-InlineMarkdown $Matches[2]) + "</h$level>`n")
        } elseif ($isBullet) {
            if (-not $inList) { [void]$sb.Append("<ul>`n"); $inList = $true }
            [void]$sb.Append('<li>' + (Format-InlineMarkdown $Matches[1]) + "</li>`n")
        } elseif ($line.Trim() -ne '') {
            $paragraph.Add($line.Trim())
        }
    }
    if ($paragraph.Count) { [void]$sb.Append('<p>' + (Format-InlineMarkdown ($paragraph -join ' ')) + "</p>`n") }
    if ($inList) { [void]$sb.Append("</ul>`n") }
    $sb.ToString()
}
#endregion

#region Renderers
function Get-ColumnIndex($Columns, [string]$Name) {
    for ($i = 0; $i -lt $Columns.Count; $i++) { if ($Columns[$i].name -eq $Name) { return $i } }
    return -1
}

function New-TableHtml($Columns, $Rows, [int]$Limit) {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="table-wrap"><table class="data"><thead><tr>')
    foreach ($c in $Columns) { [void]$sb.Append('<th title="Sort">' + (ConvertTo-HtmlText $c.name) + '</th>') }
    [void]$sb.Append('</tr></thead><tbody>')
    $shown = 0
    foreach ($row in $Rows) {
        if ($shown -ge $Limit) { break }
        [void]$sb.Append('<tr>')
        for ($i = 0; $i -lt $Columns.Count; $i++) {
            $cls = if (Test-Numeric $Columns[$i].type) { ' class="num"' } else { '' }
            [void]$sb.Append("<td$cls>" + (ConvertTo-HtmlText (Format-Cell $row[$i] $Columns[$i].type)) + '</td>')
        }
        [void]$sb.Append('</tr>')
        $shown++
    }
    [void]$sb.Append('</tbody></table></div>')
    if ($Rows.Count -gt $Limit) {
        [void]$sb.Append("<p class=`"note`">Showing the first $Limit of $($Rows.Count) rows. Use -MaxRows to show more.</p>")
    }
    $sb.ToString()
}

function New-TilesHtml($Columns, $Rows, $Settings) {
    $titleIdx = -1; $valueIdx = -1; $subIdx = -1
    if ($Settings) {
        if ($Settings.PSObject.Properties['titleContent']) { $titleIdx = Get-ColumnIndex $Columns $Settings.titleContent.columnMatch }
        if ($Settings.PSObject.Properties['leftContent']) { $valueIdx = Get-ColumnIndex $Columns $Settings.leftContent.columnMatch }
        if ($Settings.PSObject.Properties['secondaryContent']) { $subIdx = Get-ColumnIndex $Columns $Settings.secondaryContent.columnMatch }
    }
    if ($titleIdx -lt 0 -or $valueIdx -lt 0) { return $null }
    $numeric = Test-Numeric $Columns[$valueIdx].type
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="tiles">')
    foreach ($row in $Rows) {
        $value = $row[$valueIdx]
        $valueText = if ($null -ne $value -and $numeric) { Format-Number ([double]$value) } else { Format-Cell $value $Columns[$valueIdx].type }
        $hot = if ($null -ne $value -and $numeric -and [double]$value -gt 0) { ' hot' } else { '' }
        [void]$sb.Append("<div class=`"tile$hot`"><div class=`"tile-title`">" + (ConvertTo-HtmlText $row[$titleIdx]) + '</div>')
        [void]$sb.Append('<div class="tile-value">' + (ConvertTo-HtmlText $valueText) + '</div>')
        if ($subIdx -ge 0) { [void]$sb.Append('<div class="tile-sub">' + (ConvertTo-HtmlText $row[$subIdx]) + '</div>') }
        [void]$sb.Append('</div>')
    }
    [void]$sb.Append('</div>')
    $sb.ToString()
}

function New-BarsHtml($Columns, $Rows, [bool]$ShowShare) {
    $valueIdx = -1
    for ($i = $Columns.Count - 1; $i -ge 0; $i--) { if (Test-Numeric $Columns[$i].type) { $valueIdx = $i; break } }
    if ($valueIdx -lt 0) { return $null }
    $labelIdx = @(for ($i = 0; $i -lt $Columns.Count; $i++) { if ($i -ne $valueIdx -and -not (Test-Numeric $Columns[$i].type) -and $Columns[$i].type -ne 'datetime') { $i } })
    $totals = [ordered]@{}
    foreach ($row in $Rows) {
        $label = if ($labelIdx.Count) { (@(foreach ($i in $labelIdx) { Format-Cell $row[$i] $Columns[$i].type }) -join ' / ') } else { $Columns[$valueIdx].name }
        if ($label -eq '') { $label = '(empty)' }
        $v = if ($null -eq $row[$valueIdx]) { 0 } else { [double]$row[$valueIdx] }
        if ($totals.Contains($label)) { $totals[$label] += $v } else { $totals[$label] = $v }
    }
    $items = @($totals.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Key = $_.Key; Value = [double]$_.Value } } | Sort-Object Value -Descending)
    if ($items.Count -gt 15) {
        $other = ($items | Select-Object -Skip 14 | Measure-Object Value -Sum).Sum
        $items = @($items | Select-Object -First 14) + @([pscustomobject]@{ Key = 'Other'; Value = [double]$other })
    }
    $max = ($items | Measure-Object Value -Maximum).Maximum
    $sum = ($items | Measure-Object Value -Sum).Sum
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="bars">')
    $n = 0
    foreach ($item in $items) {
        $pct = if ($max -gt 0) { [math]::Round(100 * $item.Value / $max, 1) } else { 0 }
        $share = if ($ShowShare -and $sum -gt 0) { ' (' + [math]::Round(100 * $item.Value / $sum, 1).ToString($inv) + '%)' } else { '' }
        $color = $palette[$n % $palette.Count]
        [void]$sb.Append('<div class="bar-row"><span class="bar-label" title="' + (ConvertTo-HtmlText $item.Key) + '">' + (ConvertTo-HtmlText $item.Key) + '</span>')
        [void]$sb.Append("<span class=`"bar-track`"><span class=`"bar`" style=`"width:$(([double]$pct).ToString($inv))%;background:$color`"></span></span>")
        [void]$sb.Append('<span class="bar-value">' + (Format-Number $item.Value) + $share + '</span></div>')
        $n++
    }
    [void]$sb.Append('</div>')
    $sb.ToString()
}

function New-TimeChartHtml($Columns, $Rows) {
    $timeIdx = -1
    for ($i = 0; $i -lt $Columns.Count; $i++) { if ($Columns[$i].type -eq 'datetime') { $timeIdx = $i; break } }
    if ($timeIdx -lt 0) { return $null }
    $numIdx = @(for ($i = 0; $i -lt $Columns.Count; $i++) { if (Test-Numeric $Columns[$i].type) { $i } })
    if (-not $numIdx.Count) { return $null }
    $seriesIdx = @(for ($i = 0; $i -lt $Columns.Count; $i++) { if ($i -ne $timeIdx -and -not (Test-Numeric $Columns[$i].type)) { $i } })

    $series = @{}
    foreach ($row in $Rows) {
        $time = ConvertTo-UtcDate $row[$timeIdx]
        if (-not $time) { continue }
        $points = @()
        if ($seriesIdx.Count) {
            $name = (@(foreach ($i in $seriesIdx) { Format-Cell $row[$i] $Columns[$i].type }) -join ' / ')
            if ($name -eq '') { $name = '(empty)' }
            $v = if ($null -eq $row[$numIdx[0]]) { 0 } else { [double]$row[$numIdx[0]] }
            $points = @(, @($name, $v))
        } else {
            $points = @(foreach ($i in $numIdx) { if ($null -ne $row[$i]) { , @($Columns[$i].name, [double]$row[$i]) } })
        }
        foreach ($p in $points) {
            if (-not $series.ContainsKey($p[0])) { $series[$p[0]] = @{} }
            if ($series[$p[0]].ContainsKey($time.Ticks)) { $series[$p[0]][$time.Ticks] += $p[1] } else { $series[$p[0]][$time.Ticks] = $p[1] }
        }
    }
    if (-not $series.Count) { return $null }

    $ranked = @($series.Keys | Sort-Object { ($series[$_].Values | Measure-Object -Sum).Sum } -Descending)
    $dropped = [math]::Max(0, $ranked.Count - 10)
    $ranked = @($ranked | Select-Object -First 10)
    $allTicks = @($ranked | ForEach-Object { $series[$_].Keys })
    [long]$tMin = ($allTicks | Measure-Object -Minimum).Minimum
    [long]$tMax = ($allTicks | Measure-Object -Maximum).Maximum
    if ($tMax -eq $tMin) { $tMin -= [timespan]::FromHours(1).Ticks; $tMax += [timespan]::FromHours(1).Ticks }
    [double]$yMax = ($ranked | ForEach-Object { $series[$_].Values } | Measure-Object -Maximum).Maximum
    if ($yMax -le 0) { $yMax = 1 }
    $magnitude = [math]::Pow(10, [math]::Floor([math]::Log10($yMax)))
    $yMax = [math]::Ceiling($yMax / $magnitude) * $magnitude

    $w = 960; $h = 260; $ml = 64; $mr = 16; $mt = 10; $mb = 28
    $pw = $w - $ml - $mr; $ph = $h - $mt - $mb
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<svg class=`"chart`" viewBox=`"0 0 $w $h`" role=`"img`" preserveAspectRatio=`"xMidYMid meet`">")
    for ($g = 0; $g -le 4; $g++) {
        $y = $mt + $ph - ($ph * $g / 4)
        [void]$sb.Append([string]::Format($inv, '<line x1="{0}" y1="{1:0.#}" x2="{2}" y2="{1:0.#}" class="grid"/><text x="{3}" y="{4:0.#}" class="axis" text-anchor="end">{5}</text>', $ml, $y, ($w - $mr), ($ml - 6), ($y + 4), (Format-Number ($yMax * $g / 4))))
    }
    for ($g = 0; $g -le 4; $g++) {
        $ticks = [long]($tMin + ($tMax - $tMin) * $g / 4)
        $x = $ml + $pw * $g / 4
        $anchor = if ($g -eq 0) { 'start' } elseif ($g -eq 4) { 'end' } else { 'middle' }
        [void]$sb.Append([string]::Format($inv, '<text x="{0:0.#}" y="{1}" class="axis" text-anchor="{2}">{3}</text>', $x, ($h - 8), $anchor, ([datetime]$ticks).ToString('MM-dd HH:mm', $inv)))
    }
    $legend = New-Object System.Text.StringBuilder
    $n = 0
    foreach ($name in $ranked) {
        $color = $palette[$n % $palette.Count]
        $coords = @(foreach ($k in ($series[$name].Keys | Sort-Object)) {
            $x = $ml + $pw * ($k - $tMin) / ($tMax - $tMin)
            $y = $mt + $ph - ($ph * $series[$name][$k] / $yMax)
            [string]::Format($inv, '{0:0.#},{1:0.#}', $x, $y)
        })
        if ($coords.Count -eq 1) {
            $xy = $coords[0].Split(',')
            [void]$sb.Append("<circle cx=`"$($xy[0])`" cy=`"$($xy[1])`" r=`"3`" fill=`"$color`"><title>" + (ConvertTo-HtmlText $name) + '</title></circle>')
        } else {
            [void]$sb.Append("<polyline fill=`"none`" stroke=`"$color`" stroke-width=`"2`" points=`"$($coords -join ' ')`"><title>" + (ConvertTo-HtmlText $name) + '</title></polyline>')
        }
        $total = ($series[$name].Values | Measure-Object -Sum).Sum
        [void]$legend.Append("<span class=`"legend-item`"><span class=`"swatch`" style=`"background:$color`"></span>" + (ConvertTo-HtmlText $name) + ' <em>' + (Format-Number $total) + '</em></span>')
        $n++
    }
    [void]$sb.Append('</svg><div class="legend">' + $legend.ToString() + '</div>')
    if ($dropped) { [void]$sb.Append("<p class=`"note`">$dropped smaller series not drawn; see the data table.</p>") }
    $sb.ToString()
}
#endregion

#region Load workbook
$WorkbookPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WorkbookPath)
if (-not (Test-Path -LiteralPath $WorkbookPath -PathType Leaf)) { throw "Workbook not found: $WorkbookPath" }
$workbook = Get-Content -LiteralPath $WorkbookPath -Raw -Encoding UTF8 | ConvertFrom-Json

$tabLabels = @{}
foreach ($item in $workbook.items) {
    if ($item.type -eq 11 -and $item.content.PSObject.Properties['links']) {
        foreach ($link in $item.content.links) { if ($link.PSObject.Properties['subTarget']) { $tabLabels[$link.subTarget] = $link.linkLabel } }
    }
}
$workbookTitle = 'MDO Mail Anomalies'
$titleItem = $workbook.items | Where-Object { $_.type -eq 1 } | Select-Object -First 1
if ($titleItem -and $titleItem.content.json -match '(?m)^#\s+(.+?)\s*$') { $workbookTitle = $Matches[1].Trim() }

$tabs = @(foreach ($group in ($workbook.items | Where-Object { $_.type -eq 12 })) {
    $id = $group.name -replace '^group-', ''
    if ($group.PSObject.Properties['conditionalVisibility'] -and $group.conditionalVisibility) { $id = $group.conditionalVisibility.value }
    $label = if ($tabLabels.ContainsKey($id)) { $tabLabels[$id] } else { $id }
    $selected = $false
    foreach ($pattern in $Tab) { if ($id -like $pattern -or $label -like $pattern) { $selected = $true; break } }
    if ($selected) { [pscustomobject]@{ Id = $id; Label = $label; Items = @($group.content.items) } }
})
if (-not $tabs.Count) { throw "No workbook tabs match -Tab $($Tab -join ', '). Tab ids: $(@($tabLabels.Keys | Sort-Object) -join ', ')" }
#endregion

#region Run queries
$script:token = Get-LogAnalyticsToken
$queryTotal = @($tabs | ForEach-Object { $_.Items } | Where-Object { $_.type -eq 3 }).Count
$queryNumber = 0
$results = New-Object System.Collections.Generic.List[object]
foreach ($t in $tabs) {
    foreach ($item in $t.Items) {
        if ($item.type -ne 3) { continue }
        $c = $item.content
        $queryNumber++
        Write-Progress -Activity 'Running workbook queries' -Status "$($t.Label): $($c.title)" -PercentComplete (100 * $queryNumber / [math]::Max(1, $queryTotal))
        $kql = $c.query.Replace('{TimeRange:start}', $startIso).Replace('{TimeRange:end}', $endIso).Replace('{TimeRange:grain}', $grain).Replace('{TimeRange}', "between (datetime($startIso) .. datetime($endIso))")
        $windowStart = $rangeStart
        if ($c.PSObject.Properties['timeContext'] -and $c.timeContext -and $c.timeContext.durationMs) {
            $override = $rangeEnd.AddMilliseconds(-[double]$c.timeContext.durationMs)
            if ($override -lt $windowStart) { $windowStart = $override }
        }
        $timespan = '{0}/{1}' -f $windowStart.ToString($isoFormat, $inv), $endIso
        $entry = [ordered]@{ Tab = $t.Id; Name = $item.name; Title = $c.title; Query = $kql; Columns = @(); Rows = @(); Error = $null; Warning = $null }
        try {
            $response = Invoke-WorkspaceQuery $kql $timespan
            $table = @($response.tables | Where-Object { $_.name -eq 'PrimaryResult' } | Select-Object -First 1)
            if (-not $table.Count) { $table = @($response.tables | Select-Object -First 1) }
            if ($table.Count) {
                $entry.Columns = @($table[0].columns)
                $entry.Rows = @($table[0].rows)
            }
            if ($response.PSObject.Properties['error'] -and $response.error) {
                $entry.Warning = 'Partial results: ' + [string]$response.error.message
            }
        } catch {
            $entry.Error = $_.Exception.Message
            Write-Warning "$($t.Label) / $($c.title): $($entry.Error)"
        }
        $results.Add([pscustomobject]$entry)
    }
}
Write-Progress -Activity 'Running workbook queries' -Completed
$script:token = $null
#endregion

#region Build HTML
$css = @'
:root{--fg:#1b1b1b;--muted:#5f6368;--line:#e1e4e8;--bg:#fff;--soft:#f6f8fa;--accent:#0078d4;--hot:#d13438}
*{box-sizing:border-box}body{font:14px/1.5 "Segoe UI",system-ui,-apple-system,sans-serif;color:var(--fg);background:var(--bg);margin:0}
header{background:#0f2b46;color:#fff;padding:24px 32px}header h1{margin:0 0 4px;font-size:24px}header .meta{color:#c8d6e5;font-size:13px}
main{max-width:1280px;margin:0 auto;padding:16px 32px 48px}nav{background:var(--soft);border:1px solid var(--line);border-radius:6px;padding:12px 16px;margin:16px 0}
nav ol{columns:3;margin:0;padding-left:20px}nav li{break-inside:avoid}.controls{margin:8px 0 0;font-size:13px;color:var(--muted)}
h2{border-bottom:2px solid var(--accent);padding-bottom:4px;margin-top:40px}h3{font-size:16px;margin:24px 0 8px}h4,h5{margin:12px 0 6px}
.badge{display:inline-block;font-size:12px;font-weight:600;border-radius:10px;padding:1px 8px;margin-left:8px;background:var(--soft);border:1px solid var(--line);color:var(--muted);vertical-align:middle}
.badge.hit{background:#fde7e9;border-color:#f1bbbc;color:var(--hot)}.badge.err{background:#fff4ce;border-color:#f2d27a;color:#8a6100}
.desc{background:var(--soft);border-left:4px solid var(--accent);padding:4px 16px;margin:8px 0 16px}.desc h3,.desc h4{margin-top:8px}
code{background:#eef1f4;border-radius:3px;padding:0 4px;font-family:Consolas,monospace;font-size:12.5px}
.table-wrap{overflow:auto;max-height:520px;border:1px solid var(--line);border-radius:6px}
table.data{border-collapse:collapse;width:100%;font-size:12.5px}table.data th{position:sticky;top:0;background:#eef1f4;cursor:pointer;text-align:left;white-space:nowrap}
table.data th,table.data td{padding:4px 8px;border-bottom:1px solid var(--line);vertical-align:top}table.data td{max-width:480px;overflow-wrap:anywhere}td.num{text-align:right;white-space:nowrap}
table.data tbody tr:nth-child(even){background:#fafbfc}
.tiles{display:flex;flex-wrap:wrap;gap:10px}.tile{border:1px solid var(--line);border-radius:6px;padding:10px 14px;min-width:190px;flex:1 1 190px}
.tile-title{font-size:12.5px;color:var(--muted)}.tile-value{font-size:26px;font-weight:600}.tile.hot .tile-value{color:var(--hot)}.tile-sub{font-size:12px;color:var(--muted)}
.bars{display:grid;gap:4px}.bar-row{display:grid;grid-template-columns:minmax(120px,320px) 1fr 120px;gap:8px;align-items:center}
.bar-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.bar-track{background:var(--soft);border-radius:3px;height:14px}.bar{display:block;height:14px;border-radius:3px}.bar-value{font-variant-numeric:tabular-nums}
svg.chart{width:100%;height:auto;max-height:300px}svg .grid{stroke:var(--line)}svg .axis{fill:var(--muted);font-size:11px}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:12.5px;margin-top:4px}.swatch{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px}.legend em{color:var(--muted);font-style:normal}
.empty{color:var(--muted);font-style:italic}.error{background:#fff4ce;border:1px solid #f2d27a;border-radius:6px;padding:8px 12px;font-family:Consolas,monospace;font-size:12.5px;white-space:pre-wrap}
.note{color:var(--muted);font-size:12.5px}details{margin:6px 0}summary{cursor:pointer;color:var(--accent)}pre{background:#0f2b46;color:#e6edf3;padding:12px;border-radius:6px;overflow:auto;font-size:12px}
footer{color:var(--muted);font-size:12px;border-top:1px solid var(--line);margin-top:40px;padding-top:12px}
body.hits-only article[data-rows="0"]:not([data-error]){display:none}
@media print{header{background:none;color:#000}header .meta{color:#000}nav .controls,details{display:none}.table-wrap{max-height:none;overflow:visible}section{break-before:page}}
'@

$js = @'
document.querySelectorAll('table.data th').forEach(function(th){th.addEventListener('click',function(){
var table=th.closest('table'),body=table.tBodies[0],i=Array.prototype.indexOf.call(th.parentNode.children,th),asc=th.dataset.asc!=='1';
th.dataset.asc=asc?'1':'0';var num=/^-?[\d,]*\.?\d+$/;
Array.prototype.slice.call(body.rows).sort(function(a,b){var x=a.cells[i].textContent,y=b.cells[i].textContent,r;
if(num.test(x)&&num.test(y)){r=parseFloat(x.replace(/,/g,''))-parseFloat(y.replace(/,/g,''))}else{r=x.localeCompare(y)}return asc?r:-r})
.forEach(function(r){body.appendChild(r)})})});
var box=document.getElementById('hitsOnly');if(box){box.addEventListener('change',function(){document.body.classList.toggle('hits-only',box.checked)})}
'@

$withRows = @($results | Where-Object { -not $_.Error -and $_.Rows.Count -gt 0 }).Count
$failed = @($results | Where-Object { $_.Error }).Count
$generated = $utcNow.ToString('yyyy-MM-dd HH:mm', $inv) + ' UTC'
$rangeText = '{0} ({1} to {2} UTC)' -f $rangeLabel, $rangeStart.ToString('yyyy-MM-dd HH:mm', $inv), $rangeEnd.ToString('yyyy-MM-dd HH:mm', $inv)

$html = New-Object System.Text.StringBuilder
[void]$html.Append("<!DOCTYPE html>`n<html lang=`"en`"><head><meta charset=`"utf-8`"><meta name=`"viewport`" content=`"width=device-width, initial-scale=1`"><meta name=`"robots`" content=`"noindex`">")
[void]$html.Append('<title>' + (ConvertTo-HtmlText "$workbookTitle - $rangeText") + "</title><style>$css</style></head><body>`n")
[void]$html.Append('<header><h1>' + (ConvertTo-HtmlText $workbookTitle) + '</h1><div class="meta">')
[void]$html.Append('Workspace ' + (ConvertTo-HtmlText $WorkspaceId) + ' &middot; ' + (ConvertTo-HtmlText $rangeText) + ' &middot; Generated ' + (ConvertTo-HtmlText $generated))
[void]$html.Append("<br>$($results.Count) queries &middot; $withRows with results &middot; $failed failed &middot; Confidential: contains tenant mail and identity data</div></header><main>`n")

[void]$html.Append('<nav><strong>Tabs</strong><ol>')
foreach ($t in $tabs) {
    $tabResults = @($results | Where-Object { $_.Tab -eq $t.Id })
    $hits = @($tabResults | Where-Object { -not $_.Error -and $_.Rows.Count -gt 0 }).Count
    $errs = @($tabResults | Where-Object { $_.Error }).Count
    $badge = if ($hits) { "<span class=`"badge hit`">$hits/$($tabResults.Count)</span>" } else { "<span class=`"badge`">0/$($tabResults.Count)</span>" }
    if ($errs) { $badge += "<span class=`"badge err`">$errs failed</span>" }
    [void]$html.Append("<li><a href=`"#tab-$(ConvertTo-HtmlText $t.Id)`">" + (ConvertTo-HtmlText $t.Label) + "</a>$badge</li>")
}
[void]$html.Append('</ol><div class="controls"><label><input type="checkbox" id="hitsOnly"> Only show queries that returned results</label> &middot; Badges show queries with results / queries run. Click a column header to sort.</div></nav>' + "`n")

foreach ($t in $tabs) {
    [void]$html.Append("<section id=`"tab-$(ConvertTo-HtmlText $t.Id)`"><h2>" + (ConvertTo-HtmlText $t.Label) + "</h2>`n")
    foreach ($item in $t.Items) {
        if ($item.type -eq 1) {
            [void]$html.Append('<div class="desc">' + (ConvertFrom-WorkbookMarkdown $item.content.json) + "</div>`n")
            continue
        }
        if ($item.type -ne 3) { continue }
        $r = $results | Where-Object { $_.Tab -eq $t.Id -and $_.Name -eq $item.name } | Select-Object -First 1
        $c = $item.content
        $rowCount = if ($r.Error) { 0 } else { $r.Rows.Count }
        $errAttr = if ($r.Error) { ' data-error="1"' } else { '' }
        [void]$html.Append("<article data-rows=`"$rowCount`"$errAttr><h3>" + (ConvertTo-HtmlText $c.title))
        if ($r.Error) { [void]$html.Append('<span class="badge err">failed</span>') }
        elseif ($rowCount) { [void]$html.Append("<span class=`"badge hit`">$rowCount rows</span>") }
        else { [void]$html.Append('<span class="badge">0 rows</span>') }
        [void]$html.Append("</h3>`n")
        if ($r.Error) {
            [void]$html.Append('<div class="error">' + (ConvertTo-HtmlText $r.Error) + '</div>')
        } elseif (-not $rowCount) {
            $msg = if ($c.PSObject.Properties['noDataMessage'] -and $c.noDataMessage) { $c.noDataMessage } else { 'No results.' }
            [void]$html.Append('<p class="empty">' + (ConvertTo-HtmlText $msg) + '</p>')
        } else {
            if ($r.Warning) { [void]$html.Append('<p class="note">' + (ConvertTo-HtmlText $r.Warning) + '</p>') }
            $visual = $null
            $settings = if ($c.PSObject.Properties['tileSettings']) { $c.tileSettings } else { $null }
            switch ($c.visualization) {
                'tiles' { $visual = New-TilesHtml $r.Columns $r.Rows $settings }
                'timechart' { $visual = New-TimeChartHtml $r.Columns $r.Rows }
                'barchart' { $visual = New-BarsHtml $r.Columns $r.Rows $false }
                'piechart' { $visual = New-BarsHtml $r.Columns $r.Rows $true }
            }
            $table = New-TableHtml $r.Columns $r.Rows $MaxRows
            if ($visual) {
                [void]$html.Append($visual)
                [void]$html.Append("<details><summary>Data ($rowCount rows)</summary>$table</details>")
            } else {
                [void]$html.Append($table)
            }
        }
        if ($IncludeQueries) {
            [void]$html.Append('<details><summary>KQL</summary><pre>' + (ConvertTo-HtmlText $r.Query) + '</pre></details>')
        }
        [void]$html.Append("</article>`n")
    }
    [void]$html.Append("</section>`n")
}

[void]$html.Append('<footer>Generated by Export-MDOAnomaliesReport.ps1 from <a href="https://github.com/homelabber/MDO-Anomalies">homelabber/MDO-Anomalies</a>. ')
[void]$html.Append('Queries come from ' + (ConvertTo-HtmlText (Split-Path $WorkbookPath -Leaf)) + '. Times are UTC. Results reflect the data the signed-in identity could read when the report was generated.</footer>')
[void]$html.Append("</main><script>$js</script></body></html>`n")
#endregion

#region Write
if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) ('MDO-Anomalies-Report-{0}.html' -f (Get-Date -Format 'yyyyMMdd-HHmm')) }
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$parent = Split-Path $OutputPath -Parent
if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
[IO.File]::WriteAllText($OutputPath, $html.ToString(), (New-Object System.Text.UTF8Encoding($false)))

[pscustomobject]@{
    Path        = $OutputPath
    TimeRange   = $rangeText
    Queries     = $results.Count
    WithResults = $withRows
    Failed      = $failed
}
#endregion
