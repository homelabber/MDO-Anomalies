<#
.SYNOPSIS
    Deploys the MDO-Anomalies custom detection rules to Microsoft Defender XDR.

.DESCRIPTION
    Reads detections.json plus the matching .kql files and creates or updates each rule
    through the Microsoft Graph beta custom detection API
    (/beta/security/rules/detectionRules). Rules are created DISABLED by default so you
    can review and tune them first. Use -Status enabled to turn them on.

    Requires the Microsoft.Graph.Authentication module and the CustomDetection.ReadWrite.All
    permission (delegated or application).

.PARAMETER Status
    Status for the deployed rules: 'disabled' (default) or 'enabled'.

.PARAMETER Include
    Optional list of rule ids (or wildcard patterns) to deploy, for example 'mdo-01*'.

.PARAMETER ExportOnly
    Write the Graph request bodies to the given folder instead of calling Graph.

.EXAMPLE
    .\Deploy-CustomDetections.ps1 -ExportOnly .\out

.EXAMPLE
    Connect-MgGraph -Scopes CustomDetection.ReadWrite.All
    .\Deploy-CustomDetections.ps1 -Status enabled -Include 'mdo-01*','mdo-02*'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('disabled', 'enabled')]
    [string]$Status = 'disabled',
    [string[]]$Include = @('*'),
    [string]$ExportOnly
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$definitions = Get-Content -LiteralPath (Join-Path $root 'detections.json') -Raw | ConvertFrom-Json
$apiBase = 'https://graph.microsoft.com/beta/security/rules/detectionRules'

function ConvertTo-RuleBody($def, [string]$status) {
    $query = Get-Content -LiteralPath (Join-Path $root $def.queryFile) -Raw
    $tactics = @(foreach ($t in $def.tactics) {
        @{ tactic = $t.tactic; techniques = @(foreach ($tech in $t.techniques) { @{ technique = $tech } }) }
    })
    $mappings = @{}
    foreach ($p in $def.entityMappings.PSObject.Properties) {
        $mappings[$p.Name] = @(foreach ($m in $p.Value) {
            $h = @{}; foreach ($mp in $m.PSObject.Properties) { $h[$mp.Name] = $mp.Value }; $h
        })
    }
    [ordered]@{
        '@odata.type'   = '#microsoft.graph.security.detectionRule'
        id              = $def.id
        displayName     = $def.displayName
        description     = $def.description
        status          = $status
        queryCondition  = @{ queryText = $query }
        schedule        = @{ frequency = $def.frequency }
        detectionAction = @{
            alertTemplate = [ordered]@{
                title              = $def.displayName
                description        = $def.description
                severity           = $def.severity
                recommendedActions = $def.recommendedActions
                entityMappings     = $mappings
                tactics            = $tactics
            }
        }
    }
}

$selected = $definitions | Where-Object { $id = $_.id; $Include | Where-Object { $id -like $_ } }
if (-not $selected) { throw "No detections matched -Include $($Include -join ', ')" }

if ($ExportOnly) {
    New-Item -ItemType Directory -Path $ExportOnly -Force | Out-Null
    foreach ($def in $selected) {
        $path = Join-Path $ExportOnly "$($def.id).json"
        ConvertTo-RuleBody $def $Status | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding utf8
        Write-Host "Exported $path"
    }
    return
}

if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
    throw 'Install the Microsoft.Graph.Authentication module: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
}
if (-not (Get-MgContext)) {
    Connect-MgGraph -Scopes 'CustomDetection.ReadWrite.All' -NoWelcome
}

foreach ($def in $selected) {
    $body = ConvertTo-RuleBody $def $Status
    $json = $body | ConvertTo-Json -Depth 20
    $exists = $false
    try {
        Invoke-MgGraphRequest -Method GET -Uri "$apiBase/$($def.id)" | Out-Null
        $exists = $true
    } catch {
        if ($_.Exception.Message -notmatch '404|NotFound') { throw }
    }

    if ($exists) {
        if ($PSCmdlet.ShouldProcess($def.id, 'Update custom detection')) {
            $body.Remove('@odata.type'); $body.Remove('id')
            Invoke-MgGraphRequest -Method PATCH -Uri "$apiBase/$($def.id)" -Body ($body | ConvertTo-Json -Depth 20) -ContentType 'application/json' | Out-Null
            Write-Host "Updated  $($def.id) ($Status)" -ForegroundColor Yellow
        }
    } elseif ($PSCmdlet.ShouldProcess($def.id, 'Create custom detection')) {
        Invoke-MgGraphRequest -Method POST -Uri $apiBase -Body $json -ContentType 'application/json' | Out-Null
        Write-Host "Created  $($def.id) ($Status)" -ForegroundColor Green
    }
}
