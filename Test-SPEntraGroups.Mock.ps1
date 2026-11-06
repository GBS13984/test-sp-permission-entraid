[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$EnvFile,

    [Parameter(Mandatory)]
    [ValidateSet('Guard', 'Success', 'MissingRead', 'ForbiddenWrite', 'AlreadyMember', 'WrongName', 'ExistingOwned', 'ExistingOwnedWrite', 'ReadDenied', 'OwnerMissing', 'CreatedAddDenied', 'UnexpectedAdd', 'RollbackFailure')]
    [string]$Scenario
)

$ErrorActionPreference = 'Stop'
$global:mockScenario = $Scenario
$global:mockTenant = '11111111-1111-1111-1111-111111111111'
$global:mockClient = '22222222-2222-2222-2222-222222222222'
$global:mockSp = '33333333-3333-3333-3333-333333333333'
$global:mockUser = '55555555-5555-5555-5555-555555555555'
$global:mockExternal = '66666666-6666-6666-6666-666666666666'
$global:mockCreated = '77777777-7777-7777-7777-777777777777'
$global:mockCreatedName = 'poc-sp-test=$(throw ''non eseguire'')=valore#test'
$global:mockTokenCalls = 0
$global:mockCreatedMember = $false
$global:mockExternalMember = $Scenario -eq 'AlreadyMember'

function global:Invoke-RestMethod {
    param([string]$Method, [string]$Uri, [string]$ContentType, [hashtable]$Body)

    $global:mockTokenCalls++
    if ($global:mockTokenCalls -ne 1 -or
        $Method -ne 'Post' -or
        $Uri -ne "https://login.microsoftonline.com/$global:mockTenant/oauth2/v2.0/token" -or
        [string]$Body.client_id -ne $global:mockClient -or
        $Body.client_secret -cne 'synthetic=secret#dont-print' -or
        $Body.scope -ne 'https://graph.microsoft.com/.default' -or
        $Body.grant_type -ne 'client_credentials') {
        throw 'Richiesta token inattesa nel mock.'
    }

    $roles = @('Group.Create', 'GroupMember.Read.All')
    if ($global:mockScenario -eq 'MissingRead') {
        $roles = @('Group.Create')
    }
    elseif ($global:mockScenario -eq 'ForbiddenWrite') {
        $roles += 'GroupMember.ReadWrite.All'
    }
    $claims = @{
        tid   = $global:mockTenant
        appid = $global:mockClient
        aud   = 'https://graph.microsoft.com'
        roles = $roles
    } | ConvertTo-Json -Compress
    $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($claims))
    $payload = $payload.TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $global:mockToken = "mock.$payload.mock"
    Write-Host 'MOCK_TOKEN_OK'
    [pscustomobject]@{ access_token = $global:mockToken }
}

function global:New-MockResponse {
    param([int]$StatusCode, [object]$Body)

    $content = if ($null -eq $Body) { '' } else { ConvertTo-Json -InputObject $Body -Depth 10 -Compress }
    [pscustomobject]@{ StatusCode = $StatusCode; Content = $content }
}

function global:Invoke-WebRequest {
    [CmdletBinding()]
    param(
        [string]$Method,
        [string]$Uri,
        [hashtable]$Headers,
        [string]$ContentType,
        [string]$Body,
        [switch]$UseBasicParsing
    )

    if ($Headers.Authorization -ne "Bearer $global:mockToken") {
        throw 'Token inatteso nella richiesta Graph simulata.'
    }
    Write-Host 'MOCK_GRAPH'
    $path = ([Uri]$Uri).AbsolutePath.Replace('%24', '$')
    $externalPath = "/v1.0/groups/$global:mockExternal"
    $createdPath = "/v1.0/groups/$global:mockCreated"
    $memberRef = '/members/$ref'
    $deleteRef = "$externalPath/members/$global:mockUser" + '/$ref'

    switch ("$Method $path") {
        "GET $externalPath" {
            if ($global:mockScenario -eq 'ReadDenied') {
                return New-MockResponse 403 $null
            }
            $displayName = if ($global:mockScenario -eq 'WrongName') { 'AG_OTHER_GROUP' } else { 'AG_TEST_EXTERNAL' }
            return New-MockResponse 200 @{
                id                 = $global:mockExternal
                displayName        = $displayName
                securityEnabled    = $true
                mailEnabled        = $false
                groupTypes         = @()
                isAssignableToRole = $false
            }
        }
        "GET $externalPath/owners" {
            $owners = if ($global:mockScenario -in @('ExistingOwned', 'ExistingOwnedWrite')) { @(@{ id = $global:mockSp }) } else { @() }
            return New-MockResponse 200 @{ value = @($owners) }
        }
        "GET $externalPath/members" {
            $members = if ($global:mockExternalMember) { @(@{ id = $global:mockUser }) } else { @() }
            return New-MockResponse 200 @{ value = @($members) }
        }
        'POST /v1.0/groups' {
            $group = $Body | ConvertFrom-Json
            $expectedOwner = "https://graph.microsoft.com/v1.0/servicePrincipals/$global:mockSp"
            if ($group.displayName -cne $global:mockCreatedName -or
                $group.mailNickname -notmatch '^poc-sp-[0-9a-f]{32}$' -or
                $group.'owners@odata.bind' -notcontains $expectedOwner) {
                throw 'Creazione del gruppo non corrispondente alla configurazione.'
            }
            Write-Host 'MOCK_CREATE'
            return New-MockResponse 201 @{ id = $global:mockCreated }
        }
        "GET $createdPath/owners" {
            $owners = if ($global:mockScenario -eq 'OwnerMissing') { @() } else { @(@{ id = $global:mockSp }) }
            return New-MockResponse 200 @{ value = @($owners) }
        }
        "POST $createdPath$memberRef" {
            $member = $Body | ConvertFrom-Json
            if ($member.'@odata.id' -ne "https://graph.microsoft.com/v1.0/directoryObjects/$global:mockUser") {
                throw 'Utente inatteso nel gruppo creato.'
            }
            if ($global:mockScenario -eq 'CreatedAddDenied') {
                Write-Host 'MOCK_CREATED_DENIED'
                return New-MockResponse 403 $null
            }
            $global:mockCreatedMember = $true
            Write-Host 'MOCK_ADD_CREATED'
            return New-MockResponse 204 $null
        }
        "GET $createdPath/members" {
            $members = if ($global:mockCreatedMember) { @(@{ id = $global:mockUser }) } else { @() }
            return New-MockResponse 200 @{ value = @($members) }
        }
        "POST $externalPath$memberRef" {
            $member = $Body | ConvertFrom-Json
            if ($member.'@odata.id' -ne "https://graph.microsoft.com/v1.0/directoryObjects/$global:mockUser") {
                throw 'Utente inatteso nel gruppo esterno.'
            }
            if ($global:mockScenario -in @('UnexpectedAdd', 'RollbackFailure', 'ExistingOwnedWrite')) {
                $global:mockExternalMember = $true
                return New-MockResponse 204 $null
            }
            Write-Host 'MOCK_DENIED'
            return New-MockResponse 403 $null
        }
        "DELETE $deleteRef" {
            if (-not $global:mockExternalMember) {
                throw 'Rollback simulato senza aggiunta precedente.'
            }
            if ($global:mockScenario -eq 'RollbackFailure') {
                return New-MockResponse 403 $null
            }
            $global:mockExternalMember = $false
            Write-Host 'MOCK_ROLLBACK'
            return New-MockResponse 204 $null
        }
        default {
            throw "Richiesta Graph inattesa nel mock: $Method $path."
        }
    }
}

foreach ($command in @('Invoke-RestMethod', 'Invoke-WebRequest')) {
    if ((Get-Command $command).CommandType -ne 'Function') {
        throw "Mock non attivo per $command."
    }
}

$parameters = @{ EnvFile = $EnvFile; Execute = $true }
if ($Scenario -ne 'Guard') {
    $parameters.AllowNonTestGroup = $true
}
& (Join-Path $PSScriptRoot 'Test-SPEntraGroups.ps1') @parameters
exit $LASTEXITCODE
