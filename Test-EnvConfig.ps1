[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'Test-SPEntraGroups.ps1'
$mockScriptPath = Join-Path $PSScriptRoot 'Test-SPEntraGroups.Mock.ps1'
$shellPath = (Get-Process -Id $PID).Path
$tempFile = [IO.Path]::GetTempFileName()

$validConfig = @'
# Valori sintetici per verifiche locali, senza accesso al tenant.
TENANT_ID=11111111-1111-1111-1111-111111111111
APP_CLIENT_ID=22222222-2222-2222-2222-222222222222
APP_SERVICE_PRINCIPAL_OBJECT_ID=33333333-3333-3333-3333-333333333333
USER_OBJECT_ID=55555555-5555-5555-5555-555555555555
EXISTING_GROUP_OBJECT_ID=66666666-6666-6666-6666-666666666666
EXISTING_GROUP_NAME='AG_TEST_EXTERNAL'
EXISTING_OWNED_GROUP_NAME="poc-sp-test=$(throw 'non eseguire')=valore#test"
APP_CLIENT_SECRET='synthetic=secret#dont-print'
'@

function Test-ConfigCase {
    param(
        [string]$Name,
        [string]$Content,
        [int]$ExpectedExit,
        [string]$ExpectedMessage = '',
        [string[]]$ExtraArguments = @()
    )

    [IO.File]::WriteAllText($tempFile, $Content, [Text.UTF8Encoding]::new($false))
    $output = & $shellPath -NoProfile -File $scriptPath -EnvFile $tempFile -ValidateConfig @ExtraArguments 2>&1
    $actualExit = $LASTEXITCODE
    $text = $output | Out-String
    if ($text.Contains('synthetic=secret#dont-print')) {
        throw "$Name : un secret sintetico è stato mostrato nell'output."
    }
    if ($actualExit -ne $ExpectedExit -or ($ExpectedMessage -and $text -notmatch $ExpectedMessage)) {
        throw "$Name : uscita $actualExit, attesa $ExpectedExit. Output: $text"
    }
    Write-Host "PASS $Name"
}

function Test-MockCase {
    param(
        [string]$Name,
        [string]$Scenario,
        [int]$ExpectedExit,
        [string[]]$ExpectedText = @(),
        [string[]]$ForbiddenText = @()
    )

    [IO.File]::WriteAllText($tempFile, $validConfig, [Text.UTF8Encoding]::new($false))
    $output = & $shellPath -NoProfile -File $mockScriptPath -EnvFile $tempFile -Scenario $Scenario 2>&1
    $actualExit = $LASTEXITCODE
    $text = $output | Out-String
    if ($text.Contains('synthetic=secret#dont-print') -or $text -match 'mock\.[A-Za-z0-9_-]+\.mock') {
        throw "$Name : secret o token sintetico mostrato nell'output."
    }
    if ($actualExit -ne $ExpectedExit) {
        throw "$Name : uscita $actualExit, attesa $ExpectedExit. Output: $text"
    }
    foreach ($expected in $ExpectedText) {
        if (-not $text.Contains($expected)) {
            throw "$Name : manca '$expected'. Output: $text"
        }
    }
    foreach ($forbidden in $ForbiddenText) {
        if ($text.Contains($forbidden)) {
            throw "$Name : trovato '$forbidden'. Output: $text"
        }
    }
    Write-Host "PASS $Name"
}

try {
    Test-ConfigCase -Name 'Configurazione valida e valori letterali' -Content $validConfig -ExpectedExit 0 `
        -ExpectedMessage 'AllowNonTestGroup'

    $invalidGuid = $validConfig.Replace('APP_CLIENT_ID=22222222-2222-2222-2222-222222222222', 'APP_CLIENT_ID=not-a-guid')
    Test-ConfigCase -Name 'GUID non valido' -Content $invalidGuid -ExpectedExit 2 -ExpectedMessage 'APP_CLIENT_ID'
    Test-ConfigCase -Name 'Parametro esplicito prevalente' -Content $invalidGuid -ExpectedExit 0 `
        -ExtraArguments @('-AppClientId', '22222222-2222-2222-2222-222222222222')

    $missing = $validConfig.Replace('USER_OBJECT_ID=55555555-5555-5555-5555-555555555555', 'USER_OBJECT_ID=')
    Test-ConfigCase -Name 'Valore obbligatorio assente' -Content $missing -ExpectedExit 2 -ExpectedMessage 'USER_OBJECT_ID'
    $missingGroupName = $validConfig -replace '(?m)^EXISTING_OWNED_GROUP_NAME=.*$', 'EXISTING_OWNED_GROUP_NAME='
    Test-ConfigCase -Name 'Nome gruppo da creare assente' -Content $missingGroupName -ExpectedExit 2 `
        -ExpectedMessage 'EXISTING_OWNED_GROUP_NAME'
    Test-ConfigCase -Name 'Chiave duplicata' -Content ($validConfig + "`napp_client_id=duplicate") `
        -ExpectedExit 2 -ExpectedMessage 'duplicata'
    Test-ConfigCase -Name 'Riga malformata' -Content ($validConfig + "`nnon valida") `
        -ExpectedExit 2 -ExpectedMessage 'Formato .env'
    Test-ConfigCase -Name 'Virgolette non bilanciate' -Content ($validConfig + "`nALTRO=`"non chiuso") `
        -ExpectedExit 2 -ExpectedMessage 'Virgolette'
    Test-ConfigCase -Name 'Modalita incompatibili' -Content $validConfig -ExpectedExit 2 `
        -ExpectedMessage 'non entrambi' -ExtraArguments @('-Execute')

    Test-MockCase -Name 'Protezione gruppo esterno non contrassegnato' -Scenario Guard -ExpectedExit 2 `
        -ExpectedText @('-AllowNonTestGroup') -ForbiddenText @('MOCK_TOKEN_OK', 'MOCK_GRAPH')
    Test-MockCase -Name 'Tre casi con un solo SP' -Scenario Success -ExpectedExit 0 `
        -ExpectedText @('MOCK_TOKEN_OK', 'MOCK_CREATE', 'MOCK_ADD_CREATED', 'MOCK_DENIED')
    Test-MockCase -Name 'Permesso di lettura mancante' -Scenario MissingRead -ExpectedExit 2 `
        -ExpectedText @('GroupMember.Read.All') -ForbiddenText @('MOCK_GRAPH')
    Test-MockCase -Name 'Permesso di scrittura troppo ampio' -Scenario ForbiddenWrite -ExpectedExit 2 `
        -ExpectedText @('troppo ampio') -ForbiddenText @('MOCK_GRAPH')
    Test-MockCase -Name 'Utente gia membro del gruppo esterno' -Scenario AlreadyMember -ExpectedExit 2 `
        -ExpectedText @('MOCK_GRAPH') -ForbiddenText @('MOCK_CREATE', 'MOCK_ADD_CREATED')
    Test-MockCase -Name 'Nome del gruppo esterno diverso' -Scenario WrongName -ExpectedExit 2 `
        -ExpectedText @('MOCK_GRAPH') -ForbiddenText @('MOCK_CREATE', 'MOCK_ADD_CREATED')
    Test-MockCase -Name 'SP owner del gruppo esterno: tentativo consentito' -Scenario ExistingOwned -ExpectedExit 0 `
        -ExpectedText @('owner del gruppo esterno', 'MOCK_CREATE', 'MOCK_ADD_CREATED', 'MOCK_DENIED')
    Test-MockCase -Name 'SP owner del gruppo esterno: aggiunta inattesa' -Scenario ExistingOwnedWrite -ExpectedExit 1 `
        -ExpectedText @('owner del gruppo esterno', 'MOCK_CREATE', 'MOCK_ADD_CREATED', 'MOCK_ROLLBACK')
    Test-MockCase -Name 'Lettura del gruppo esterno negata' -Scenario ReadDenied -ExpectedExit 2 `
        -ExpectedText @('MOCK_GRAPH') -ForbiddenText @('MOCK_CREATE', 'MOCK_ADD_CREATED')
    Test-MockCase -Name 'Owner non confermato: TC2 saltato' -Scenario OwnerMissing -ExpectedExit 1 `
        -ExpectedText @('MOCK_CREATE', 'MOCK_DENIED', 'SKIP') -ForbiddenText @('MOCK_ADD_CREATED')
    Test-MockCase -Name 'Aggiunta al gruppo creato negata' -Scenario CreatedAddDenied -ExpectedExit 1 `
        -ExpectedText @('MOCK_CREATED_DENIED', 'MOCK_DENIED', 'FAIL') -ForbiddenText @('MOCK_ADD_CREATED')
    Test-MockCase -Name 'Aggiunta esterna inattesa e rollback' -Scenario UnexpectedAdd -ExpectedExit 1 `
        -ExpectedText @('MOCK_CREATE', 'MOCK_ADD_CREATED', 'MOCK_ROLLBACK')
    Test-MockCase -Name 'Rollback fallito segnalato' -Scenario RollbackFailure -ExpectedExit 1 `
        -ExpectedText @('MOCK_CREATE', 'MOCK_ADD_CREATED', 'rollback fallito')
}
finally {
    [IO.File]::Delete($tempFile)
}
