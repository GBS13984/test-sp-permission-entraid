[CmdletBinding(PositionalBinding = $false)]
param(
    [Guid]$TenantId,

    [Guid]$AppClientId,

    [Guid]$AppServicePrincipalObjectId,

    [Guid]$UserObjectId,

    [Guid]$ExistingGroupObjectId,

    [string]$ExistingGroupName,

    [string]$ExistingOwnedGroupName,

    [string]$EnvFile = (Join-Path $PSScriptRoot '.env'),

    [switch]$Execute,

    [switch]$ValidateConfig,

    [switch]$AllowNonTestGroup
)

$ErrorActionPreference = 'Stop'
$GraphBase = 'https://graph.microsoft.com/v1.0'
$Results = [System.Collections.Generic.List[object]]::new()
$CreatedGroupId = $null
$CreatedGroupVerified = $false
$AppToken = $null

function Read-EnvFile {
    param([string]$Path)

    $values = @{}
    $lineNumber = 0
    foreach ($line in (Get-Content -LiteralPath $Path -Encoding UTF8)) {
        $lineNumber++
        $line = $line.Trim()
        if ($line.Length -eq 0 -or $line.StartsWith('#')) {
            continue
        }
        if ($line -match '^(?<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?<value>.*)$') {
            $key = $Matches['key']
            $value = $Matches['value'].Trim()
        }
        else {
            throw "Formato .env non valido alla riga $lineNumber."
        }
        if ($values.ContainsKey($key)) {
            throw "Chiave .env duplicata '$key' alla riga $lineNumber."
        }
        if ($value.Length -gt 0 -and ($value[0] -eq '"' -or $value[0] -eq "'")) {
            if ($value.Length -lt 2 -or $value[$value.Length - 1] -ne $value[0]) {
                throw "Virgolette .env non bilanciate alla riga $lineNumber."
            }
            $value = $value.Substring(1, $value.Length - 2)
        }
        $values[$key] = $value
    }

    $values
}

function Get-PlainTextSecret {
    param([Security.SecureString]$Secret)

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
    try {
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Get-AccessToken {
    param(
        [Guid]$Tenant,
        [Guid]$Client,
        [Security.SecureString]$Secret
    )

    $plainSecret = Get-PlainTextSecret $Secret
    try {
        $response = Invoke-RestMethod `
            -Method Post `
            -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" `
            -ContentType 'application/x-www-form-urlencoded' `
            -Body @{
                client_id     = $Client
                client_secret = $plainSecret
                scope         = 'https://graph.microsoft.com/.default'
                grant_type    = 'client_credentials'
            }
    }
    catch {
        $detail = $null
        if ($_.ErrorDetails.Message) {
            $detail = ($_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue).error_description
        }
        if (-not $detail) {
            $detail = $_.Exception.Message
        }
        throw "Richiesta del token per l'app $Client fallita: $detail"
    }
    finally {
        $plainSecret = $null
    }

    if ([string]::IsNullOrWhiteSpace($response.access_token)) {
        throw "Il token endpoint non ha restituito un access token per l'app $Client."
    }

    $response.access_token
}

function Get-TokenClaims {
    param([string]$Token)

    $parts = $Token.Split('.')
    if ($parts.Count -lt 2) {
        throw 'Il token ricevuto non è un JWT valido.'
    }

    $payload = $parts[1].Replace('-', '+').Replace('_', '/')
    $payload += '=' * ((4 - ($payload.Length % 4)) % 4)
    $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
    $json | ConvertFrom-Json
}

function Assert-AppToken {
    param(
        [string]$Token,
        [Guid]$ExpectedClientId,
        [string[]]$RequiredRoles,
        [string[]]$ForbiddenRoles
    )

    $claims = Get-TokenClaims $Token
    $tokenClientId = if ($claims.appid) { $claims.appid } else { $claims.azp }
    if ($claims.tid -ne $TenantId.ToString() -or
        $tokenClientId -ne $ExpectedClientId.ToString() -or
        $claims.aud -notin @('https://graph.microsoft.com', '00000003-0000-0000-c000-000000000000')) {
        throw "Tenant, client ID o audience del token non corrispondono alla configurazione attesa."
    }
    # With Group.Create alone the app may bind only itself as owner (oid = its own SP object ID).
    if ($claims.oid -ne $AppServicePrincipalObjectId.ToString()) {
        throw "APP_SERVICE_PRINCIPAL_OBJECT_ID ($AppServicePrincipalObjectId) non è lo SP del token (oid $($claims.oid)): con solo Group.Create Graph risponde 403 su owners@odata.bind."
    }

    $roles = @($claims.roles)
    foreach ($role in $RequiredRoles) {
        if ($role -notin $roles) {
            throw "Il token non contiene il ruolo applicativo richiesto: $role."
        }
    }

    foreach ($role in $ForbiddenRoles) {
        if ($role -in $roles) {
            throw "Il token contiene il ruolo troppo ampio '$role'; interrompo prima di effettuare modifiche."
        }
    }
}

function Invoke-GraphRequest {
    param(
        [string]$Token,
        [ValidateSet('GET', 'POST', 'DELETE')]
        [string]$Method,
        [string]$Uri,
        [object]$Body
    )

    $parameters = @{
        Method      = $Method
        Uri         = $Uri
        Headers     = @{ Authorization = "Bearer $Token" }
        ErrorAction = 'Stop'
        UseBasicParsing = $true
    }
    if ($null -ne $Body) {
        $parameters.ContentType = 'application/json'
        $parameters.Body = $Body | ConvertTo-Json -Depth 8
    }

    try {
        $response = Invoke-WebRequest @parameters
        $responseBody = $null
        if (-not [string]::IsNullOrWhiteSpace($response.Content)) {
            $responseBody = $response.Content | ConvertFrom-Json
        }
        [pscustomobject]@{ StatusCode = [int]$response.StatusCode; Body = $responseBody }
    }
    catch {
        $response = $_.Exception.Response
        if ($null -eq $response) {
            throw
        }

        $statusCode = [int]$response.StatusCode
        $errorBody = ''
        if ($response -is [System.Net.Http.HttpResponseMessage]) {
            # PS7 has already read and disposed the content; the body is in ErrorDetails.
            $errorBody = [string]$_.ErrorDetails.Message
        }
        elseif ($response.GetResponseStream()) {
            $reader = [IO.StreamReader]::new($response.GetResponseStream())
            try {
                $errorBody = $reader.ReadToEnd()
            }
            finally {
                $reader.Dispose()
            }
        }

        [pscustomobject]@{ StatusCode = $statusCode; Body = $errorBody }
    }
}

function Get-RelatedObjectIds {
    param(
        [string]$Token,
        [Guid]$GroupId,
        [ValidateSet('members', 'owners')]
        [string]$Relationship
    )

    $ids = [System.Collections.Generic.List[string]]::new()
    # v1.0 /owners does not list service principals (staged rollout, see group-list-owners docs): use beta.
    $base = if ($Relationship -eq 'owners') { 'https://graph.microsoft.com/beta' } else { $GraphBase }
    $uri = "$base/groups/$GroupId/${Relationship}?`$select=id"
    while ($uri) {
        $response = Invoke-GraphRequest -Token $Token -Method GET -Uri $uri
        if ($response.StatusCode -ne 200) {
            throw "Lettura della relazione '$Relationship' fallita (HTTP $($response.StatusCode))."
        }

        foreach ($item in $response.Body.value) {
            $ids.Add([string]$item.id)
        }
        $uri = $response.Body.'@odata.nextLink'
    }
    $ids.ToArray()
}

function Wait-ForMembership {
    param(
        [Guid]$GroupId,
        [Guid]$MemberId,
        [bool]$Expected
    )

    for ($attempt = 0; $attempt -lt 6; $attempt++) {
        $memberIds = Get-RelatedObjectIds -Token $AppToken -GroupId $GroupId -Relationship members
        $found = $MemberId.ToString() -in $memberIds
        if ($found -eq $Expected) {
            return
        }
        Start-Sleep -Seconds 5
    }

    $state = if ($Expected) { 'presente' } else { 'assente' }
    throw "La membership non risulta $state dopo 30 secondi."
}

function Invoke-TestCase {
    param(
        [string]$Name,
        [scriptblock]$Action,
        [string]$SkipReason
    )

    if ($SkipReason) {
        $Results.Add([pscustomobject]@{ Caso = $Name; Esito = 'SKIP'; Dettaglio = $SkipReason })
        return
    }

    try {
        $detail = & $Action
        $Results.Add([pscustomobject]@{ Caso = $Name; Esito = 'PASS'; Dettaglio = [string]$detail })
    }
    catch {
        $Results.Add([pscustomobject]@{ Caso = $Name; Esito = 'FAIL'; Dettaglio = $_.Exception.Message })
    }
}

function Assert-MembershipDenied {
    param([Guid]$GroupId, [string]$GroupName)

    $response = Invoke-GraphRequest `
        -Token $AppToken `
        -Method POST `
        -Uri "$GraphBase/groups/$GroupId/members/`$ref" `
        -Body @{ '@odata.id' = "$GraphBase/directoryObjects/$UserObjectId" }
    if ($response.StatusCode -eq 204) {
        $cleanup = Invoke-GraphRequest `
            -Token $AppToken `
            -Method DELETE `
            -Uri "$GraphBase/groups/$GroupId/members/$UserObjectId/`$ref"
        if ($cleanup.StatusCode -ne 204) {
            throw "Aggiunta inattesa a '$GroupName' e rollback fallito (HTTP $($cleanup.StatusCode)); rimuovere manualmente l'utente di test."
        }
        Wait-ForMembership -GroupId $GroupId -MemberId $UserObjectId -Expected $false
        throw "Lo SP ha potuto aggiungere l'utente al gruppo esterno '$GroupName'; l'aggiunta è stata annullata."
    }
    if ($response.StatusCode -ne 403) {
        throw "Su '$GroupName' atteso HTTP 403, ricevuto HTTP $($response.StatusCode)."
    }
    Wait-ForMembership -GroupId $GroupId -MemberId $UserObjectId -Expected $false
}

try {
    if ($Execute -and $ValidateConfig) {
        throw 'Usare -ValidateConfig o -Execute, non entrambi.'
    }
    if (-not $Execute -and -not $ValidateConfig) {
        throw 'Lo script crea un gruppo e tenta modifiche di membership: verificare il tenant di test e ripetere aggiungendo -Execute.'
    }

    $envValues = @{}
    if (Test-Path -LiteralPath $EnvFile -PathType Leaf) {
        $envValues = Read-EnvFile -Path $EnvFile
    }
    elseif ($PSBoundParameters.ContainsKey('EnvFile') -or (Test-Path -LiteralPath $EnvFile)) {
        throw "Il file di configurazione non esiste o non è un file: $EnvFile."
    }

    $envKeys = [ordered]@{
        TenantId                    = 'TENANT_ID'
        AppClientId                 = 'APP_CLIENT_ID'
        AppServicePrincipalObjectId = 'APP_SERVICE_PRINCIPAL_OBJECT_ID'
        UserObjectId                = 'USER_OBJECT_ID'
        ExistingGroupObjectId       = 'EXISTING_GROUP_OBJECT_ID'
        ExistingGroupName           = 'EXISTING_GROUP_NAME'
        ExistingOwnedGroupName      = 'EXISTING_OWNED_GROUP_NAME'
    }
    foreach ($parameterName in $envKeys.Keys) {
        if ($PSBoundParameters.ContainsKey($parameterName)) {
            continue
        }

        $key = $envKeys[$parameterName]
        if (-not $envValues.ContainsKey($key) -or [string]::IsNullOrWhiteSpace($envValues[$key])) {
            throw "Valore obbligatorio '$key' assente nel file .env e nei parametri."
        }

        $value = $envValues[$key]
        if ($parameterName -notin @('ExistingGroupName', 'ExistingOwnedGroupName')) {
            $parsedId = [Guid]::Empty
            if (-not [Guid]::TryParse($value, [ref]$parsedId)) {
                throw "Il valore '$key' deve essere un GUID valido."
            }
            $value = $parsedId
        }
        Set-Variable -Name $parameterName -Value $value -Scope Script
    }

    if ($TenantId -eq [Guid]::Empty -or
        $AppClientId -eq [Guid]::Empty -or
        $AppServicePrincipalObjectId -eq [Guid]::Empty -or
        $ExistingGroupObjectId -eq [Guid]::Empty -or
        $UserObjectId -eq [Guid]::Empty) {
        throw 'Tenant, app, SP, utente e gruppo esterno devono avere ID validi.'
    }
    if ([string]::IsNullOrWhiteSpace($ExistingGroupName)) {
        throw 'Specificare il nome esatto del gruppo esterno.'
    }
    if ([string]::IsNullOrWhiteSpace($ExistingOwnedGroupName)) {
        throw 'Specificare il nome del gruppo da creare.'
    }
    if ($ExistingGroupName -notlike 'poc-sp-existing-*' -and -not $AllowNonTestGroup) {
        $warning = "Il gruppo esterno non usa il prefisso di test 'poc-sp-existing-'. Dopo aver verificato che sia sacrificabile e autorizzato, aggiungere -AllowNonTestGroup."
        if ($ValidateConfig) {
            Write-Warning $warning
        }
        else {
            throw $warning
        }
    }
    if ($ValidateConfig) {
        Write-Host 'Configurazione locale valida. Nessuna chiamata a Microsoft Graph effettuata.'
        exit 0
    }

    $AppSecret = if ([string]::IsNullOrWhiteSpace($envValues['APP_CLIENT_SECRET'])) {
        Read-Host "Secret dell'app sotto test $AppClientId" -AsSecureString
    }
    else {
        ConvertTo-SecureString -String $envValues['APP_CLIENT_SECRET'] -AsPlainText -Force
    }
    $envValues.Remove('APP_CLIENT_SECRET')
    $AppToken = Get-AccessToken -Tenant $TenantId -Client $AppClientId -Secret $AppSecret

    Assert-AppToken `
        -Token $AppToken `
        -ExpectedClientId $AppClientId `
        -RequiredRoles @('Group.Create', 'GroupMember.Read.All') `
        -ForbiddenRoles @('GroupMember.ReadWrite.All', 'Group.ReadWrite.All', 'Directory.ReadWrite.All')

    $existingGroup = Invoke-GraphRequest `
        -Token $AppToken `
        -Method GET `
        -Uri "$GraphBase/groups/${ExistingGroupObjectId}?`$select=id,displayName,groupTypes,securityEnabled,mailEnabled,isAssignableToRole"
    if ($existingGroup.StatusCode -ne 200 -or
        $existingGroup.Body.displayName -ne $ExistingGroupName -or
        $existingGroup.Body.securityEnabled -ne $true -or
        $existingGroup.Body.mailEnabled -ne $false -or
        @($existingGroup.Body.groupTypes).Count -ne 0 -or
        $existingGroup.Body.isAssignableToRole -eq $true) {
        throw 'Il gruppo esterno non corrisponde al nome atteso o non è un gruppo di sicurezza statico sacrificabile.'
    }

    $existingOwnerIds = Get-RelatedObjectIds `
        -Token $AppToken `
        -GroupId $ExistingGroupObjectId `
        -Relationship owners
    if ($AppServicePrincipalObjectId.ToString() -in $existingOwnerIds) {
        Write-Warning 'Lo SP è owner del gruppo esterno. Verificare tramite audit che il gruppo sia stato creato da altri prima di interpretare il TC3.'
    }

    $existingMemberIds = Get-RelatedObjectIds `
        -Token $AppToken `
        -GroupId $ExistingGroupObjectId `
        -Relationship members
    if ($UserObjectId.ToString() -in $existingMemberIds) {
        throw 'L''utente di test è già membro del gruppo esterno; scegliere un utente assente per poter verificare che la membership non cambi.'
    }
    Invoke-TestCase -Name 'TC1 - Creazione con SP owner' -Action {
        $filter = [uri]::EscapeDataString("displayName eq '$($ExistingOwnedGroupName.Replace("'", "''"))'")
        $lookup = Invoke-GraphRequest -Token $AppToken -Method GET -Uri "$GraphBase/groups?`$filter=$filter&`$select=id"
        if ($lookup.StatusCode -ne 200) {
            throw "Ricerca del gruppo '$ExistingOwnedGroupName' fallita (HTTP $($lookup.StatusCode)): $($lookup.Body)"
        }
        $existingIds = @($lookup.Body.value | ForEach-Object { [string]$_.id })
        if ($existingIds.Count -gt 0) {
            # Same name may exist more than once (Entra allows duplicates): prefer the one owned by the SP.
            $script:CreatedGroupId = $existingIds[0]
            foreach ($id in $existingIds) {
                if ($AppServicePrincipalObjectId.ToString() -in @(Get-RelatedObjectIds -Token $AppToken -GroupId $id -Relationship owners)) {
                    $script:CreatedGroupId = $id
                    break
                }
            }
            $script:CreatedGroupId = [Guid]$script:CreatedGroupId
            $owners = @(Get-RelatedObjectIds -Token $AppToken -GroupId $script:CreatedGroupId -Relationship owners)
            if ($AppServicePrincipalObjectId.ToString() -notin $owners) {
                throw "Il gruppo '$ExistingOwnedGroupName' esiste già ($($existingIds -join ', ')), ma lo SP non ne è owner (owner letti: $($owners -join ', '))."
            }
            $script:CreatedGroupVerified = $true
            return "Gruppo '$ExistingOwnedGroupName' già esistente ($script:CreatedGroupId): creazione saltata, SP verificato come owner."
        }

        $body = @{
            displayName     = $ExistingOwnedGroupName
            mailEnabled     = $false
            mailNickname    = "poc-sp-$([Guid]::NewGuid().ToString('N'))"
            securityEnabled = $true
            groupTypes      = @()
            'owners@odata.bind' = @("$GraphBase/servicePrincipals/$AppServicePrincipalObjectId")
        }
        $response = Invoke-GraphRequest `
            -Token $AppToken `
            -Method POST `
            -Uri "$GraphBase/groups" `
            -Body $body
        if ($response.StatusCode -ne 201 -or [string]::IsNullOrWhiteSpace($response.Body.id)) {
            throw "La creazione non ha restituito HTTP 201 e un ID gruppo (HTTP $($response.StatusCode)): $($response.Body)"
        }

        $script:CreatedGroupId = [Guid]$response.Body.id
        # Entra ID replication is eventually consistent: owners may be empty right after creation.
        for ($attempt = 0; $attempt -lt 6; $attempt++) {
            $owners = @(Get-RelatedObjectIds `
                -Token $AppToken `
                -GroupId $script:CreatedGroupId `
                -Relationship owners)
            if ($AppServicePrincipalObjectId.ToString() -in $owners) {
                break
            }
            Start-Sleep -Seconds 5
        }
        if ($AppServicePrincipalObjectId.ToString() -notin $owners) {
            throw "Il gruppo $script:CreatedGroupId è stato creato, ma dopo 30 secondi lo SP non risulta tra gli owner (owner letti: $($owners -join ', '))."
        }
        $script:CreatedGroupVerified = $true
        "Gruppo $script:CreatedGroupId creato e SP verificato come owner."
    }

    $skipMembershipTest = if ($CreatedGroupVerified) { $null } else { 'TC1 non ha creato un gruppo verificabile.' }
    Invoke-TestCase -Name 'TC2 - Aggiunta al gruppo creato' -SkipReason $skipMembershipTest -Action {
        $response = Invoke-GraphRequest `
            -Token $AppToken `
            -Method POST `
            -Uri "$GraphBase/groups/$script:CreatedGroupId/members/`$ref" `
            -Body @{ '@odata.id' = "$GraphBase/directoryObjects/$UserObjectId" }
        if ($response.StatusCode -ne 204) {
            throw "Attesa risposta HTTP 204, ricevuto HTTP $($response.StatusCode)."
        }
        Wait-ForMembership -GroupId $script:CreatedGroupId -MemberId $UserObjectId -Expected $true
        "Utente $UserObjectId aggiunto e verificato tramite lo SP."
    }

    Invoke-TestCase -Name 'TC3 - Diniego sul gruppo preesistente' -Action {
        Assert-MembershipDenied -GroupId $ExistingGroupObjectId -GroupName $ExistingGroupName
        'HTTP 403 e membership invariata sul gruppo preesistente.'
    }
}
catch {
    Write-Host "Errore di preflight: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}
finally {
    $envValues = $null
    $AppSecret = $null
    $AppToken = $null
}

$Results | Format-Table -AutoSize -Wrap
if ($CreatedGroupId) {
    Write-Host "Gruppo di test lasciato nel tenant per verifica/audit: $CreatedGroupId"
}
if (@($Results | Where-Object { $_.Esito -ne 'PASS' }).Count -gt 0) {
    exit 1
}
exit 0
