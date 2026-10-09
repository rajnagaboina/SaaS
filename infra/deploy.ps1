<#
.SYNOPSIS
  Deploys HelloWorldSSO to Azure and registers it in Microsoft Entra ID.

.DESCRIPTION
  1. Creates (or reuses) a multitenant Entra app registration with ID-token sign-in.
  2. Deploys infra/main.bicep: App Service, Azure SQL (Entra-only), Key Vault, App Insights.
  3. Sets the app registration's redirect URIs to the deployed site.
  4. Grants the web app's managed identity access to the database.
  5. Publishes the application.
  The signed-in Azure CLI user becomes the SQL Entra admin and the first platform operator.

.EXAMPLE
  ./infra/deploy.ps1 -ResourceGroup rg-helloworldsso -Location eastus -NamePrefix hwsso
#>
param(
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [Parameter(Mandatory)] [string] $Location,
    [Parameter(Mandatory)] [ValidatePattern('^[a-z][a-z0-9]{2,11}$')] [string] $NamePrefix,
    [string] $AppDisplayName = 'HelloWorldSSO'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
function Invoke-Az { $out = az @args; if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed" }; $out }

Write-Host '== Azure context' -ForegroundColor Cyan
$account = Invoke-Az account show | ConvertFrom-Json
$me = Invoke-Az ad signed-in-user show | ConvertFrom-Json
Write-Host "Subscription: $($account.name) ($($account.id))"
Write-Host "Tenant:       $($account.tenantId)"
Write-Host "Deployer:     $($me.userPrincipalName)"

Write-Host '== Entra app registration' -ForegroundColor Cyan
$app = Invoke-Az ad app list --display-name $AppDisplayName --query '[0]' | ConvertFrom-Json
if (-not $app) {
    $app = Invoke-Az ad app create --display-name $AppDisplayName --sign-in-audience AzureADMultipleOrgs `
        --enable-id-token-issuance true | ConvertFrom-Json
    Write-Host "Created app registration $($app.appId)"
} else {
    Write-Host "Reusing app registration $($app.appId)"
}
if (-not (az ad sp show --id $app.appId 2>$null)) { Invoke-Az ad sp create --id $app.appId | Out-Null }

Write-Host '== Infrastructure' -ForegroundColor Cyan
Invoke-Az group create --name $ResourceGroup --location $Location --output none
$operators = ConvertTo-Json @("$($account.tenantId):$($me.id)") -Compress
$deployment = Invoke-Az deployment group create --resource-group $ResourceGroup `
    --template-file "$PSScriptRoot/main.bicep" `
    --parameters namePrefix=$NamePrefix entraClientId=$($app.appId) sqlAdminObjectId=$($me.id) `
                 sqlAdminLogin=$($me.userPrincipalName) platformOperators=$operators `
    --query properties.outputs | ConvertFrom-Json
$webAppName = $deployment.webAppName.value
$baseUrl = $deployment.publicBaseUrl.value
$sqlServer = $deployment.sqlServerFqdn.value
$database = $deployment.databaseName.value
Write-Host "Web app: $baseUrl"

Write-Host '== Redirect URIs' -ForegroundColor Cyan
Invoke-Az ad app update --id $app.appId --enable-id-token-issuance true --web-redirect-uris `
    "$baseUrl/signin-oidc" "$baseUrl/admin/sso/consent" `
    'https://localhost:7139/signin-oidc' 'https://localhost:7139/admin/sso/consent' | Out-Null

Write-Host '== Database access for the managed identity' -ForegroundColor Cyan
$myIp = (Invoke-RestMethod -Uri 'https://api.ipify.org')
$sqlServerName = $sqlServer.Split('.')[0]
Invoke-Az sql server firewall-rule create --resource-group $ResourceGroup --server $sqlServerName `
    --name deployer --start-ip-address $myIp --end-ip-address $myIp --output none
try {
    $token = Invoke-Az account get-access-token --resource https://database.windows.net/ --query accessToken -o tsv
    $conn = New-Object System.Data.SqlClient.SqlConnection("Server=tcp:$sqlServer,1433;Database=$database;Encrypt=True;Connect Timeout=60")
    $conn.AccessToken = $token
    $conn.Open()
    $cmd = $conn.CreateCommand()
    # db_ddladmin lets the app apply EF Core migrations at startup.
    $cmd.CommandText = @"
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = '$webAppName')
    CREATE USER [$webAppName] FROM EXTERNAL PROVIDER;
ALTER ROLE db_datareader ADD MEMBER [$webAppName];
ALTER ROLE db_datawriter ADD MEMBER [$webAppName];
ALTER ROLE db_ddladmin ADD MEMBER [$webAppName];
"@
    $cmd.ExecuteNonQuery() | Out-Null
    $conn.Close()
    Write-Host "Granted $webAppName access to $database"
}
finally {
    Invoke-Az sql server firewall-rule delete --resource-group $ResourceGroup --server $sqlServerName --name deployer --output none
}

Write-Host '== Publish' -ForegroundColor Cyan
$publishDir = Join-Path ([IO.Path]::GetTempPath()) "helloworldsso-publish"
$zip = "$publishDir.zip"
Remove-Item $publishDir, $zip -Recurse -Force -ErrorAction SilentlyContinue
dotnet publish "$root/src/HelloWorldSSO/HelloWorldSSO.csproj" -c Release -o $publishDir
if ($LASTEXITCODE -ne 0) { throw 'dotnet publish failed' }
Compress-Archive -Path "$publishDir/*" -DestinationPath $zip
Invoke-Az webapp deploy --resource-group $ResourceGroup --name $webAppName --src-path $zip --type zip --output none

Write-Host ''
Write-Host "Deployed: $baseUrl" -ForegroundColor Green
Write-Host "Entra app (client) ID: $($app.appId)"
Write-Host "Platform operator sign-in: $baseUrl/login  (\"Platform operator sign-in\" link)"
