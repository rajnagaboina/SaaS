// HelloWorldSSO infrastructure: App Service (Linux, .NET 10) + Azure SQL (Entra-only auth)
// + Key Vault (RBAC). The web app authenticates to SQL and Key Vault with its managed identity,
// so no database passwords or connection-string secrets exist.

@description('Short lowercase prefix for resource names, e.g. "hwsso".')
@minLength(3)
@maxLength(12)
param namePrefix string

param location string = resourceGroup().location

@description('Client ID of the multitenant Entra app registration used for sign-in.')
param entraClientId string

@description('Object ID of the Entra user or group that administers the SQL server (the deployer).')
param sqlAdminObjectId string

@description('Display name / UPN for the SQL Entra administrator.')
param sqlAdminLogin string

@description('Platform operators as "tenantId:objectId" pairs.')
param platformOperators array = []

@description('App Service plan SKU. B1 is the smallest tier with Always On.')
param appServiceSku string = 'B1'

var suffix = uniqueString(resourceGroup().id)
var webAppName = '${namePrefix}-web-${suffix}'
var sqlServerName = '${namePrefix}-sql-${suffix}'
var keyVaultName = take('${namePrefix}kv${suffix}', 24)
var databaseName = 'helloworldsso'
var publicBaseUrl = 'https://${webAppName}.azurewebsites.net'
var operatorSettings = [for (op, i) in platformOperators: { name: 'Platform__Operators__${i}', value: op }]

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: '${namePrefix}-plan-${suffix}'
  location: location
  kind: 'linux'
  sku: { name: appServiceSku }
  properties: { reserved: true }
}

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${namePrefix}-logs-${suffix}'
  location: location
  properties: { sku: { name: 'PerGB2018' }, retentionInDays: 30 }
}

resource insights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${namePrefix}-ai-${suffix}'
  location: location
  kind: 'web'
  properties: { Application_Type: 'web', WorkspaceResourceId: logs.id }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 30
    // Turn on purge protection once the vault holds production secrets; it is left off so a
    // test environment can be torn down and recreated under the same name.
  }
}

resource sqlServer 'Microsoft.Sql/servers@2023-08-01-preview' = {
  name: sqlServerName
  location: location
  properties: {
    minimalTlsVersion: '1.2'
    publicNetworkAccess: 'Enabled'
    administrators: {
      administratorType: 'ActiveDirectory'
      azureADOnlyAuthentication: true
      login: sqlAdminLogin
      sid: sqlAdminObjectId
      tenantId: subscription().tenantId
      principalType: 'User'
    }
  }
}

// Lets Azure services (the web app) reach the server; access still requires Entra auth.
resource sqlAllowAzure 'Microsoft.Sql/servers/firewallRules@2023-08-01-preview' = {
  parent: sqlServer
  name: 'AllowAzureServices'
  properties: { startIpAddress: '0.0.0.0', endIpAddress: '0.0.0.0' }
}

resource database 'Microsoft.Sql/servers/databases@2023-08-01-preview' = {
  parent: sqlServer
  name: databaseName
  location: location
  sku: { name: 'GP_S_Gen5', tier: 'GeneralPurpose', family: 'Gen5', capacity: 1 }
  properties: {
    autoPauseDelay: 60
    minCapacity: json('0.5')
    requestedBackupStorageRedundancy: 'Local'
  }
}

resource webApp 'Microsoft.Web/sites@2023-12-01' = {
  name: webAppName
  location: location
  kind: 'app,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'DOTNETCORE|10.0'
      alwaysOn: true
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      http20Enabled: true
      healthCheckPath: '/login'
      appSettings: concat([
        { name: 'ASPNETCORE_ENVIRONMENT', value: 'Production' }
        { name: 'App__PublicBaseUrl', value: publicBaseUrl }
        { name: 'AzureAd__ClientId', value: entraClientId }
        { name: 'KeyVault__Uri', value: keyVault.properties.vaultUri }
        { name: 'Database__Provider', value: 'SqlServer' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: insights.properties.ConnectionString }
      ], operatorSettings)
      connectionStrings: [
        {
          name: 'DefaultConnection'
          type: 'SQLAzure'
          connectionString: 'Server=tcp:${sqlServer.properties.fullyQualifiedDomainName},1433;Database=${databaseName};Authentication=Active Directory Managed Identity;Encrypt=True;TrustServerCertificate=False;Connect Timeout=30;'
        }
      ]
    }
  }
}

// Key Vault Secrets User for the web app's managed identity.
resource kvSecretsUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, webApp.id, '4633458b-17de-408a-b874-0445c86b69e6')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: webApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

output webAppName string = webApp.name
output publicBaseUrl string = publicBaseUrl
output sqlServerFqdn string = sqlServer.properties.fullyQualifiedDomainName
output databaseName string = databaseName
output keyVaultName string = keyVault.name
