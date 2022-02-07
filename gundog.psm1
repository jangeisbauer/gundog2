# bring in the code from the other modules
. .\gundoghunt-alertpresentation.ps1
. .\hunting-functions.ps1
. .\TiProvider-functions.ps1
. .\get-config.ps1
. .\public-functions.ps1

# read config data and set it to vars
$useKeyVault = $config.connectionData.useKeyVault
$keyvaulttenant = $config.connectionData.keyvaulttenant
$keyvaultsubscriptionId = $config.connectionData.keyvaultsubscriptionId
$clientID = $config.connectionData.clientID
$keyVaultName = $config.connectionData.keyVaultName 
$keyvaultsecretname = $config.connectionData.keyvaultsecretname

$registryOn = $config.globalVars.registryOn
$networkOn = $config.globalVars.networkOn
$processesOn = $config.globalVars.processesOn
$vulnerabilitiesOn = $config.globalVars.vulnerabilitiesOn
$signinsOn = $config.globalVars.signinsOn
$officeOn = $config.globalVars.officeOn
$riskySignInsOn = $config.globalVars.riskySignInsOn
$emailsOn = $config.globalVars.emailsOn

$apiGeoLocation = $config.globalVars.apiGeoLocation

$numberOfEvents = $config.globalVars.numberOfEvents
$debugOn = $config.globalVars.debugOn
$irmTimeout = $config.globalVars.irmTimeout

$signinsT1 = $config.globalVars.signinst1
$signinsT1u = $config.globalVars.signinsT1u 
$signinsT2 = $config.globalVars.signinsT2 
$signinsT2u = $config.globalVars.signinsT2u  

$registryT1 = $config.globalVars.registryT1 
$registryT1u = $config.globalVars.registryT1u 
$registryT2 = $config.globalVars.registryT2 
$registryT2u = $config.globalVars.registryT2u 

$networkT1 = $config.globalVars.networkT1 
$networkT1u = $config.globalVars.networkT1u 
$networkT2 = $config.globalVars.networkT2 
$networkT2u = $config.globalVars.networkT2u 

$processesT1 = $config.globalVars.processesT1 
$processesT1u = $config.globalVars.processesT1u 
$processesT2 = $config.globalVars.processesT2 
$processesT2u = $config.globalVars.processesT2u 

$officeT1 = $config.globalVars.officeT1 
$officeT1u = $config.globalVars.officeT1u 
$officeT2 = $config.globalVars.officeT2 
$officeT2u = $config.globalVars.officeT2u 

$emailsT1 = $config.globalVars.emailsT1 
$emailsT1u = $config.globalVars.emailsT1u 
$emailsT2 = $config.globalVars.emailsT2 
$emailsT2u = $config.globalVars.emailsT2u 

$notMatchThese = $config.globalVars.notMatchThese

$error.clear()

# import the azure modules
$AzAccountsPsm = Get-Module -Name Az.Accounts -ListAvailable;
$AzKeyVaultPsm = Get-Module -Name Az.KeyVault -ListAvailable;
if ($AzAccountsPsm.length -eq 0 -or $AzKeyVaultPsm.length -eq 0){
    Write-Host "PowerShell Modules are missing. Install-Module Az.Accounts and Install-Module Az.KeyVault. This is the way." -ForegroundColor Red
    exit
}
else{
    Import-Module -Name Az.Accounts -ErrorAction SilentlyContinue;
    Import-Module -Name Az.KeyVault -ErrorAction SilentlyContinue;
}
if($keyvaulttenant -ne "tenantID")
{
    if($null -eq $clientSecret)
    {
        Login-AzAccount -TenantId $keyvaulttenant -Subscription $keyvaultsubscriptionId;
        $global:clientSecret = Get-AzKeyVaultSecret -VaultName $keyvaultname -Name $keyvaultsecretname -AsPlainText
        if(!$debugOn)
        {
            Clear-Host
        }
    }
} else {
    Write-Host "You need to configure your keyvault access. Run Set-GundogConfig and configure your tenant connections and the keyvault settings. I have spoken." -ForegroundColor Red
}

