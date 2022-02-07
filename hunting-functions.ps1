# read config
. .\get-config.ps1

# Main function to get all the data for the Alert Report (gundog hunting v1 functionality)
function get-alertData {
    [CmdletBinding()]
    param (
        [string]$AlertId,
        [string]$tenantId,
        [string]$clientSecret,
        [string]$clientId
    )
    if($AlertId -ne "")
    {
        try {  
            #allIncidents is empty, get all incidents from the last 30 days - don't change this to +30days, all other advanced hunting queries can only do 30days        
            $Today = Get-date -Format "yyyy-MM-dd"
            $StartDateAllIncidents = (get-date($Today)).AddDays(-30)
            $StartDateAllIncidentsF = Get-Date $StartDateAllIncidents -Format "yyyy-MM-dd"
            $tempUrl="/incidents?`$filter=createdTime%20gt%20" + $StartDateAllIncidentsF
            $global:allIncidents = get-APIresultMTP -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret -topic "... getting all incidents/alerts" -api $tempUrl
            foreach($inc in $allIncidents)
            {
                foreach($al in $inc.alerts)
                {
                    if($al.alertid -eq $AlertId)
                    {
                        $global:plainalert = $al 
                    }
                }
            }
        }
        catch {
            Write-Host "Error: Query for AlertId failed! This is not your day, Mando." -ForegroundColor red
            $error
        }
    }

    if($error.count -eq 0 -and $null -ne $plainalert)
    {
        #build the $alert object
        $global:alert = new-object psobject
        $alert | add-member Noteproperty Timestamp ($plainalert.creationTime.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty AlertId ($plainalert.alertId.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty Title ($plainalert.title.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty Category ($plainalert.Category.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty ServiceSource ($plainalert.ServiceSource.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty DetectionSource ($plainalert.DetectionSource.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty Entities ($plainalert.Entities.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty DeviceName ($plainalert.devices.deviceDnsName.Where({$_ -ne ""}) | Select-Object -Unique)

        #if the alert has an assigned device ID
        if($plainalert.Devices.mdatpDeviceId -ne "")
        {
            $alert | add-member Noteproperty DeviceId ($plainalert.Devices.mdatpDeviceId.tolower().Where({$_ -ne ""}) | Select-Object -Unique)
        } #if not check entities for device IDs
        else {
            if($plainalert.entities.deviceid -ne "")
            {
                $alert | add-member Noteproperty DeviceId ($plainalert.entities.deviceid.tolower().Where({$_ -ne ""}) | Select-Object -Unique)
            }
        }
        #User Object from Entities
        $alert | add-member Noteproperty AccountName ($plainalert.entities.AccountName.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty AccountDomain ($plainalert.entities.DomainName.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty AccountSid ($plainalert.entities.UserSid.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty FileName ($plainalert.entities.FileName.Where({$_ -ne ""}))
        $alert | add-member Noteproperty SHA1 ($plainalert.entities.sha1.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty SHA256 ($plainalert.entities.sha256.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty Folderpath ($plainalert.entities.filepath.Where({$_ -ne ""}))
        $alert | add-member Noteproperty Urls ($plainalert.entities.url.Where({$_ -ne ""}) | Select-Object -Unique)      
        $alert | add-member Noteproperty EmailSubject ($plainalert.entities.subject.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty EmailSender ($plainalert.entities.sender.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty EmailDeliveryAction ($plainalert.entities.DeliveryAction.Where({$_ -ne ""}) | Select-Object -Unique)

        #Build the device object
        $global:Device = new-object psobject
        $Device | add-member Noteproperty Name ($alert.DeviceName)
        $Device | add-member Noteproperty Platform $plainalert.Devices.osPlatform
        $Device | add-member Noteproperty Build $plainalert.Devices.osBuild
        $Device | add-member Noteproperty HealthStatus $plainalert.Devices.healthStatus
        $Device | add-member Noteproperty RiskScore $plainalert.Devices.riskScore
        $Device | add-member Noteproperty FirstSeen $plainalert.Devices.firstSeen
        $Device | add-member Noteproperty MachineTags $plainalert.Devices.tags

        #explicit vars needed for advanced hunting
        $DeviceId = $alert.DeviceId
        $global:Timestamp = $alert.Timestamp
        $AccountSid = $alert.AccountSid

        #try to get more identity info via advanced hunting in IdentityInfo table via user SID
        if($null -ne $AccountSid)
        {
            $global:plainIdentity = get-huntingResultMTP -kql "IdentityInfo | where CloudSid =~ '$AccountSid' or OnPremSid =~ '$AccountSid' | take 10" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting identity info"
        }
        else { #if there is no SID, we make a REST call and check for logonusers of the device
            $tempUrl="/machines/$deviceid/logonusers"
            $global:Account=get-DefenderAPIResult -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret -topic "... getting device logons" -api $tempUrl -apiGeoLocation $apiGeoLocation
            $global:AccountName = $Account.value.accountname
            try {
                if($AccountName.GetType().Name -eq "Object[]") #lets see if we have to deal with multiple logon accounts or one
                {
                    $global:AccountName = ($AccountName | Group-Object | Sort-Object count -Descending)[0].name #take the first account
                    $global:plainIdentity = get-huntingResultMTP -kql "IdentityInfo | where AccountName =~ '$AccountName' | take 10" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting identity info"
                    if($null -eq $plainIdentity)
                    {
                        $global:AccountName = ($AccountName | Group-Object | Sort-Object count -Descending)[1].name #take the second account
                        $global:plainIdentity = get-huntingResultMTP -kql "IdentityInfo | where AccountName =~ '$AccountName' | take 10" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting identity info"
                    }
                }
                else {
                    $global:plainIdentity = get-huntingResultMTP -kql "IdentityInfo | where AccountName =~ '$AccountName' | take 10" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting identity info"
                }
            }
            catch {
                $global:plainIdentity = get-huntingResultMTP -kql "IdentityInfo | where AccountName =~ '$AccountName' | take 10" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting identity info"
            }         
        }

        #now take the IdentityInfo results and build a user object
        $global:user = new-object psobject
        $user | add-member Noteproperty AccountUpn ($plainIdentity.AccountUpn.Where({$_ -ne ""}) | Select-Object -Unique)
        $user | add-member Noteproperty Department ($plainIdentity.Department.Where({$_ -ne ""}) | Select-Object -Unique)
        $user | add-member Noteproperty JobTitle ($plainIdentity.JobTitle.Where({$_ -ne ""}) | Select-Object -Unique)
        $user | add-member Noteproperty AccountName ($plainIdentity.AccountName.Where({$_ -ne ""}) | Select-Object -Unique)
        $user | add-member Noteproperty AccountDomain ($plainIdentity.AccountDomain.Where({$_ -ne ""}) | Select-Object -Unique)
        $user | add-member Noteproperty EmailAddress ($plainIdentity.EmailAddress.Where({$_ -ne ""}) | Select-Object -Unique)
        $user | add-member Noteproperty City ($plainIdentity.City.Where({$_ -ne ""}) | Select-Object -Unique)
        $user | add-member Noteproperty Country ($plainIdentity.Country.Where({$_ -ne ""}) | Select-Object -Unique)
        $user | add-member Noteproperty IsAccountEnabled ($plainIdentity.IsAccountEnabled.Where({$_ -ne ""}) | Select-Object -Unique)

        #create some explicit vars we need for advanced hunting
        $upn = $user.AccountUpn
        $emailAddress = $user.EmailAddress

        #associated hunting - main advanced hunting action starts here
        #lets see if we use sha1 or sha256 (prefer sha1 over sha256) 
        if($null -ne $alert.sha1) 
        {
            $global:fileHash = $alert.sha1
        } 
        else 
        {
            if($null -ne $alert.sha256)
            {
                $global:fileHash = $alert.sha256
            }
        }
        #if we have a deviceID, hunt the: registry, network, processes and vulnerabilities (last one not via advanced hunting but API)
        if($null -ne $DeviceId -and $DeviceId -ne "")
        {
            if($registryOn) { $global:registry = get-huntingResult -kql "DeviceRegistryEvents  | where DeviceId =~ '$DeviceId' | where Timestamp  between (datetime_add('$registryT1u', $registryT1, datetime($Timestamp))..datetime_add('$registryT2u', $registryT2, datetime($Timestamp)))" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting registry info" -apiGeoLocation $apiGeoLocation}
            if($networkOn) { 
                $global:network = get-huntingResult -kql "DeviceNetworkEvents | where DeviceId == '$DeviceId' | where Timestamp  between (datetime_add('$networkT1u',$networkT1,datetime($Timestamp))..datetime_add('$networkT2u', $networkT2,datetime($Timestamp)))" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting network info" -apiGeoLocation $apiGeoLocation
                if($numberOfEvents -le 100)
                {
                    $numberOfIps = $numberOfEvents
                }
                else {
                    $numberOfIps = 100
                }
                $body = $network.Remoteip.Where({$_ -ne ""}) | Select-Object -Unique | Select-Object -Last $numberOfIps
                $body = $body | ForEach-Object {'"' + $_ + '",'}
                $finalBody = "[" + (-join $body).trimend(",") + "]"
                $global:ipGeoInfo = get-simpleRestCall -url "http://ip-api.com/batch" -body $finalBody -method "POST" -topic "... getting geo-IP info" 
            }
            if($processesOn) { $processes = $null; $global:processes = get-huntingResult -kql "DeviceProcessEvents | where DeviceId =~ '$DeviceId' | where Timestamp  between (datetime_add('$processesT1u', $processesT1,datetime($Timestamp))..datetime_add('$processesT2u', $processesT2,datetime($Timestamp)))" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting processes info" -apiGeoLocation $apiGeoLocation }

            if($vulnerabilitiesOn) { 
                $vulnUrl="/vulnerabilities/machinesVulnerabilities?`$filter=machineId eq '$deviceId'"
                $rawVulnerabilities =  get-DefenderAPIResult -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret -topic "... getting all vulnerability info" -api $vulnUrl -apiGeoLocation $apiGeoLocation
                $global:vulnerabilities = $rawVulnerabilities.value
            } 
        }
        #getting fileinfo and filestats from MD API
        if($null -ne $fileHash)
        {
            if($fileHash.GetType().Name -eq "Object[]")
            {
                $filesApiInfo = [System.Collections.ArrayList]@()
                $filesApiStats = [System.Collections.ArrayList]@()
                foreach ($fh in $fileHash) {
                    $fileInfoUrl="/files/" + $fh
                    $fileStatsUrl="/files/" + $fh + "/stats?lookBackHours=48"
                    $filesApiStatsTemp = New-Object psobject
                    $filesApiInfoTemp = New-Object psobject
                    $filesApiInfoTemp = get-DefenderAPIResult -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret -topic "... getting all file info" -api $fileInfoUrl -apiGeoLocation $apiGeoLocation
                    $filesApiStatsTemp = get-DefenderAPIResult -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret -topic "... getting all file statistics" -api $fileStatsUrl -apiGeoLocation $apiGeoLocation
                    if($null -ne $filesApiStatsTemp -and $filesApiStatsTemp -ne "")
                    {
                        $filesApiStats.add($filesApiStatsTemp) | Out-Null
                    }
                    if($null -ne $filesApiInfoTemp -and $filesApiInfoTemp -ne "")
                    { 
                        $filesApiInfo.add($filesApiInfoTemp) | Out-Null
                    }
                }
            }
            else {
                $fileInfoUrl="/files/" + $fileHash
                $fileStatsUrl="/files/" + $fileHash + "/stats?lookBackHours=48"
                $global:filesApiInfo = get-DefenderAPIResult -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret -topic "... getting all file info" -api $fileInfoUrl -apiGeoLocation $apiGeoLocation
                $global:filesApiStats = get-DefenderAPIResult -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret -topic "... getting all file statistics" -api $fileStatsUrl -apiGeoLocation $apiGeoLocation
            }
        }
        #if we have a user UPN, we hunt for sign-ins to AAD, Office-files in MCAS and risky sign-ins (the last via direct api, not advanced hunting)
        if($null -ne $upn -and $upn -ne "")
        {
            if($signinsOn -and $null -eq $signins) { $global:signins = get-huntingResultMTP -kql "AADSignInEventsBeta | where AccountUpn =~ '$upn' | where Timestamp  between (datetime_add('$signinsT1u', $signinsT1,datetime($Timestamp))..datetime_add('$signinsT2u', $signinsT2,datetime($Timestamp)))" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting AAD sign-in info" }
            if($officeOn) { $global:office = get-huntingResultMTP -kql "AppFileEvents | where AccountUpn =~ '$upn' | where Timestamp  between (datetime_add('$officeT1u', $officeT1,datetime($Timestamp))..datetime_add('$officeT2u', $officeT2,datetime($Timestamp)))" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting Office (MCAS) info" }
            if($riskySignInsOn) {  $global:riskySignIns = get-graphResponse -graphQuery "/beta/riskDetections?`$filter=userPrincipalName eq '$upn'" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting risky sign-ins" }
        }
        #if we have a user email address, we also hunt for the last incoming and outgoing mail from and to the user mailbox
        if($null -ne $emailAddress -and $emailAddress -ne "")
        {
            if($emailsOn) { $global:emails = get-huntingResultMTP -kql "EmailEvents | where RecipientEmailAddress =~ '$emailAddress' or SenderFromAddress =~ '$emailAddress' | where Timestamp  between (datetime_add('$emailsT1u', $emailsT1,datetime($Timestamp))..datetime_add('$emailsT2u', $emailsT2,datetime($Timestamp))) | join kind=leftouter EmailUrlInfo on NetworkMessageId | join kind=leftouter EmailAttachmentInfo on NetworkMessageId" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting email info" }
        }
    }
    else {
        Write-Host "Error: Query for AlertId failed! This is the way, too!"  -ForegroundColor red
    }
}
# Does generic hunting via the Microsoft Defender for Endpoint API, provide KQL
function get-huntingResult {
    [CmdletBinding()]
    param (
        [string]$kql,
        [string]$clientID,
        [string]$clientSecret,
        [string]$tenantId,
        [string]$topic,
        [string]$irmTimeout,
        [string]$apiGeoLocation
    )
    $error.Clear()
    $oAuthUri = "https://login.microsoftonline.com/" + $tenantId + "/oauth2/token"
    $client_id = $clientID
    $client_secret = $clientSecret
    $authBody = [Ordered] @{
        resource =  "https://" + $apiGeoLocation 
        client_id = $client_id
        client_secret = $client_secret
        grant_type = "client_credentials"
    }
    try {
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    }
    catch {
        Write-Host "get-huntingResult: failed Invoke-RestMethod (Auth)"   -ForegroundColor red
        $error
    }

    $token = $authResponse.access_token
    $url = "https://" + $apiGeoLocation + "/api/advancedqueries/run" 
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $token" 
    }
    $body = ConvertTo-Json -InputObject @{ 'Query' = $kql }
    write-host $topic -ForegroundColor Green
    #Write-host $kql
    try {
        if($config.globalVars.debugon)
        {
            $webResponse = Invoke-RestMethod -Method Post -Uri $url -Headers $headers -Body $body  -verbose -debug -TimeoutSec $irmTimeout
        }
        else {
            $webResponse = Invoke-RestMethod -Method Post -Uri $url -Headers $headers -Body $body -TimeoutSec $irmTimeout
        }
    }
    catch {
        Write-Host "get-huntingResult: failed Invoke-RestMethod ($url)"      -ForegroundColor red
        Write-Host URL: $url
        $error
    }
    return $webResponse.Results
}
# NON-Advanced Hunting API access in Microsoft Defender for Endpoint
function get-DefenderAPIResult {
    [CmdletBinding()]
    param (
        [string]$api,
        [string]$clientID,
        [string]$clientSecret,
        [string]$tenantId,
        [string]$topic,
        [string]$irmTimeout,
        [string]$apiGeoLocation
    )
    $error.Clear()
    $oAuthUri = "https://login.microsoftonline.com/" + $tenantId + "/oauth2/token"
    $client_id = $clientID
    $client_secret = $clientSecret
    $authBody = [Ordered] @{
        resource =  "https://" + $apiGeoLocation 
        client_id = $client_id
        client_secret = $client_secret
        grant_type = "client_credentials"
    }
    try {
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    }
    catch {
        Write-Host "get-DefenderAPIResult: failed Invoke-RestMethod (Auth)"   -ForegroundColor red
        $error
    }

    $token = $authResponse.access_token
    $url = "https://" + $apiGeoLocation + "/api" + $api 
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $token" 
    }
    write-host $topic -ForegroundColor Green
    #Write-host $kql
    try {
        if($config.globalVars.debugon)
        {
            $global:webResponse = Invoke-RestMethod -Method get -Uri $url -Headers $headers -verbose -debug -TimeoutSec $irmTimeout
        }
        else {
            $global:webResponse = Invoke-RestMethod -Method get -Uri $url -Headers $headers -TimeoutSec $irmTimeout
        }
    }
    catch {
        Write-Host "get-DefenderAPIResult: failed Invoke-RestMethod ($url)"      -ForegroundColor red
        Write-Host URL: $url
        $error
    }
    return $webResponse
}
# Advanced hunting against the Microsoft 365 Defender (MTP) API
function get-huntingResultMTP {
    [CmdletBinding()]
    param (
        [string]$kql,
        [string]$clientID,
        [string]$clientSecret,
        [string]$tenantId,
        [string]$topic,
        [string]$irmTimeout
    )
    $error.Clear()
    $oAuthUri = "https://login.microsoftonline.com/" + $tenantId + "/oauth2/token"
    $client_id = $clientID
    $client_secret = $clientSecret
    $authBody = [Ordered] @{
        resource =  "https://api.security.microsoft.com" 
        client_id = $client_id
        client_secret = $client_secret
        grant_type = "client_credentials"
    }
    try {
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    }
    catch {
        Write-Host "get-huntingResultMTP: failed Invoke-RestMethod (Auth) --> $oAuthUri & $authBody"   -ForegroundColor red
        $error
    }
    $token = $authResponse.access_token
    $url = "https://api.security.microsoft.com/api/advancedhunting/run" 
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $token" 
    }
    $body = ConvertTo-Json -InputObject @{ 'Query' = $kql.Replace("`"","'")}
    #write-host $topic -ForegroundColor Green
    try {
        if($config.globalVars.debugon)
        {
            $webResponse = Invoke-RestMethod -Method Post -Uri $url -Headers $headers -Body $body -verbose -debug -TimeoutSec $irmTimeout #-Proxy "http://127.0.0.1:8888"
        } else {
            $webResponse = Invoke-RestMethod -Method Post -Uri $url -Headers $headers -Body $body -TimeoutSec $irmTimeout #-Proxy "http://127.0.0.1:8888"
        }
    }
    catch {
        $errorOutput = "get-huntingResultMTP: failed Invoke-RestMethod ($url) " + $error
        $errorOutput
    }
    $webResponse.Results
}
# NON-Advanced Hunting calls against Microsoft 365 Defender API, does support paging
function get-APIresultMTP {
    [CmdletBinding()]
    param (
        [string]$api,
        [string]$clientID,
        [string]$clientSecret,
        [string]$tenantId,
        [string]$irmTimeout,
        [string]$topic
    )
    $error.Clear()
    $oAuthUri = "https://login.microsoftonline.com/" + $tenantId + "/oauth2/token"
    $client_id = $clientID
    $client_secret = $clientSecret
    $authBody = [Ordered] @{
        resource =  "https://api.security.microsoft.com" 
        client_id = $client_id
        client_secret = $client_secret
        grant_type = "client_credentials"
    }
    try {
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    }
    catch {
        Write-Host "get-huntingResultMTP: failed Invoke-RestMethod (Auth)"   -ForegroundColor red
        $error
    }
    $token = $authResponse.access_token
    $url = "https://api.security.microsoft.com/api" +  $api
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $token" 
    }
    write-host $topic -ForegroundColor Green
    $result  =  @()
    try {

        if($config.globalVars.debugon)
        {
        $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -verbose -debug -TimeoutSec $irmTimeout #-Proxy "http://127.0.0.1:8888"
        }
        else
        {
            $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -TimeoutSec $irmTimeout
        }
        $result = $response.value

        while ($null -ne $response.'@odata.nextLink'){
            $nextUri = $response.'@odata.nextLink';
            if($config.globalVars.debugon)
            {
                $response  = Invoke-RestMethod -Method Get -Uri $nextUri -Headers $headers -verbose -debug -TimeoutSec $irmTimeout
            }
            else {
                $response  = Invoke-RestMethod -Method Get -Uri $nextUri -Headers $headers -TimeoutSec $irmTimeout
            }
            $result += $response.value
        }
    }
    catch {
        Write-Host "get-APIresultMTP: failed Invoke-RestMethod ($url)" -ForegroundColor red
        $error
    }
    return $result
}
# common quieries against MS Graph
function get-graphResponse{
    [CmdletBinding()]
    param (
        [string]$graphQuery,
        [string]$tenantId,
        [string]$clientid,
        [string]$clientsecret,
        [string]$topic
    )
    $error.Clear()
    $oAuthUri = "https://login.microsoftonline.com/" + $tenantId + "/oauth2/token"
    $authBody = [Ordered] @{
        resource = "https://graph.microsoft.com" 
        client_id = $clientid
        client_secret = $clientsecret
        grant_type = "client_credentials"
    }
    try {
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    }
    catch {
        Write-Host "get-graphResponse: failed Invoke-RestMethod (auth)" -ForegroundColor red
        write-host $oAuthUri
        $error
    }

    $token = $authResponse.access_token
    $url = "https://graph.microsoft.com$graphQuery"
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $token" 
    }
    write-host $topic -ForegroundColor green
    try {
        $webResponse = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop
        $webResponse
    }
    catch {
        Write-Host "get-graphResponse: failed Invoke-RestMethod ($url)" -ForegroundColor red
        write-host $oAuthUri
        $error
    }

}
# rest call without authentication, provide full url
function get-simpleRestCall{
    [CmdletBinding()]
    param (
        [string]$url,
        [string]$body,
        [string]$topic,
        [string]$method
    )
    $error.Clear()
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept = 'application/json'
    }
    write-host $topic -ForegroundColor green
    try {
        $webResponse = Invoke-RestMethod -Method $method -Uri $url -body $body -Headers $headers -ErrorAction Stop
        $webResponse
    }
    catch {
        Write-Host "get-simpleRestCall: failed Invoke-RestMethod ($topic)" -ForegroundColor red
        $error
    } 
}
# all alerts from specified tenant
function huntAllAlerts {
    param (
        [string]$TenantId,
        [string]$searchDurationLastXDays
    )
    # display alerts for the last X days:
    if($searchDurationLastXDays -eq "")
    {
        $searchDurationLastXDays = 30
    }
    $DurationDisplayAllAlerts = -$searchDurationLastXDays
    write-host $Tenant.name -ForegroundColor green
    $Today = Get-date -Format "yyyy-MM-dd"
    $StartDateAllAlerts = (get-date($Today)).AddDays($DurationDisplayAllAlerts)
    $StartDateAllAlertsF = Get-Date $StartDateAllAlerts -Format "yyyy-MM-dd"
    $graphQuery = "/beta/security/alerts?`$filter=createdDateTime%20gt%20" + $StartDateAllAlertsF
    $allAlertsResponse = (get-graphResponse -tenantId $TenantId -clientID $clientID -clientSecret $clientSecret -graphQuery $graphQuery -topic "... searching for all alerts").value
    $allAlertsResponse
}
# kql hunting all tenants
function allTenantAction {
    param (
        [string[]]$allTenants,
        [string]$kql
    )
    $allTenantResults = $null
    $allTenantResults = New-Object psobject 
    $singleTenantResult = $null
    foreach($tenant in $allTenants)
    {
        
        $singleTenantResult = get-huntingResultMTP -tenantId $tenant.TenantId -clientID $clientID -clientSecret $clientSecret -kql $kql -apiGeoLocation $apiGeoLocation
        if($null -ne $singleTenantResult)
        {
            $tempTenant =$tenant.name
            $allTenantResults | Add-Member NoteProperty $tempTenant $singleTenantResult
        }
    }
    $allTenantResults
}
# kql hunting single tenant
function singleTenantAction {
    param (
        [psobject]$allTenants,
        [string]$tenantNumber,
        [string]$kql
    )
    $allTenantResults = $null
    $allTenantResults = New-Object psobject 
    $singleTenantResult = $null

    $countingTenants = 1
    foreach($tenant in $allTenants)
    {
        if($countingTenants -eq $tenantNumber)
        {
            $singleTenantResult = get-huntingResultMTP -tenantId $tenant.TenantId -clientID $clientID -clientSecret $clientSecret -kql $kql 
            if($null -ne $singleTenantResult)
            {
                $allTenantResults = $singleTenantResult
            }
            else {
                write-host "Not your day Boba - relax in your Bacta Tank." -ForegroundColor red
            }
        }
        $countingTenants = $countingTenants + 1
    }
    $allTenantResults
}
# kql hunting mulitple tenants
function multiTenantAction {
    param (
        [psobject]$allTenants,
        [string]$tenantNumbers,
        [string]$kql
    )
    $allTenantResults = $null
    $allTenantResults = New-Object System.Collections.ArrayList 
    $singleTenantResult = New-Object psobject 
    $hT = $tenantNumbers.Split(",")
    $countingTenants = 1
    foreach($tenant in $allTenants)
    {
        if($hT -contains $countingTenants)
        {
            $singleTenantResult = get-huntingResultMTP -tenantId $tenant.TenantId -clientID $clientID -clientSecret $clientSecret -kql $kql
            if($null -ne $singleTenantResult)
            {
                if(!$config.globalVars.debugOn)
                {
                    Clear-Host
                }
                $singleTenantResult | add-member Noteproperty Tenant $tenant.name.substring(0,3).toupper() 
                $allTenantResults.add($singleTenantResult) | Out-Null
            }
        }
        $countingTenants = $countingTenants + 1 
    }
    return $allTenantResults
}