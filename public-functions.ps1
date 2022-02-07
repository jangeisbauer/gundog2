# import other modules
. .\gundoghunt-alertpresentation.ps1
. .\hunting-functions.ps1

# main function to start gundog
function Start-Gundog {

    if($config.allTenants[0].tenantID -eq "tenantID")
    {
        Read-HostCustom -prompt "Your tenant configuration is empty like the desserts on Tatooine, Boba. Press enter to get to main menu, then choose 'Configuration' >>> "
    }
    displayHeader -menuText "1 All alerts by Tenant  `n2 Gundog Hunting by AlertId  `n3 Vulnerabilities  `n4 All Alerts (med/high) last 24h  `n5 All Alerts (med/high) last 24h (Refresh)  `n6 Plain KQL Hunting  `n7 Hunt from GitHub Repo  `n8 Configuration" 
    #$menuChoice = Read-Host "Hunt for"
    $menuChoice = Read-HostCustom -Prompt "Hunt for >>> "

    if($menuChoice -eq 1)
    {
        Get-AllAlertsByTenant
    }
    # gundog hunt
    if($menuChoice -eq 2)
    {
        Get-GunDogHunt
    }
    # all tenants gundog hunt
    if($menuChoice -eq 3)
    {
        Get-Vulnerabilities
    }
    # all tenants all medium & high alerts MDE
    if($menuChoice -eq 4)
    {
        Get-AllAlertsAllTenants
    }
    # all tenants all medium & high alerts MDE - reload every 
    if($menuChoice -eq 5)
    {
        Get-AllAlertsAllTenantsRefresh
    }
    # plain kql hunting
    if($menuChoice -eq 6)
    {
        Get-MultiTenantHunting
    }
    # hunt from repo
    if($menuChoice -eq 7)
    {
        Get-MultiTenantHunting -kqlFktInput "github"
    }
    # set config
    if($menuChoice -eq 8)
    {
        Set-GundogConfig
    }

    $menuChoice = ""
}
# fire up notepad to configure gundog.config
function Set-GundogConfig {
    Start-Process "notepad.exe" "gundog.config"
}
# get vulnerabilities for one, multiple or all tenants
function Get-Vulnerabilities {

    Get-MultiTenantHunting -headline "Critical vulnerabilities from the last 30 days" -kqlFktInput "
    let newVuln =
    DeviceTvmSoftwareVulnerabilitiesKB 
    | where VulnerabilitySeverityLevel == 'Critical'
    | where LastModifiedTime >ago(30day);
    DeviceTvmSoftwareVulnerabilities 
    | join newVuln on CveId
    | summarize dcount(DeviceId) by DeviceName, DeviceId, Timestamp=LastModifiedTime, SoftwareName, SoftwareVendor, SoftwareVersion, VulnerabilitySeverityLevel, CvssScore, IsExploitAvailable, CveId
    | project Timestamp, CveId, SoftwareName, SoftwareVendor, SoftwareVersion, VulnerabilitySeverityLevel, CvssScore, IsExploitAvailable, DeviceId
    "
}
# all (med/high) alerts from all tenants refresh
function Get-AllAlertsAllTenantsRefresh {
        $allTenants = get-TenantList
        write-host
        write-host Hunting ... -ForegroundColor green
        write-host
        do
        {
            $global:allTenantResults = New-Object System.Collections.ArrayList 
            $kql = "AlertInfo | where Timestamp > ago(1d) | where Severity == 'Medium' or Severity == 'High' | where ServiceSource == 'Microsoft Defender for Endpoint' | join AlertEvidence on AlertId | summarize count() by AlertId, Timestamp, Title, Severity | order by Timestamp | project-away count_"
            foreach($Tenant in $allTenants)
            {
                $singleTenantResult = get-huntingResultMTP -tenantId $Tenant.TenantId -clientID $clientID -clientSecret $clientSecret -kql $kql 
                if($null -ne $singleTenantResult)
                {
                    $temp = $singleTenantResult | ft @{Name="Timestamp";expression={if($_.timestamp -gt (get-date).addhours(-2)){$color="33"}else{if($_.Severity -eq "High"){$color="31"}};$e = [char]27;"$e[${color}m$($_.Timestamp)${e}[0m"}}, @{Name="Tenant";expression={$Tenant.name.substring(0,3).toupper()}}, Timestamp, Title, AlertId, Severity
                    $allTenantResults.add($temp) | Out-Null
                }
            }
            if(!$config.globalVars.debugOn)
            {
                Clear-Host
            }
            Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
            write-host "All high & medium alerts from all Tenants last 24h                                             " -ForegroundColor green
            Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
            Write-Host 
            $date = get-date
            Write-Host Last Update: $date -ForegroundColor green
            $allTenantResults
            Start-Sleep -Seconds 3600
        } #dont stop me now
        while (1 -eq 1) {
            
        }
}
# kql hunting from github
function Get-KQLFromGitHub {

        $gitHubRawUrl = Read-HostCustom -Prompt "GitHub Repo >>> "
        $repoName = $gitHubRawUrl.Replace("https://github.com/","")
        $gitDir = Invoke-WebRequest $gitHubRawUrl                                                                                               
        $global:gitRules = ($gitDir.Links.outerhtml | ?{$_ -like "*$repoName/blob/master*"} | %{[regex]::match($_,'master.*"').Value}).Replace('"',"") | %{if($_ -ne ""){"https://raw.githubusercontent.com/$repoName/" + $_}}
        Write-Host
        write-host "Found those queries:" -ForegroundColor Green
        write-host
        $counter = 0

        foreach($rawLink in $gitRules)
        {
            $counter += 1
            $tempLine = "https://raw.githubusercontent.com/$repoName" + "/master/"
            write-host $counter $rawLink.Replace($tempLine,"").Replace("%20"," ")
        }
        write-host
        [int]$queryNumber= Read-HostCustom -Prompt "Run query >>> "
        $queryNumberIndex = $queryNumber - 1
        $kql = Invoke-WebRequest $gitRules[$queryNumberIndex]
        return $kql
}
# all alerts (med/high) from all tenants (once)
function Get-AllAlertsAllTenants {

    $allTenantResults = New-Object System.Collections.ArrayList 
    $allTenants = get-TenantList
    write-host
    write-host Hunting ... -ForegroundColor green
    write-host
    $kql = "AlertInfo | where Timestamp > ago(1d) | where Severity == 'Medium' or Severity == 'High' | where ServiceSource == 'Microsoft Defender for Endpoint' | join AlertEvidence on AlertId | summarize count() by AlertId, Timestamp, Title, Severity | order by Timestamp | project-away count_"
    foreach($tenant in $allTenants)
    {
        $singleTenantResult = get-huntingResultMTP -tenantId $tenant.TenantId -clientID $clientID -clientSecret $clientSecret -kql $kql
        if($null -ne $singleTenantResult)
        {
            $temp = $singleTenantResult | ft @{Name="Tenant";expression={$tenant.name.substring(0,3).toupper()}}, Timestamp, Title, AlertId, Severity
            $allTenantResults.add($temp) | Out-Null
        }
    }
    if(!$config.globalVars.debugOn)
    {
        Clear-Host
    }
    Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
    write-host "All high & medium alerts from all Tenants last 24h                                             " -ForegroundColor green
    Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
    Write-Host
    Write-Host
    $allTenantResults
    $allIncidents = $null
}
# receives list of tenant numbers then does the kql hunting against those tenants
function Get-MultiTenantHunting {
    param (
        [string]$kqlFktInput,
        [string]$headline,
        [string]$tenantNumbers
    )
    if($headline -eq "")
    {
        $headline = "Hunting Results from your custom KQL Query:"
    }
    if($tenantNumbers -eq "")
    {
        $allTenants = get-TenantList
        $menuTextTenants = get-menuTextTenants
        displayHeader -menuText $menuTextTenants 
        [string]$tenantNumbers = Read-HostCustom -Prompt "Hunt in those tenants (Tenant Numbers Comma Seperated, * for all) >>> "
    }
    if($kqlFktInput -eq "")
    {
        $kqlInput = Read-HostCustom -Prompt "Type your query here or copy it to clipboard, then press Enter >>> "
        if($kqlInput -eq "")
        {
            $kql = Get-Clipboard
        }
        else {
            $kql = $kqlInput
        }
    }
    else {
        if($kqlFktInput -eq 'github')
        {
            $kql = Get-KQLFromGitHub
        }
        else {
            $kql = $kqlFktInput   
        }
    }
    write-host Hunting ... -ForegroundColor red
    if(!$config.globalVars.debugOn)
    {
        Clear-Host
    }
    
    if($tenantNumbers -eq "*")
    {
        $allTenantResults = allTenantAction

        $x = ($allTenantResults | Get-Member | Where-Object{$_.MemberType -eq 'NoteProperty'}).name
        $global:results = $x | ForEach-Object{$t=$_;$allTenantResults.($_)} | Format-Table @{Name="Tenant";expression={$t}},*

        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "$headline (more via: `$results)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green

        $results
    }
    else {
            if($tenantNumbers.Contains(","))
            {
                $global:results = multiTenantAction -allTenants $allTenants -tenantNumbers $tenantNumbers -kql $kql

                Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
                write-host "$headline (more via: `$results)" -ForegroundColor green
                write-host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green

                $results | Format-Table Tenant, *
            }
            else {
                $singleTenantResult = singleTenantAction -allTenants $allTenants -tenantNumber $tenantNumbers -kql $kql  
                if($null -ne $singleTenantResult)
                {
                    Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
                    write-host "$headline (more via: `$results)" -ForegroundColor green
                    write-host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
                    
                    $singleTenantResult | Format-Table
                    $global:results=$singleTenantResult
                }
                else {
                    write-host Sorry Boba, your query results are as empty as the deserts on tatooine.
                }
            }
    }
    # in case of vulnerability hunting, ask for further hunting for devices per CVE
    if($headline -eq "Critical vulnerabilities from the last 30 days")
    {
        $cveid = Read-HostCustom -Prompt "Type CveId for a list of affected devices or press enter to exit >>> "
        if($cveid -ne "")
        {
            Get-MultiTenantHunting -tenantNumbers $tenantNumbers -kqlFktInput "DeviceTvmSoftwareVulnerabilities | where CveId == '$cveid'" -headline "CVE Hunting: $cveid affected devices"
        }
    }
}
# v1 functionality - gundog hunting against alertID
function Get-GunDogHunt {
    $menuTextTenants=get-menuTextTenants
    $allTenants=get-TenantList
    displayHeader -menuText $menuTextTenants
    $tenantNumber = Read-HostCustom -Prompt "Tenant Number >>> "
    $tenantTenantNumber = $tenantNumber - 1 
    $tenantId=$allTenants[$tenantTenantNumber].TenantId
    $AlertId = Read-HostCustom -Prompt "Type AlertID >>> "
    write-host Hunting ... -ForegroundColor red
    get-alertData -AlertId $AlertId -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret
    $CurrentTenant=$allTenants[$tenantTenantNumber].name
    get-alertDataResults

    if($null -eq $alert)
    {
        write-host "We couldn't get any response for the Alert ID you provided:" $AlertId  -ForegroundColor red
    }
}
# all alerts from one tenant (not only med/high)
function Get-AllAlertsByTenant {
    $menuTextTenants=get-menuTextTenants
    $allTenants=get-TenantList
    displayHeader -menuText $menuTextTenants
    $tenantNumber = Read-HostCustom -Prompt "Tenant Number >>> "
    $tenantTenantNumber = ([int]$tenantNumber - 1).ToString()
    $tenantId=$allTenants[$tenantTenantNumber].TenantId
    if($config.globalVars.debugon)
    {
        Write-Host tenantID $tenantId
    }
    $duration=Read-HostCustom -Prompt "Display alerts from last X days (default = 30) >>> "  
    $global:results = huntAllAlerts -TenantId $tenantId -searchDurationLastXDays $duration

    $CurrentTenant=$allTenants[$tenantTenantNumber].name
    if(!$config.globalVars.debugOn)
    {
        Clear-Host
    }
    if($null -ne $results)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "All Alerts from: $CurrentTenant                                                                (more info via `$results)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $results | Select-Object -ErrorAction SilentlyContinue | Sort-Object createdDateTime -Descending | Format-Table @{Name="Time";expression={get-date($_.createdDateTime)}}, id, title, severity,@{Name="source";expression={$_.vendorinformation.provider}}, status, description  
    }
}
#this gives back a psobject of all tenants form config 
function get-TenantList {
    $gundogConfig = get-content .\gundog.config #Invoke-WebRequest -Uri $gistURL -UseBasicParsing
    $global:config = $gundogConfig | ConvertFrom-Json # add $gist.content for IWR

    $allTenants = @()
    $allTenants.Clear()
    $numberOfTenants=0

    $menuTextTenants = ""
    foreach($c in $config.allTenants)
    {
        $PSObjectAllTenants = new-object psobject
        $PSObjectAllTenants | add-member Noteproperty TenantId $c.tenantID
        $PSObjectAllTenants | add-member Noteproperty name $c.name
        $allTenants += $PSObjectAllTenants
        $numberOfTenants = $numberOfTenants + 1
        $menuTextTenants = $menuTextTenants + $numberOfTenants.ToString() + " " + $PSObjectAllTenants.name.substring(0,3).toupper() + " "
    }
    $allTenants
}
# this gives back the TEXT (string) of all tenants from config
function get-menuTextTenants {
    $gundogConfig = get-content .\gundog.config 
    $global:config = $gundogConfig | ConvertFrom-Json # add $gist.content for IWR

    $allTenants = @()
    $allTenants.Clear()
    $numberOfTenants=0

    $numberOfTenants = $null
    $menuTextTenants = ""
    foreach($c in $config.allTenants)
    {
        $PSObjectAllTenants = new-object psobject
        $PSObjectAllTenants | add-member Noteproperty TenantId $c.tenantID
        $PSObjectAllTenants | add-member Noteproperty name $c.name
        $allTenants += $PSObjectAllTenants
        $numberOfTenants = $numberOfTenants + 1
        $menuTextTenants = $menuTextTenants + $numberOfTenants.ToString() + " " + $PSObjectAllTenants.name.substring(0,3).toupper() + " "
        if($numberOfTenants % 12 -eq 0)
        {
            $menuTextTenants = $menuTextTenants + "`n`n"
        }
    }
    $menuTextTenants
}