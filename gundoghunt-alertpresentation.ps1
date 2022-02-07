# load config
. .\get-config.ps1

#Main function to PRESENT the data
function displayHeader {
    param (
        [string]$menuText
    )
    $logoColor="green"
    [console]::ForegroundColor = $logoColor
    if(!$debugOn)
    {
        Clear-Host
    }
    write-host "                                                      	gggggg                  " 
    write-host "                                                   gggggg                       "       
    write-host "                                             gggggg                             "       
    write-host "                                      ggggggg                                   "      
    write-host "         %ggggggg              ggggggggg                                        "     
    write-host "       gggggggggggg.   %ggggggg  gggg                                           "  
    write-host "        ggggggggggg ggggggg     gggg                                            "   
    write-host "        ggggggggggggggg        ggggg                                            " 
    write-host "         ggggggggggggg          ggggg                                           " 
    write-host "    ggggggggggggggggggggggggggggggg%                                            "
    write-host "    gggggggggggggggggggggggggggggggg                                            "
    write-host "   ggggggggggggggggggggggggggggg                                                "
    write-host "    ggggggggggggggggggggg    g                                                  "
    write-host "   gggggggggggggggggg      .                                                    "
    write-host "    ggggggggggggggggggggg                                                       "
    write-host "   gggggggggggggggggggg                                                         "
    write-host "    ggggggggggggggggggg                                                         "
    write-host "    gggggggggggggggggggg                                                        "
    write-host "   *ggggggggggggggggggg                                                         "
    write-host "   ggggggggggggggggggggg                                                        "
    write-host "   gggggggggggggggggggg%                                                        "
    write-host "      gggggggggggggggggg                                                        "
    write-host "    ggggggggggggggggggggg                                                       "
    write-host "    gggggggggggggggggggggg                                                      "
    write-host "   gggggggggggg /ggggggggg                                                      "
    write-host "    gggggggggg    ggggggggg                                       ,gggggg       "
    write-host "   ggggggggggg     gggggggg                              .  gggggggggg<●>gg/  "
    write-host "   gggggggggg      gggggggg    %gggggggggggggggggggggggggggggggggggggggggg,*    "
    write-host "    gggggggg       gggggggg     gggggggggggggggggggggggggggggggggg              "
    write-host "   ggggggggg       gggggggg    gggggggggggggggggggggggggggggggg,                "
    write-host "   gggggggg       %gggggggg   ggggggggggg    gggggggggggggggg%                  "
    write-host "   ggggggg       ggggggggg   /gggggggggg/        ,ggggggggggg                   "
    write-host "  gggggggg       gggggggg   gggg   gggg/              gg/  /gggg                "
    write-host " ggggggg          ggggggg ggg      ggg        8I      gg       g                "
    write-host "ggggggggg         .gggggggg      ggg          8I     *gg      gg                "
    write-host " %gggggg          gggggggggg      gg          8I     *gg                        "
    write-host " gggggg            *g/ ggggggg     .g         8I       gggg                     "
    write-host "ggggg ,gg  gg      gg   ,ggg ggg.      .gggg.8I    ,ggggg.    ,gggg,gg          "
    write-host "dP    Y8I  I8      8I  ,8   8P   8,   dP    Y8I   dP    Y8gggdP    Y8I          "
    write-host "i8     ,8I  I8.    .8I  I8   8I   8I  i8     .8I  i8     ,8I i8     .8I         "
    write-host "d8     d8I  d8b    d8b  dP   8I   Yb  d8     d8b  d8     d8  d8     d8I         "
    write-host  "P Y8888P.8888P..Y88P..Y88P.   8I   .Y8P.Y8888P..Y8P.Y8888P   P.Y8888P.888      "    
    write-host  "    .d8I.                                                         d8I          "
    write-host  "  .dP-8I                                                       ,dP.8I          "
    write-host  " .8    8I                                                      .8   8I         "
    write-host  "  I8   8I                                                      I8   8I         "
    write-host  "  .8   8I                                                      .8   8I         "   
    write-host  "   .Y8P.                                                        .Y8P           "
    Write-Host 
    Write-Host  "Version 2.0 | February 2022 | (C) @jangeisbauer | Happy Hunting" 
    [console]::ForegroundColor = "White"
    write-host $versionText
    Write-Host
    write-host $menuText
    Write-Host
    Write-Host
}
# custom prompt
function Read-HostCustom{
    param($Prompt)
    Write-Host $Prompt -NoNewLine
    $Host.UI.ReadLine()
}
# gundog hunting alert presentation (v1 functionality)
function get-alertDataResults {
    if(!$debugOn)
    {
        Clear-Host
    }
    if($null -ne $alert)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor red
        Write-host Tenant: $CurrentTenant
        $tempAlertTitle = "[" + $plainalert.severity + "] " + $alert.Title   
        Write-Host "$tempAlertTitle (more info via `$alert)"  -ForegroundColor red       
        $alertTime = get-date($alert.Timestamp)
        Write-Host $alertTime
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor red
        Write-Host
        Write-Host "Category:" $alert.category "| Detection Source:" $alert.DetectionSource "| Investigation: " $plainalert.investigationState "| Status: " $plainalert.status
        Write-Host 
    }
    if($null -ne $plainalert)
    {
        $global:Incident = $allIncidents | Where-Object{$_.incidentid -eq $plainalert.incidentId}
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor darkyellow
        $incidentName = $Incident.incidentName 
        Write-Host "Associated Incident: $incidentName (more info via `$Incident)"  -ForegroundColor darkyellow      
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor darkyellow
        Write-Host
        Write-Host "Incident ID:" $Incident.incidentId " | Incident Severity:" $Incident.Severity  
        Write-Host
        if($Incident.alerts.count -gt 1)
        {
            Write-Host "Other Alerts in this Incident:" -ForegroundColor darkyellow
            Write-Host
            foreach ($incidentAlert in $Incident.alerts) {
                if($incidentAlert.alertId -ne $plainalert.alertId)
                {
                    Write-Host "Alert Name:" $incidentAlert.title
                    Write-Host "AlertID:" $incidentAlert.alertID
                    Write-Host "Severity:" $incidentAlert.severity
                    Write-Host "Service Source:" $incidentAlert.serviceSource
                    Write-Host "Creation Time:" $incidentAlert.creationTime
                    Write-Host "Status:" $incidentAlert.status
                    write-Host "Classification:" $incidentAlert.classification
                    write-Host "Assigned To:" $incidentAlert.assignedTo
                    Write-Host
                }
            }
        }
        else {
            Write-Host "The alert is the only alert in this incident."
            Write-Host 
        }
    }
    if($null -ne $alert.EmailSubject)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "Email-Alert                                                                                     (more info via `$alert)"  -ForegroundColor green   
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "EmailSubject:" $alert.EmailSubject
        Write-Host "EmailP1Sender:" $alert.EmailP1Sender 
        Write-Host "EmailP2Sender:" $alert.EmailP2Sender
        Write-Host "EmailSenderIP:" $alert.EmailSenderIP 
        Write-Host "EmailThreats:" $alert.EmailThreats 
        Write-Host "EmailThreatIntelligence:" $alert.EmailThreatIntelligence 
        Write-Host "EmailDeliveryAction:" $alert.EmailDeliveryAction 
        Write-Host "EmailDeliveryLocation:" $alert.EmailDeliveryLocation 
        Write-Host
    }
    if($null -ne $alert.Entities.ProcessCommandLine)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "Process Alert                                                                                   (more info via `$alert)"  -ForegroundColor green   
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "File Name:" $alert.Entities.fileName
        Write-Host "File Path:" $alert.Entities.filePath
        Write-Host "Process Command Line:" $alert.Entities.ProcessCommandLine 
        Write-Host
    }
    if($null -ne $alert.filename -or $null -ne $alert.sha256 -or $null -ne $alert.folderpath -or $null -ne $alert.sha1)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "Files                                                                (more info via `$filesApiInfo and `$filesApiStats)"  -ForegroundColor green   
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "FileName:" $alert.filename 
        Write-Host "Folderpath:" $alert.folderpath 
        Write-Host "SHA1:" $alert.sha1
        Write-Host "SHA256:" $alert.sha256 
        Write-Host
        if($null -ne $filesApiInfo)
        {
            if($filesApiInfo.GetType().Name -eq "Object[]")
            {
                foreach ($fi in $filesApiInfo) {
                    Write-Host Global Prevalence: $fi.globalPrevalence
                    Write-Host Global First Observed: $fi.globalFirstObserved
                    Write-Host File Size: $fi.size
                    Write-Host File Product Name: $fi.fileProductName
                    Write-Host Signer: $fi.signer
                    Write-Host Issuer: $fi.issuer
                    Write-Host Is Valid Cert: $fi.isValidCertificate
                    Write-Host
                }
            }
            else {
                Write-Host Global Prevalence: $filesApiInfo.globalPrevalence
                Write-Host Global First Observed: $filesApiInfo.globalFirstObserved
                Write-Host File Size: $filesApiInfo.size
                Write-Host File Product Name: $filesApiInfo.fileProductName
                Write-Host Signer: $filesApiInfo.signer
                Write-Host Issuer: $filesApiInfo.issuer
                Write-Host Is Valid Cert: $filesApiInfo.isValidCertificate
                Write-Host
            }
        }
        if($null -ne $filesApiStats)
        {
            if($filesApiStats.GetType().Name -eq "Object[]")
            {
                foreach ($fs in $filesApiStats) {
                    Write-Host Org Prevalence: $fs.orgPrevalence
                    Write-Host Org First Obeserved: $fs.orgFirstSeen
                    Write-Host
                }
            }
            else {
                Write-Host Org Prevalence: $filesApiStats.orgPrevalence
                Write-Host Org First Obeserved: $filesApiStats.orgFirstSeen
                Write-Host
            }
        }
        
    }

    if($null -ne $alert.Remoteurl -or $null -ne $alert.urls)
    {
        if($alert.urls -ne "about:internet")
        {
            if($null -ne $alert.Remoteurl) {$url = $alert.Remoteurl}
            if($null -ne $alert.urls) {$url = $alert.urls}
            Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
            Write-Host "URLs                                                                     (more info via `$urlScan & `$urlScanResultUrl)" -ForegroundColor green
            Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
            Write-Host $alert.url
            Write-Host
            
            if($url.GetType().Name -eq "Object[]")
            {
                foreach ($u in $url) {
                    get-urlInfo -url $u
                    if($null -ne $urlScan -and $urlScan -ne "")
                    {
                        Write-Host $u -ForegroundColor Yellow
                        write-host $urlScanResult 
                        if($null -ne $urlScan.verdicts.overall)
                        {
                            Write-Host Malicious: $urlScan.verdicts.overall.malicious
                            $ipsTemp = $urlScan.lists.ips | Select-Object -First 10
                            Write-Host IPs: $ipsTemp
                            $countryTemp = $urlScan.lists.countries | Select-Object -First 10
                            Write-Host Countries: $countryTemp
                            $cityTemp = $urlScan.page.city | Select-Object -First 10
                            Write-Host City: $cityTemp
                            $domainsTemp = $urlScan.lists.Domains | Select-Object -First 10
                            Write-Host Domains: $domainsTemp
                            $serverTemp = $urlScan.lists.servers | Select-Object -First 10
                            Write-Host Server: $serverTemp
                            $certsTemp = $urlScan.lists.certificates | Select-Object -First 10
                            Write-Host Certificates: $certsTemp
                            write-host
                        }
                    }
                    else {
                        Write-Host $u -ForegroundColor Yellow
                        write-host "No results from URLScan.io"
                    }
                }
            }else 
            {
                get-urlInfo -url $url
                if($null -ne $urlScan -and $urlScan -ne "")
                {
                    Write-Host $url -ForegroundColor Yellow
                    write-host $urlScanResult
                    if($null -ne $urlScan.verdicts.overall)
                    {
                        Write-Host Malicious: $urlScan.verdicts.overall.malicious
                        $ipsTemp = $urlScan.lists.ips | Select-Object -First 10
                        Write-Host IPs: $ipsTemp
                        $countryTemp = $urlScan.lists.countries | Select-Object -First 10
                        Write-Host Countries: $countryTemp
                        $cityTemp = $urlScan.page.city | Select-Object -First 10
                        Write-Host City: $cityTemp
                        $domainsTemp = $urlScan.lists.Domains | Select-Object -First 10
                        Write-Host Domains: $domainsTemp
                        $serverTemp = $urlScan.lists.servers | Select-Object -First 10
                        Write-Host Server: $serverTemp
                        $certsTemp = $urlScan.lists.certificates | Select-Object -First 10
                        Write-Host Certificates: $certsTemp
                        write-host
                    }
                }
                else {
                    Write-Host $url -ForegroundColor Yellow
                    write-host "No results from URLScan.io"
                }
            }
            Remove-Variable url -ErrorAction SilentlyContinue
            Remove-Variable urlScan -ErrorAction SilentlyContinue
            Remove-Variable urlScanResult -ErrorAction SilentlyContinue
            Write-Host
        }
    }
    if($null -ne $device)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "Device                                                                                         (more info via `$Device)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $device  | Out-Host
    }
    if($null -ne $user)
    {
        Write-Host
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "User                                                                                             (more info via `$User)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $user  | Out-Host
    }
    if($null -ne $riskySignIns)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "Risky SignIns                                                                            (more info via `$riskySignIns)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $riskySignIns.value | Sort-Object Timestamp -Descending | Format-Table @{Name="Time";expression={get-date($_.activityDateTime)}}, riskType, riskEvent, riskLevel, @{Name="City";expression={$_.location.city}}, @{Name="State";expression={$_.location.state}}, @{Name="Country";expression={$_.location.countryorregion}} | Out-Host
        Write-Host
        if($riskySignIns.value.Count -eq 0)
        {
            $AccountName = $user.accountname
            Write-Host "No Risky SignIns for" $AccountName
            Write-Host
        }
    }
    if($null -ne $network)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "Network                                                                                       (more info via `$Network)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $network | Select-Object -Last $numberOfEvents -ErrorAction SilentlyContinue | Sort-Object Timestamp -Descending | Where-Object{$_.remoteurl -ne "" -and $_.remoteurl -notmatch $notMatchThese} | Format-Table @{Name="Time";expression={get-date($_.TimeStamp)}},InitiatingProcessFileName, @{Name="Country";expression={($ipGeoInfo -match $_.RemoteIP).Country}},@{Name="City";expression={($ipGeoInfo -match $_.RemoteIP).City}}, RemoteIP, RemotePort, RemoteUrl | Out-Host
    }
    if($null -ne $processes)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "Processes                                                                                   (more info via `$Processes)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $processes | Select-Object -Last $numberOfEvents -ErrorAction SilentlyContinue | Sort-Object Timestamp -Descending | Format-Table @{Name="Time";expression={get-date($_.TimeStamp)}}, ActionType, FolderPath, ProcessCommandLine, InitiatingProcessAccountName | Out-Host
    }
    if($null -ne $vulnerabilities)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "Vulnerabilities                                                                       (more info via `$vulnerabilities)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $criticalVuln=$vulnerabilities | Where-Object {$_.severity -eq "Critical"} | Format-Table cveId, productName, ProductVendor, ProductVersion, severity | Out-Host
        $criticalVuln
        Write-Host
        if($criticalVuln.Count -eq 0)
        {
            $deviceName = $device.name 
            Write-Host "No critical vulnerabilities on $deviceName"
            Write-Host
        }
    }
    if($null -ne $signins)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "SignIns                                                                                       (more info via `$signins)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "User City:" $user.city "User Country:" $user.country -ForegroundColor yellow
        $signins | Select-Object -Last $numberOfEvents -ErrorAction SilentlyContinue | Sort-Object Timestamp -Descending | Format-Table @{Name="Time";expression={get-date($_.TimeStamp)}}, Application, LogonType, AccountUpn, DeviceName, Country, City, IPAddress  | Out-Host
    }
    if($null -ne $emails)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "Emails                                                                                         (more info via `$emails)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $emails | Select-Object -Last $numberOfEvents -ErrorAction SilentlyContinue | Sort-Object Timestamp -Descending | Format-Table @{Name="Time";expression={get-date($_.TimeStamp)}}, SenderFromAddress, RecipientEmailAddress, Subject, Url, FileName  | Out-Host
    }
    if($null -ne $office)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "Office                                                                                         (more info via `$Office)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $office | Select-Object -Last $numberOfEvents -ErrorAction SilentlyContinue | Sort-Object Timestamp -Descending | Format-Table @{Name="Time";expression={get-date($_.TimeStamp)}}, Application, FileName, DeviceName, ISP | Out-Host
    }
    if($null -ne $allalerts)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "All Alerts                                                                                  (more info via `$allalerts)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $allIncidents.alerts | Where-Object{$_.devices.devicednsname -eq $alert.devicename -or $_.entities.accountname -eq $alert.accountname} | Format-Table @{Name="Time";expression={get-date($_.creationTime)}}, Title, Severity, status, DetectionSource | out-host
    }
    if($null -ne $registry)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "Registry                                                                                     (more info via `$Registry)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $registry | Select-Object -Last $numberOfEvents -ErrorAction SilentlyContinue | Where-Object {$_.RegistryValueName -ne ""} | Sort-Object Timestamp -Descending | Format-Table @{Name="Time";expression={get-date($_.TimeStamp)}}, RegKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine | Out-Host
    }
}
