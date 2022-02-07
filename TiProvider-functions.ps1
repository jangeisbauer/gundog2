
# read config file
. .\get-config.ps1
# checks URL Scan for URL entities from Alert
function get-urlInfo {
    [CmdletBinding()]
    param (
        [string]$url
    )
    $error.Clear()
    # cleanup URL
    try {
        $url = $url.ToLower().Replace("https://","")
        $url = $url.ToLower().Replace("http://","")
        $url = $url.Trim("/")
        if($url.Contains("/"))
        {
            $url = $url.Split("/")[0]
        }
    }
    catch {}
    try {
        $global:urlScanQuery = Invoke-RestMethod -Method get -Uri "https://urlscan.io/api/v1/search/?q=domain:$url" #-verbose -debug #-Proxy "http://127.0.0.1:8888"
        if($urlScanQuery.results.length -ne 0)
        {
            $global:urlScanResultUrl = ($urlScanQuery.results | Sort-Object indexedAt -Descending | Select-Object -Last 1).result
        }
    }
    catch {
        Write-Host "get-URLinfo: failed Invoke-RestMethod (UrlScan)" -ForegroundColor red
        $error
    }
    if($urlScanResultUrl -ne "" -and $null -ne $urlScanResultUrl)
    {
        try {
            $global:urlScan = Invoke-RestMethod -Method get -Uri $urlScanResultUrl #-verbose -debug #-Proxy "http://127.0.0.1:8888"
        }
        catch {
            Write-Host "get-URLinfo: failed Invoke-RestMethod ($url)" -ForegroundColor red
            $error
        }
    }
}
#gets fileInfo from abuse.ch, provide file hash
function get-fileInfo {
    [CmdletBinding()]
    param (
        [string]$fileHash
    )
    $error.Clear()
    try {
        #check abuse.ch
        $global:abuseFileResponse = Invoke-RestMethod -Method POST -Uri "https://mb-api.abuse.ch/api/v1/" -body "query=get_info&hash=$fileHash" -ErrorAction Stop
        $global:abuseFileData = $abuseFileResponse.data
        $global:abuseFileStatus = $abuseFileResponse.query_status
        }
    catch {
        Write-Host "get-fileInfo: failed Invoke-RestMethod (abuse)" -ForegroundColor red
        $error
    }    
}