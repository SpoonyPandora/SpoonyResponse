
<# Collect any registry run keys on the system for the HKCU and HKLM hives. #>

function getRunKeys()
{
    Write-Host 'Collecting HKCU Run keys...'
    
    Get-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    
    Write-Host 'Collecting HKCU RunOnce keys...'
    
    Get-Item -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    
    Write-Host 'Collecting HKLM Run keys...'
    
    Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    
    Write-Host 'Collecting HKLM RunOnce keys...'
    
    Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    
}

<# Get current running services. #>

function getCurrentServices()
{
    Write-Host 'Collecting running services...'
    
    Get-Service | Where-Object {$_.Status -eq 'Running'} | Format-List -property Name, DisplayName,ServiceName,ServiceType,StartType
}

<# Get running process, including process owner. Must be run from an elevated shell. #>

function getRunningProcesses()
{
    $ErrorActionPreference = 'silentlycontinue'
    
    Write-Host 'Collecting running processes...'
    
    Get-Process -IncludeUserName
}

<# Enumerate network connections. #>

function getNetworkConnections()
{
 
    Write-Host 'Collecting network connections...'
    
    netstat -abof | format-table -autosize

    #Get-NetTCPConnection |  Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcessName
    
}

<# Get all scheduled tasks. #>

function getScheduledTasks()
{
    Write-Host 'Collecting scheduled tasks...'
    
    schtasks
}

<# Print system hosts file. #>

function getHostsFile()
{
    Write-Host 'Collecting hosts file content...'
    
    Get-Content C:\Windows\System32\Drivers\etc\hosts
}


<# Get startup objects #>

function getStartupObjects()
{
    $user = Read-Host 'Provide account/user name:'

    Write-Host 'Collecting startup objects for user $user...'

    $directory = "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"

    Get-ChildItem $directory
}

<# Show menu. #>

function Show-Menu
{
    param (
        [string]$Title = ' ________  ________  ________  ________  ________       ___    ___      ________  _______   ________  ________  ________  ________   ________  _______      
|\   ____\|\   __  \|\   __  \|\   __  \|\   ___  \    |\  \  /  /|    |\   __  \|\  ___ \ |\   ____\|\   __  \|\   __  \|\   ___  \|\   ____\|\  ___ \     
\ \  \___|\ \  \|\  \ \  \|\  \ \  \|\  \ \  \\ \  \   \ \  \/  / /    \ \  \|\  \ \   __/|\ \  \___|\ \  \|\  \ \  \|\  \ \  \\ \  \ \  \___|\ \   __/|    
 \ \_____  \ \   ____\ \  \\\  \ \  \\\  \ \  \\ \  \   \ \    / /      \ \   _  _\ \  \_|/_\ \_____  \ \   ____\ \  \\\  \ \  \\ \  \ \_____  \ \  \_|/__  
  \|____|\  \ \  \___|\ \  \\\  \ \  \\\  \ \  \\ \  \   \/  /  /        \ \  \\  \\ \  \_|\ \|____|\  \ \  \___|\ \  \\\  \ \  \\ \  \|____|\  \ \  \_|\ \ 
    ____\_\  \ \__\    \ \_______\ \_______\ \__\\ \__\__/  / /           \ \__\\ _\\ \_______\____\_\  \ \__\    \ \_______\ \__\\ \__\____\_\  \ \_______\
   |\_________\|__|     \|_______|\|_______|\|__| \|__|\___/ /             \|__|\|__|\|_______|\_________\|__|     \|_______|\|__| \|__|\_________\|_______|
   \|_________|                                       \|___|/                                 \|_________|                             \|_________|         
                                                                                                                                                            
                                                                                                                                                            '
    )
    Clear-Host
    Write-Host "$Title"
    Write-Host "Welcome to the 11:11 Systems incident response command line. All input and output will be logged for later reference.

    NOTE: This program will only read the requested data and will not perform any write operations.
    
    "
    Write-Host "Press '1' to collect run keys."
    Write-Host "Press '2' to get services."
    Write-Host "Press '3' to get running processes."
    Write-Host "Press '4' to get network connections."
    Write-Host "Press '5' to get scheduled tasks."
    Write-Host "Press '6' to get hosts file."
    Write-Host "Press '7' to get startup folder objects."
    Write-Host "Press 'q' to quit."
    Write-Host ""
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
        '1' {
            getRunKeys
        } '2' {
            getCurrentServices
        } '3' {
            getRunningProcesses
        } '4' {
            getNetworkConnections
        } '5' {
            getScheduledTasks
        } '6' {
            getHostsFile
        } '7' {
            getStartupObjects
        } 'q' {
            exit
        }
    }
}

do {
    Show-Menu
    pause
    }
until ($selection -eq 'q')

<#
getRunKeys
getCurrentServices
getRunningProcesses
getNetworkConnections
getScheduledTasks
getHostsFile
Show-Menu
#>

<#
Collect Windows logs for analysis.

function CollectLogs($ExportDirName)
{
    $logs = Get-EventLog -LogName * | Select-Object Log

    $categories = @()

    $logs | Foreach-Object { $category = $_.Log ; $categories += $category }

    $ExportDirName = $ExportDirName.ToString() 

    $categories | Foreach-Object {
                                    $category = $_

                                    New-Item -ItemType Directory -Path (Get-Location) -Name $category | Out-Null
                                 }
    
    $logs | Foreach-Object { 
                                $directory = $_.Log.ToString()

                                $curDir    = Get-Location ; $curDir = $curDir.Path+'\'+$directory

                                $events    = $directory+'.csv'

                                New-Item -ItemType File -Path $curDir -Name $events | Out-Null

                                $filePath = $curDir+'\'+$events

                                Write-Host -ForegroundColor Yellow "[*] Exporting: $directory "

                                try 
                                {
                                    Get-EventLog -LogName $_.Log -ErrorAction SilentlyContinue | Export-CSV -Path $filePath

                                    Write-Host -ForegroundColor Green "[*] Export complete: $directory "
                                }
                                catch 
                                {
                                    Write-Host -ForegroundColor Red "[!] Failed to export: $directory "
                                }
                           }

    Write-Host -ForegroundColor Green "[*] Windows Event Viewer Log Export Complete! " ; Start-Sleep -Seconds 3

}#>
