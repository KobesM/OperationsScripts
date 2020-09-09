function Write-Log 
{
    param (
        [string]$systemName,
        [string]$message
    )

    Write-Output "[$(Get-Date -format T)] - [$systemName]::$($message)"
}

function Confirm-Path
{
    param (
        [string] $Location
    )

    if (!(Test-Path $Location)) {
        Write-Log -systemName Host -message "The path does not exist - Creating path: $($Location)"
        $null = New-Item -Type Directory -Path $Location
    } else {
        Write-Log -systemName Host -message "The path $($Location) does exist"
    }
}

function Confirm-File
{
    param (
        [string] $FileLocation
    )

    if (!(Test-Path $FileLocation -PathType Leaf)) {
        Write-Log -systemName Host -message "The iten does not exist at the provided location: $($FileLocation)"
        Write-Warning -Message "Item does not exist stopping script!"
        break
    } else {
        Write-Log -systemName Host -message "The item $($FileLocation) does exist"
    }
}

function Clear-File
{
    param (
        [string] $file
    )
    
    if (Test-Path $file) {
        Write-Log -systemName Host -message "Removing file: $($file)"
        $null = Remove-Item $file -Recurse -Force
    }
}

function Get-UnattendChunk 
{
    param (
        [string] $pass, 
        [string] $component, 
        [xml] $unattendfile
    )
    
    $unattendfile.unattend.settings | Where-Object -Property pass -EQ -Value $pass | Select-Object -ExpandProperty component | Where-Object -Property name -EQ -Value $component
}

function New-UnattendFile 
{
    param (
        [string] $filePath,
        [string] $WindowsKey,
        [string] $RegisteredOrganization = $HyperLabRegisteredOrganization,
        [string] $RegisteredOwner = $HyperLabRegisteredOwner,
        [string] $Timezone = $HyperLabTimezone,
        [string] $adminPassword = $HyperLabAdminPassword,
        [string]$unattendsource = $UnnatendSourceLocation
    )

    [xml]$unattend = Get-Content -Path $unattendsource
    Get-UnattendChunk -pass 'specialize' -component 'Microsoft-Windows-Shell-Setup' -unattendfile $unattend | ForEach-Object -Process {
        $_.RegisteredOrganization = $RegisteredOrganization
        $_.RegisteredOwner = $RegisteredOwner
        $_.TimeZone = $Timezone
        $_.ProductKey = $WindowsKey
    }

    Get-UnattendChunk 'oobeSystem' 'Microsoft-Windows-Shell-Setup' $unattend | ForEach-Object -Process {
        $_.UserAccounts.AdministratorPassword.Value = $adminPassword
    }

    Clear-File $filePath
    $unattend.Save($filePath)
}

Function Initialize-BaseImage 
{
    param (
        [parameter(Mandatory=$true)][string] $BaseImageName,
        [parameter(Mandatory=$true)][string] $BaseISO,
        [parameter(Mandatory=$true)][string] $Edition,
        [parameter(Mandatory=$true)][string] $WindowsKey,
        [string] $VHDPath = $BaseVHDPath,
        [string] $RegisteredOrganization = $HyperLabRegisteredOrganization,
        [string] $RegisteredOwner = $HyperLabRegisteredOwner,
        [string] $Timezone = $HyperLabTimezone,
        [string] $adminPassword = $HyperLabAdminPassword
    )

    if (!(Test-Path -Path "$($VHDPath)\$BaseImageName.vhdx")) {
        Write-Log -systemName Host -message "The baseimage does not exist - Creating baseimage: $($BaseImageName)"

        $null = Mount-DiskImage $BaseISO
        $DVDDriveLetter = (Get-DiskImage $BaseISO | Get-Volume).DriveLetter

        New-UnattendFile -filePath "$VHDPath\unattend.xml" -WindowsKey $WindowsKey -unattendsource $UnnatendSourceLocation
        
        Convert-WindowsImage -SourcePath "$($DVDDriveLetter):\sources\install.wim" -VhdPath "$($VHDPath)\$($BaseImageName).vhdx" `
        -SizeBytes 90GB -VHDFormat VHDX -UnattendPath "$($VHDPath)\unattend.xml" -Edition $Edition -VHDPartitionStyle GPT 

        Clear-File "$($VHDPath)\unattend.xml"
        $null = Dismount-DiskImage $BaseISO
    } else {
        Write-Log -systemName Host -message "The baseimage does already exist - Skipping creating baseimage: $($BaseImageName)"
    } 
}


function New-LabVM
{
    param (
        [parameter(Mandatory=$true)][string] $VMName, 
        [parameter(Mandatory=$true)][string] $GuestOSName,
        [parameter(Mandatory=$true)][string] $BaseImageName,
        [parameter(Mandatory=$true)][int] $MemoryStartupBytes,
        [parameter(Mandatory=$true)][int] $ProcessorCount,
        [switch] $RemoveExistingVM,
        [switch] $DynamicMemoryEnabled
    ) 

    $CreateNewVM = $true
    $VM = Get-VM $VMName -ErrorAction SilentlyContinue

    if (-not ([string]::IsNullOrEmpty($VM))) {
        if ($RemoveExistingVM) {
            $VM = Get-VM $VMName -ErrorAction SilentlyContinue
            if (-not ([string]::IsNullOrEmpty($VM))) {
                Write-Log $VMName "The VM: $($VMName) already exists - Deleting VM"
                $VM | Stop-VM -TurnOff -Force -Passthru -WarningAction SilentlyContinue | Remove-VM -Force
                Clear-File "$($VMPath)\$($VMName)\$($VMName).vhdx"
                $CreateNewVM = $true
            }
        } else {
            Write-Log $VMName "The VM: $($VMName) already exists - Skipping creationprocess"
            $CreateNewVM = $false
        }
    }

    if ($CreateNewVM) {
        Write-Log $VMName "Checking if full path for the VM's data does exist"
        Confirm-Path "$($VMPath)\$($VMName)"

        Write-Log $VMName "Creating Disk for new VM based on the baseimage $($BaseImageName)"
        Copy-Item -Path "$($BaseVHDPath)\$($BaseImageName).vhdx" -Destination "$($VMPath)\$($VMName)\$($VMName).vhdx"

        Write-Log $VMName 'Creating virtual machine'
        New-VM -Name $VMName -MemoryStartupBytes $MemoryStartupBytes -Generation 2 -Path "$($VMPath)\$($VMName)\" | Set-VM -ProcessorCount $ProcessorCount
        
        if ($DynamicMemoryEnabled) {
            Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $true
        } else {
            Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $false
        }

        Add-VMHardDiskDrive -VMName $VMName -Path "$($VMPath)\$($VMName)\$($VMName).vhdx" -ControllerType SCSI
        Enable-VMIntegrationService -Name 'Guest Service Interface' -VMName $VMName
    }
    
    Write-Log $VMName 'Starting virtual machine'
    Start-VM $VMName
}

function Wait-PSDirect
{
    param (
        [string]$VMName,
        [Object]$cred
    )

    Write-Log $VMName "Waiting for PowerShell Direct (using $($cred.username))"
    while ((Invoke-Command -VMName $VMName -Credential $cred {'Test'} -ea SilentlyContinue) -ne 'Test') {Start-Sleep -Seconds 1}
}


#region scriptparameters
$WorkingDir = "C:\HyperLab"
$HyperLabRegisteredOwner = "HyperLab"
$HyperLabRegisteredOrganization = "HyperLab Corp"
$HyperLabTimezone = 'W. Europe Standard Time'
$HyperLabAdminPassword = 'Pa$$w0rd'
#endregion

#region import modules
Install-Module -Name Convert-WindowsImage
#endregion

#region variables
$BaseVHDPath = "$WorkingDir\BaseVHD"
$VMPath = "$WorkingDir\VMs"
$ISODir = "$WorkingDir\ISO"
$UnnatendSourceLocation = "$WorkingDir\unnatendsource.xml"

$WS2019ISOPath = "$ISODir\SW_DVD9_Win_Server_STD_CORE_2019_1909.4_64Bit_English_DC_STD_MLF_X22-29333.iso"

#The following keys are KMS client setup keys - Replace this by your own valid Keys! (https://docs.microsoft.com/en-us/windows-server/get-started/kmsclientkeys)
$WS2019SEKey = "N69G4-B89J2-4G8F4-WWYCC-J464C" 
$WS2019DCKey = "WMDGN-G9PQG-XVVXX-R3X43-63DFG"
#endregion

#region Confirm if paths exist
Confirm-Path -Location $BaseVHDPath
Confirm-Path -Location $VMPath
Confirm-Path -Location $ISODir
#endregion

#region Confirm if File exist
Confirm-File -FileLocation $WS2019ISOPath
#endregion

#regio Copy the source unnatendfile to the workdir
Write-Log -systemName Localsystem -message "Copying the source unnatendfile to the WorkingDir: $($WorkingDir)"
Copy-Item -Path .\unnatendsource.xml -Destination "$($UnnatendSourceLocation)"
#endregion

#Creating BaseImages
Initialize-BaseImage -BaseImageName WS2019SEGUI -BaseISO $WS2019ISOPath -Edition "Windows Server 2019 Standard (Desktop Experience)" -WindowsKey $WS2019SEKey
Initialize-BaseImage -BaseImageName WS2019SECore -BaseISO $WS2019ISOPath -Edition "Windows Server 2019 Standard" -WindowsKey $WS2019SEKey
Initialize-BaseImage -BaseImageName WS2019DCGUI -BaseISO $WS2019ISOPath -Edition "Windows Server 2019 Datacenter (Desktop Experience)" -WindowsKey $WS2019DCKey
Initialize-BaseImage -BaseImageName WS2019DCCore -BaseISO $WS2019ISOPath -Edition "Windows Server 2019 Datacenter" -WindowsKey $WS2019DCKey

#Update BaseImages

#Setting Labcredentials
$HyperLabAdminCredentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList 'Administrator', (ConvertTo-SecureString -String $HyperLabAdminPassword -AsPlainText -Force)

#Deploy Lab VMs
New-LabVM -VMName HyperLab-DC01 -GuestOSName DC01 -BaseImageName 'WS2019SECore' -MemoryStartupBytes 512MB -ProcessorCount 2