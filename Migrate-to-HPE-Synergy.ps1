##############################################################################
# Migrate-to-HPE-Synergy.ps1
#
# - Script for helping migrate server profiles from C7000 to Synergy
#
#   VERSION 2.00
#
#   AUTHORS
#   Vikram Fernandes - HPE Global Solutions Engineering
#   Dave Olker       - HPE Global Solutions Engineering
#
# (C) Copyright 2019 Hewlett Packard Enterprise Development LP 
##############################################################################
<#
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
#>


function Collect_Data_from_C7000 {
    #
    # This function connects to an HP OneView v4.0 standalone appliance.
    # The v4.0 appliance acts as an intermediary between the C7000
    # enclosure managed by Virtual Connect and the target Synergy
    # composer.
    #
    # A v4.0 appliance is required because the underlying data model
    # in the migration report changed in v4.1 and forward.
    #

    #
    # Unload any versions of the HPOneView POSH modules
    #
    Remove-Module -ErrorAction SilentlyContinue HPOneView.120
    Remove-Module -ErrorAction SilentlyContinue HPOneView.200
    Remove-Module -ErrorAction SilentlyContinue HPOneView.300
    Remove-Module -ErrorAction SilentlyContinue HPOneView.310
    Remove-Module -ErrorAction SilentlyContinue HPOneView.400
    Remove-Module -ErrorAction SilentlyContinue HPOneView.410
    Remove-Module -ErrorAction SilentlyContinue HPOneView.420

    if (-not (Get-Module HPOneView.400)) {
        Import-Module HPOneView.400
    }

    if (-not $ConnectedSessions) {

        Connect-HPOVMgmt -Hostname $OneView_IP -Username $OneView_Username -Password $OneView_Password

        if (-not $ConnectedSessions) {
            Write-Output "Login to the OneView 4.0 Appliance failed.  Exiting."
            Exit
        } else {
            Import-HPOVSslCertificate
        }
    }

    #
    # Create C7000 structures used to collect a OneView migration report
    #
    $c7000Creds = @{
        oaIpAddress    = $C7000_oaIpAddress;
        oaUsername     = $C7000_oaUsername;
        oaPassword     = $C7000_oaPassword;
        vcmUsername    = $C7000_vcmUsername;
        vcmPassword    = $C7000_vcmPassword;
        type           = "EnclosureCredentials"
    }

    $c7000 = @{
        iloLicenseType = "OneView";
        credentials    = $c7000Creds;
        category       = "migratable-vc-domains";
        type           = "MigratableVcDomainV300"
    }

    $task = Send-HPOVRequest -uri "/rest/migratable-vc-domains" -body $c7000 -method POST
    $task | Wait-HPOVTaskComplete

    #
    # Pause to sync resources
    #
    Start-Sleep 10

    # This might return back after a few mins
    # We do not care about compatibility
    # Get the task URI for the associatedResource
    $initial_resp = Send-HPOVRequest -uri $task.uri

    #
    # Get the associated URI
    #
    $uri = $initial_resp.associatedResource.resourceUri
    $buildUri = $uri + "?view=detail"

    #
    # Contact the C7000 and gather information
    #
    $resp = Send-HPOVRequest -uri $buildUri -method GET

    #
    # Process the discovered Fibre Channel Networks
    #
    $FCFile = "FCNetworks.csv"
    New-Item -Path $FCFile -ItemType File -Force | Out-Null
    Clear-Content -Path $FCFile

    foreach ($FCnetwork in $resp.oneViewResourceCompatibility.fcNetworks.fcNetworks) {
        $FCnet_Name              = $FCnetwork.obj.name
        $FCnet_Type              = "Fibre Channel"
        $FCnet_fabricType        = $FCnetwork.obj.fabricType
        $FCnet_linkStabilityTime = $FCnetwork.obj.linkStabilityTime
        $FCnet_maximumBandwidth  = $FCnetwork.bandwidth.maximumBandwidth
        $FCnet_typicalBandwidth  = $FCnetwork.bandwidth.typicalBandwidth

        $FCArray = "$FCnet_Name,$FCnet_Type,$FCnet_fabricType,$FCnet_linkStabilityTime,$FCnet_maximumBandwidth,$FCnet_typicalBandwidth"

        if (-not [String]::IsNullOrEmpty($FCArray)) {
            Add-Content -Path $FCFile $FCArray
        }
    }

    #
    # Process the discovered Ethernet Networks
    #
    $EthFile = "EthernetNetworks.csv"
    New-Item -Path $EthFile -ItemType File -Force | Out-Null
    Clear-Content -Path $EthFile

    foreach ($EthNetwork in $resp.oneViewResourceCompatibility.networks.networks) {
        $EthNet_Name              = $EthNetwork.obj.name
        $EthNet_Type              = "Ethernet"
        $EthNet_Purpose           = $EthNetwork.obj.purpose
        $EthNet_vlanId            = $EthNetwork.obj.vlanId
        $EthNet_vlanType          = $EthNetwork.obj.ethernetNetworkType
        $EthNet_maximumBandwidth  = $EthNetwork.bandwidth.maximumBandwidth
        $EthNet_typicalBandwidth  = $EthNetwork.bandwidth.typicalBandwidth

        $EthArray = "$EthNet_Name,$EthNet_Type,$EthNet_Purpose,$EthNet_vlanId,$EthNet_vlanType,$EthNet_maximumBandwidth,$EthNet_typicalBandwidth"

        if (-not [String]::IsNullOrEmpty($EthArray)) {
            Add-Content -Path $EthFile $EthArray
        }
    }

    #
    # Process the discovered Server Profiles
    #
    foreach ($profile in $resp.oneViewResourceCompatibility.profiles.serverProfiles) {
        #
        # Make sure the enclosureBay is populated
        #
        if ([String]::IsNullOrEmpty($profile.obj.enclosureBay)) {
            continue
        }

        #
        # Make sure this is a ProLiant Blade
        #
        $ServerType = $resp.servers[($profile.obj.enclosureBay - 1)].name
        if ($ServerType -notmatch "ProLiant") {
            continue
        }

        $ServerName = $profile.obj.name
        $SvrProfileFile = "@$ServerName@.txt"
        New-Item -Path $SvrProfileFile -ItemType File -Force | Out-Null
        Clear-Content -Path $SvrProfileFile

        $NumEth  = 1
        $NumFC   = 1
        $NumConn = 1
        foreach ($connection in $profile.obj.connections) {
            if ([String]::IsNullOrEmpty($connection)) {
                continue
            }
            if ($connection.functionType -eq "Ethernet") {
                $Conn_networkName = $profile.singleNetworkAssociatedToConnection.($connection.id)

                #
                # If this connection is not plumbed to a network then skip it
                #
                if (-not [String]::IsNullOrEmpty($Conn_networkName)) {
                    $Conn_functionType                           = $connection.functionType
                    $Conn_macType                                = $connection.macType
                    $Conn_mac                                    = $connection.mac
                    $Conn_portId                                 = $connection.portId
                    $Conn_requestedMbps                          = $connection.requestedMbps

                    $EthArray = @()
                    $EthArray += "Eth$NumEth-ConnectionID        = $NumConn"
                    $EthArray += "Eth$NumEth-networkName         = $Conn_networkName"
                    $EthArray += "Eth$NumEth-functionType        = $Conn_functionType"
                    $EthArray += "Eth$NumEth-macType             = $Conn_macType"
                    $EthArray += "Eth$NumEth-macAddr             = $Conn_mac"
                    $EthArray += "Eth$NumEth-portId              = $Conn_portId"
                    $EthArray += "Eth$NumEth-requestedMbps       = $Conn_requestedMbps"

                    Add-Content -Path $SvrProfileFile -Value $EthArray

                    $NumEth++
                    $NumConn++
                }
            }

            if ($connection.functionType -eq "FibreChannel") {
                $Conn_networkName = $profile.singleNetworkAssociatedToConnection.($connection.id)

                #
                # If this connection is not plumbed to a network then skip it
                #
                if (-not [String]::IsNullOrEmpty($Conn_networkName)) {
                    $Conn_functionType                         = $connection.functionType
                    $Conn_wwpnType                             = $connection.wwpnType
                    $Conn_wwnn                                 = $connection.wwnn
                    $Conn_wwpn                                 = $connection.wwpn
                    $Conn_requestedMbps                        = $connection.requestedMbps
                    $Conn_bootPriority                         = $connection.boot.priority
                    $Conn_bootTargetsArrayWwpn                 = $connection.boot.targets.arrayWwpn
                    $Conn_bootTargetsLun                       = $connection.boot.targets.lun
                    $Conn_portId                               = $connection.portId

                    $FCArray = @()
                    $FCArray += "FC$NumFC-ConnectionID         = $NumConn"
                    $FCArray += "FC$NumFC-networkName          = $Conn_networkName"
                    $FCArray += "FC$NumFC-functionType         = $Conn_functionType"
                    $FCArray += "FC$NumFC-wwpnType             = $Conn_wwpnType"
                    $FCArray += "FC$NumFC-wwnn                 = $Conn_wwnn"
                    $FCArray += "FC$NumFC-wwpn                 = $Conn_wwpn"
                    $FCArray += "FC$NumFC-requestedMbps        = $Conn_requestedMbps"
                    $FCArray += "FC$NumFC-bootPriority         = $Conn_bootPriority"
                    $FCArray += "FC$NumFC-bootTargetsArrayWwpn = $Conn_bootTargetsArrayWwpn"
                    $FCArray += "FC$NumFC-bootTargetsLun       = $Conn_bootTargetsLun"
                    $FCArray += "FC$NumFC-portId               = $Conn_portId"

                    Add-Content -Path $SvrProfileFile -Value $FCArray

                    $NumFC++
                    $NumConn++
                }
            }
        }
    }

    #
    # Disconnect from intermediary OneView v4.0 appliance
    # and unload the HPOneView.400 library.
    #
    Disconnect-HPOVMgmt
    Remove-Module HPOneView.400
}


function Create_Synergy_Server_Profiles {
    #
    # Load the OneView v4.2 library and connect to the Synergy
    # Composer where the server profiles will be created.
    #

    #
    # Unload any versions of the HPOneView POSH modules
    #
    Remove-Module -ErrorAction SilentlyContinue HPOneView.120
    Remove-Module -ErrorAction SilentlyContinue HPOneView.200
    Remove-Module -ErrorAction SilentlyContinue HPOneView.300
    Remove-Module -ErrorAction SilentlyContinue HPOneView.310
    Remove-Module -ErrorAction SilentlyContinue HPOneView.400
    Remove-Module -ErrorAction SilentlyContinue HPOneView.410

    if (-not (Get-Module HPOneView.420)) {
        Import-Module HPOneView.420
    }

    if (-not $ConnectedSessions) {

        Connect-HPOVMgmt -Hostname $Synergy_ComposerIP -Username $Synergy_Username -Password $Synergy_Password

        if (-not $ConnectedSessions) {
            Write-Output "Login to the Synergy Composer failed.  Exiting."
            Exit
        } else {
            Import-HPOVSslCertificate
        }
    }

    #
    # Create new server profiles using the information from the C7000
    #
    foreach ($ServerProfile in Get-ChildItem -Path "@*@.txt") {
        #
        # Process the contents of the Server Profile Configuration
        #
        # Each line contains a variable name and a corresponding value
        # Need to substitute "-" with "_" in the variable name to make
        # PowerShell treat it as a valid variable name
        #
        if (Test-Path $ServerProfile) {
            Get-Content $ServerProfile | Where-Object { !$_.StartsWith("#") } | Foreach-Object {
                $var = $_.Split('=')
                New-Variable -Name $var[0].Replace("-", "_").Trim() -Value $var[1].Trim() -Force
            }
        } else {
            Write-Output "Server Profile file '$ServerProfile' not found.  Exiting."
            Exit
        }

        #
        # Add connections to the array as they are created
        #
        $ConnectionArray           = @()

        #
        # Create Ethernet Connections
        #
        if (Get-Variable -Name Eth1_networkName -ErrorAction SilentlyContinue) {
            #
            # Override Parameters from the Collected Profile
            #
            if (-not [String]::IsNullOrEmpty($Eth1_networkName_Override)) {
                Set-Variable -Name Eth1_networkName -Value $Eth1_networkName_Override
            }
            if (-not [String]::IsNullOrEmpty($Eth1_portId_Override)) {
                Set-Variable -Name Eth1_portId -Value $Eth1_portId_Override
            }
            if (-not [String]::IsNullOrEmpty($Eth1_requestedMbps_Override)) {
                Set-Variable -Name Eth1_requestedMbps -Value $Eth1_requestedMbps_Override
            }
                        
            $Eth1_OVNetwork        = Get-HPOVNetwork -Name $Eth1_networkName -ErrorAction Stop
            $Eth1params = @{
                ConnectionID       = $Eth1_ConnectionID;
                ConnectionType     = $Eth1_functionType;
                Name               = $Eth1_networkName;
                Network            = $Eth1_OVNetwork;
                PortId             = $Eth1_portId;
                RequestedBW        = $Eth1_requestedMbps;
            }
            $Eth1_Conn             = New-HPOVServerProfileConnection @Eth1params
            $Eth1_Conn.macType     = $Eth1_macType
            $Eth1_Conn.mac         = $Eth1_macAddr

            $ConnectionArray       += $Eth1_Conn
        }

        if (Get-Variable -Name Eth2_networkName -ErrorAction SilentlyContinue) {
            #
            # Override Parameters from the Collected Profile
            #
            if (-not [String]::IsNullOrEmpty($Eth2_networkName_Override)) {
                Set-Variable -Name Eth2_networkName -Value $Eth2_networkName_Override    
            }
            if (-not [String]::IsNullOrEmpty($Eth2_portId_Override)) {
                Set-Variable -Name Eth2_portId -Value $Eth2_portId_Override    
            }
            if (-not [String]::IsNullOrEmpty($Eth2_requestedMbps_Override)) {
                Set-Variable -Name Eth2_requestedMbps -Value $Eth2_requestedMbps_Override
            }
            
            $Eth2_OVNetwork        = Get-HPOVNetwork -Name $Eth2_networkName -ErrorAction Stop
            $Eth2params = @{
                ConnectionID       = $Eth2_ConnectionID;
                ConnectionType     = $Eth2_functionType;
                Name               = $Eth2_networkName;
                Network            = $Eth2_OVNetwork;
                PortId             = $Eth2_portId;
                RequestedBW        = $Eth2_requestedMbps;
            }
            $Eth2_Conn             = New-HPOVServerProfileConnection @Eth2params
            $Eth2_Conn.macType     = $Eth2_macType
            $Eth2_Conn.mac         = $Eth2_macAddr

            $ConnectionArray       += $Eth2_Conn
        }

        if (Get-Variable -Name Eth3_networkName -ErrorAction SilentlyContinue) {
            #
            # Override Parameters from the Collected Profile
            #
            if (-not [String]::IsNullOrEmpty($Eth3_networkName_Override)) {
                Set-Variable -Name Eth3_networkName -Value $Eth3_networkName_Override
            }
            if (-not [String]::IsNullOrEmpty($Eth3_portId_Override)) {
                Set-Variable -Name Eth3_portId -Value $Eth3_portId_Override
            }
            if (-not [String]::IsNullOrEmpty($Eth3_requestedMbps_Override)) {
                Set-Variable -Name Eth3_requestedMbps -Value $Eth3_requestedMbps_Override
            }
                        
            $Eth3_OVNetwork        = Get-HPOVNetwork -Name $Eth3_networkName -ErrorAction Stop
            $Eth3params = @{
                ConnectionID       = $Eth3_ConnectionID;
                ConnectionType     = $Eth3_functionType;
                Name               = $Eth3_networkName;
                Network            = $Eth3_OVNetwork;
                PortId             = $Eth3_portId;
                RequestedBW        = $Eth3_requestedMbps;
            }
            $Eth3_Conn             = New-HPOVServerProfileConnection @Eth3params
            $Eth3_Conn.macType     = $Eth3_macType
            $Eth3_Conn.mac         = $Eth3_macAddr

            $ConnectionArray       += $Eth3_Conn
        }

        if (Get-Variable -Name Eth4_networkName -ErrorAction SilentlyContinue) {
            #
            # Override Parameters from the Collected Profile
            #
            if (-not [String]::IsNullOrEmpty($Eth4_networkName_Override)) {
                Set-Variable -Name Eth4_networkName -Value $Eth4_networkName_Override
            }
            if (-not [String]::IsNullOrEmpty($Eth4_portId_Override)) {
                Set-Variable -Name Eth4_portId -Value $Eth4_portId_Override
            }
            if (-not [String]::IsNullOrEmpty($Eth4_requestedMbps_Override)) {
                Set-Variable -Name Eth4_requestedMbps -Value $Eth4_requestedMbps_Override
            }
                        
            $Eth4_OVNetwork        = Get-HPOVNetwork -Name $Eth4_networkName -ErrorAction Stop
            $Eth4params = @{
                ConnectionID       = $Eth4_ConnectionID;
                ConnectionType     = $Eth4_functionType;
                Name               = $Eth4_networkName;
                Network            = $Eth4_OVNetwork;
                PortId             = $Eth4_portId;
                RequestedBW        = $Eth4_requestedMbps;
            }
            $Eth4_Conn             = New-HPOVServerProfileConnection @Eth4params
            $Eth4_Conn.macType     = $Eth4_macType
            $Eth4_Conn.mac         = $Eth4_macAddr

            $ConnectionArray       += $Eth4_Conn
        }
    
        #
        # Create Fibre Channel Connections
        #
        if (Get-Variable -Name FC1_networkName -ErrorAction SilentlyContinue) {
            #
            # Override Parameters from the Collected Profile
            #
            if (-not [String]::IsNullOrEmpty($FC1_networkName_Override)) {
                Set-Variable -Name FC1_networkName -Value $FC1_networkName_Override
            }
            if (-not [String]::IsNullOrEmpty($FC1_portId_Override)) {
                Set-Variable -Name FC1_portId -Value $FC1_portId_Override
            }
            if (-not [String]::IsNullOrEmpty($FC1_requestedMbps_Override)) {
                Set-Variable -Name FC1_requestedMbps -Value $FC1_requestedMbps_Override
            }
            
            $FC1_OVNetwork         = Get-HPOVNetwork -Name $FC1_networkName -ErrorAction Stop
            $FC1params = @{
                Bootable           = $True;
                BootVolumeSource   = "UserDefined";
                ConnectionID       = $FC1_ConnectionID;
                ConnectionType     = $FC1_functionType;
                LUN                = $FC1_bootTargetsLun;
                Name               = $FC1_networkName;
                Network            = $FC1_OVNetwork;
                PortId             = $FC1_portId;
                Priority           = $FC1_bootPriority;
                RequestedBW        = $FC1_requestedMbps;
                TargetWwpn         = $FC1_bootTargetsArrayWwpn;
            }
            $FC1_Conn              = New-HPOVServerProfileConnection @FC1params
            $FC1_Conn.wwpnType     = $FC1_wwpnType
            $FC1_Conn.wwpn         = $FC1_wwpn
            $FC1_Conn.wwnn         = $FC1_wwnn

            $ConnectionArray       += $FC1_Conn
        }

        if (Get-Variable -Name FC2_networkName -ErrorAction SilentlyContinue) {
            #
            # Override Parameters from the Collected Profile
            #
            if (-not [String]::IsNullOrEmpty($FC2_networkName_Override)) {
                Set-Variable -Name FC2_networkName -Value $FC2_networkName_Override
            }
            if (-not [String]::IsNullOrEmpty($FC2_portId_Override)) {
                Set-Variable -Name FC2_portId -Value $FC2_portId_Override
            }
            if (-not [String]::IsNullOrEmpty($FC2_requestedMbps_Override)) {
                Set-Variable -Name FC2_requestedMbps -Value $FC2_requestedMbps_Override
            }

            $FC2_OVNetwork         = Get-HPOVNetwork -Name $FC2_networkName -ErrorAction Stop
            $FC2params = @{
                Bootable           = $True;
                BootVolumeSource   = "UserDefined";
                ConnectionID       = $FC2_ConnectionID;
                ConnectionType     = $FC2_functionType;
                LUN                = $FC2_bootTargetsLun;
                Name               = $FC2_networkName;
                Network            = $FC2_OVNetwork;
                PortId             = $FC2_portId;
                Priority           = $FC2_bootPriority;
                RequestedBW        = $FC2_requestedMbps;
                TargetWwpn         = $FC2_bootTargetsArrayWwpn;
            }
            $FC2_Conn              = New-HPOVServerProfileConnection @FC2params
            $FC2_Conn.wwpnType     = $FC2_wwpnType
            $FC2_Conn.wwpn         = $FC2_wwpn
            $FC2_Conn.wwnn         = $FC2_wwnn

            $ConnectionArray       += $FC2_Conn
        }
        
        #
        # Identify a server blade with no profile associated
        #
        $ServerProfileName     = $ServerProfile.Name.Split('@')[1]
        $SHT                   = Get-HPOVServerHardwareTypes -Name "$Synergy_Server_Hardware_Type" -ErrorAction Stop
        $EnclGroup             = Get-HPOVEnclosureGroup -Name $Synergy_Enclosure_Group -ErrorAction Stop
        $ServerBlade           = Get-HPOVServer -ServerHardwareType $SHT -NoProfile -ErrorAction Stop | Select-Object -First 1
        
        if ($Synergy_Server_Hardware_Type -match "Gen9") {
            $params = @{
                AssignmentType     = "Server";
                Affinity           = "Bay";
                Bootmode           = "UEFIOptimized";
                BootOrder          = "HardDisk";
                Connections        = $ConnectionArray;
                Description        = "HPE Synergy compute module configured with imported profile";
                EnclosureGroup     = $EnclGroup;
                HideUnusedFlexNics = $True;
                LocalStorage       = $False;
                ManageBoot         = $True;
                Name               = $ServerProfileName;
                Server             = $ServerBlade;
            }
        } else {
            $params = @{
                AssignmentType     = "Server";
                Affinity           = "Bay";
                BootOrder          = "HardDisk";
                Connections        = $ConnectionArray;
                Description        = "HPE Synergy compute module configured with imported profile";
                EnclosureGroup     = $EnclGroup;
                HideUnusedFlexNics = $True;
                LocalStorage       = $False;
                ManageBoot         = $True;
                Name               = $ServerProfileName;
                Server             = $ServerBlade;
            }
        }

        #
        # Create the new server profile
        #
        New-HPOVServerProfile @params | Wait-HPOVTaskComplete

        #
        # Power on the server blade
        #
        if ($Synergy_Power_On_Server -eq "True") {
            Start-HPOVServer -Server $ServerBlade | Wait-HPOVTaskComplete
        }
    }
}


##########################################################################
#
# Process variables in the Migrate-to-HPE-Synergy.conf file
#
##########################################################################
New-Variable -Name config_file -Value .\Migrate-to-HPE-Synergy.conf -Force

if (Test-Path $config_file) {
    Get-Content $config_file | Where-Object { !$_.StartsWith("#") -and $_ -ne "" } | Foreach-Object {
        $var = $_.Split('=')
        New-Variable -Name $var[0].Trim() -Value $var[1].Trim().Replace("`"","") -Scope Global -Force
    }
} else {
    Write-Output "Configuration file '$config_file' not found.  Exiting."
    Exit
}


#############################################################################
#
# Function Calls
#
##############################################################################
#Collect_Data_from_C7000
Create_Synergy_Server_Profiles
