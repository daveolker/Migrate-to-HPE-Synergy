# Migrate-to-HPE-Synergy

The Migrate-to-HPE-Synergy tool is designed to help Hewlett Packard Enterprise Solution Architects and customers easily migrate their existing ProLiant blade servers from a C7000 environment managed by Virtual Connect to a new HPE Synergy environment.

The primary use case for this tool is to automate the creation of HPE Synergy Server Profiles with the virtual MAC addresses and virtual Fibre Channel WWNN/WWPN IDs used by the existing ProLiant blades when booting from SAN.

## How to use the tool
The Migrate-to-HPE-Synergy tool consists of a PowerShell script and a configuration file. The PowerShell script leverages version 4 of the HPE OneView PowerShell library found here: https://github.com/HewlettPackard/POSH-HPOneView. It is strongly recommended to use the latest version of the PowerShell library to take advantage of the latest features, new OneView/Synergy capabilities, and defect fixes.

This tool requires a standalone OneView version 4.00 appliance deployed in the environment.  This standalone appliance acts as an intermediary between the Virtual Connect (VC) managed C7000 enclosure and the target Synergy Composer.  The v4.0 appliance can be "empty", meaning it does not need any resources configured in the appliance such as networks, server profiles, etc.

## Background

This tool was developed in response to a customer request to help them migrate their legacy ProLiant blade environment to a new HPE Synergy environment as quickly and easily as possible.  The customer's ProLiant blades were configured to boot from SAN and the idea was to create Server Profiles on the Synergy system with the same FC WWNNs/WWPNs and boot LUN information.  In doing so, the customer would not have to touch the storage systems or change the FC switch zoning rules to allow the new Synergy compute modules to boot from the existing boot disks.

## Caveats

In this initial release of the Migrate-to-HPE-Synergy tool, there are several conditions that must be present in both the existing C7000 environment and the replacement Synergy environment for the tool to work correctly.

 - Both environments must be physically cabled to the same Fibre Channel infrastructure (i.e. fabric switches and storage arrays) and the same physical networking infrastructure.
 - Both environments must be configured with matching Virtual MAC and Virtual FC WWN pools, and the C7000 blades must be using these virtual addresses as part of their Virtual Connect server profiles.
 - The "FC HBA Connections" section of the Virtual Connect server profiles must contain the Primary and Secondary Target Port Name and LUN number of the SAN-based boot disk.
 - The boot disk's Operating System must be configured with any drivers required for both the C7000 blades and Synergy compute modules.  This would include drivers for:
	 - Ethernet adapters
	 - Fibre Channel adapters
	 - Storage adapters
	 - Storage devices
	 - Any other mezzanine cards installed in the Synergy compute modules
 - Currently only the first two Ethernet and Fibre Channel connections in the server profile will be migrated.  This could be extended in future versions of the tool based on user demand.

The Migrate-to-HPE-Synergy tool was initially tested using a recent HPE custom ESXi image installed on the C7000 blades.  This custom image contains all drivers for both the BL460c Gen9 source blades and the target Synergy compute modules.

It may be possible to use this tool in Microsoft Windows or Linux environments provided the necessary Synergy drivers are injected in the OS image prior to migration.  These use cases have not yet been tested.

## Configuration Parameters

The parameters used to configure the Migrate-to-HPE-Synergy tool are contained in the **Migrate-to-HPE-Synergy.conf** file.  A sample of this file is provided in the **Migrate-to-HPE-Synergy.conf.SAMPLE** file.  This file must be renamed to **Migrate-to-HPE-Synergy.conf** prior to running the tool.  The configurable parameters include:

    C7000_oaIpAddress		(IP Address of the C7000 Onboard Administrator)
    C7000_oaUsername		(Username used to log into C7000 Onboard Administrator)
    C7000_oaPassword		(Password used to log into C7000 Onboard Administrator)
    C7000_vcmUsername		(Username used to log into C7000 Virtual Connect Manager)
    C7000_vcmPassword		(Password used to log into C7000 Virtual Connect Manager)

    OneView_IP			(IP Address of the standalone OneView v4.0 Appliance)
    OneView_Username		(Username used to log into the OneView v4.0 Appliance)
    OneView_Password		(Password used to log into the OneView v4.0 Appliance)

    Synergy_ComposerIP		(IP Address of Synergy Composer)
    Synergy_Username		(Username used to log into Synergy Composer)
    Synergy_Password		(Password used to log into Synergy Composer)
    Synergy_Enclosure_Group		(Enclosure Group housing target Synergy Compute Modules)
    Synergy_Server_Hardware_Type	(Server Hardware Type of target Synergy Compute Modules)
    Synergy_Power_On_Server		(Power on the Synergy Compute Module after the Profile is applied?  Values: True or False)

### Override Parameters
The Migrate-to-HPE-Synergy.conf file also includes a number of "override" parameters.  These are used in the case where the names of Ethernet or Fibre Channel networks do not match between the C7000 and Synergy environments, or where the PortID of the Ethernet or Fibre Channel adapters differs between C7000 and Synergy environments, or when the requested bandwidth values in the C7000 VC server profile need to be adjusted when creating the Synergy Server Profiles.

    Eth1_networkName_Override	(Name of Ethernet Network for Primary Ethernet connection on HPE Synergy)
    Eth1_portId_Override		(PortId used to map to Primary Ethernet connection on HPE Synergy - i.e. "Flb 2:1a" or "Mezz 5:1-a")
    Eth1_requestedMbps_Override	(Requested Bandwidth - i.e. 10000)
    Eth2_networkName_Override	(Same for Secondary Ethernet connection)
    Eth2_portId_Override		(Same for Secondary Ethernet connection)
    Eth2_requestedMbps_Override	(Same for Secondary Ethernet connection)
    FC1_networkName_Override	(Name of FC network for Primary FC connection on HPE Synergy)
    FC1_portId_Override		(PortId used to map Primary FC connection on HPE Synergy)
    FC1_requestedMbps_Override	(Requested Bandwidth - i.e. 8000 or 16000)
    FC2_networkName_Override	(Same for Secondary FC connection)
    FC2_portId_Override		(Same for Secondary FC connection)
    FC2_requestedMbps_Override	(Same for Secondary FC connection)

## Recommendations
As this process involves migrating between physical platforms, a scheduled maintenance window will be needed to physically power off the existing ProLiant blades and power on the new Synergy compute modules.  

Since the new Synergy Server Profiles will be using the identical virtual MAC/WWPN/WWNN addresses used by the existing ProLiant blades, the **strong recommendation** is to *cleanly shutdown the Operating System and power off the ProLiant blades* prior to running the tool.

The tool does not require the ProLiant blades to be running to gather the information needed to create the Synergy Server Profiles.  Also, the Synergy compute modules must be powered off in order to apply the newly created Server Profiles.

In the event that the customer wishes to create and apply the new Synergy Server Profiles while the existing ProLiant blades are running and schedule a later date to perform the actual migration, be sure to configure the **Synergy_Power_On_Server** parameter to **False** so that the compute modules will remain powered off after the new profiles are applied.
