# Configuration Definition
Configuration CIS_setup_firewall {
   param (
       [string[]]$NodeName ='localhost'
       )


   Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
   Import-DscResource -ModuleName 'AuditPolicyDsc'
   Import-DscResource -ModuleName 'SecurityPolicyDsc'

   Node $NodeName {
       #Source: https://github.com/PowerShell/SecurityPolicyDsc
       SecurityOption AccountSecurityOptions {
         Name                                   = 'AccountSecurityOptions'

       #  9.1.1 (L1) Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'
       Registry 'EnableFirewallDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall'
           ValueName   = 'EnableFirewall'
           ValueType   = 'DWord'
           ValueData   = '1'
       }

       #  9.1.2 (L1) Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Allow (default)'
       Registry 'DefaultInboundActionDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction'
           ValueName   = 'DefaultInboundAction'
           ValueType   = 'DWord'
           ValueData   = '0'
       }

       #  9.1.3 (L1) Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'
       Registry 'DefaultOutboundActionDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
           ValueName   = 'DefaultOutboundAction'
           ValueType   = 'DWord'
           ValueData   = '0'
       }

       # 9.1.4 (L1) Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'
       Registry 'DisableNotificationsDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DisableNotifications'
           ValueName   = 'DisableNotifications'
           ValueType   = 'DWord'
           ValueData   = '0'
       }

       # 9.1.5 (L1) Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\domainfw.log'
       Registry 'LogFilePathDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFilePath'
           ValueName   = 'DisableNotifications'
           ValueType   = 'String'
           ValueData   = '%windir%\system32\logfiles\firewall\domainfirewall.log'
       }

       # 9.1.6 (L1) Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'
       Registry 'LogFileSizeDomain' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize'
           ValueName   = 'LogFileSize'
           ValueType   = 'DWord'
           ValueData   = '16384'
       }

       #  9.1.7 (L1) Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'
       Registry 'LogDroppedPacketsDomain' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets'
          ValueName    = 'LogDroppedPackets'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.1.8 (L1) Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'
       Registry 'LogSuccessfulConnectionsDomain' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections'
          ValueName    = 'LogSuccessfulConnections'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.2.1 (L1) Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'
       Registry 'EnableFirewallPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
          ValueName    = 'EnableFirewall'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.2.2 (L1) Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Allow (default)'
       Registry 'DefaultInboundActionPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
          ValueName    = 'DefaultInboundAction'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.2.3 (L1) Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'
       Registry 'DefaultOutboundActionPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
          ValueName    = 'DefaultOutboundAction'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.2.4 (L1) Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'
       Registry 'DisableNotificationsPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
          ValueName    = 'DisableNotifications'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.2.5 (L1) Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\privatefw.log'
       Registry 'LogFilePathPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
          ValueName    = 'LogFilePath'
          ValueType    = 'String'
          ValueData    = '%windir%\system32\logfiles\firewall\privatefirewall.log'
       }

       #  9.2.6 (L1) Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'
       Registry 'LogFileSizePrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
          ValueName    = 'LogFileSize'
          ValueType    = 'DWord'
          ValueData    = '16384'
       }

       #  9.2.7 (L1) Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'
       Registry 'LogDroppedPacketsPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
          ValueName    = 'LogDroppedPackets'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.2.8 (L1) Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'
       Registry 'LogSuccessfulConnectionsPrivate' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
          ValueName    = 'LogSuccessfulConnections'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.3.1 (L1) Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'
       Registry 'EnableFirewallPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'EnableFirewall'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.3.2 (L1) Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'
       Registry 'DefaultInboundActionPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'DefaultInboundAction'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.3.3 (L1) Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'
       Registry 'DefaultOutboundActionPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'DefaultOutboundAction'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.3.4 (L1) Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'
       Registry 'DisableNotificationsPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'DisableNotifications'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.3.5 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'
       Registry 'AllowLocalPolicyMerge' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'AllowLocalPolicyMerge'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.3.6 (L1) Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'
       Registry 'AllowLocalIPsecPolicyMerge' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
          ValueName    = 'AllowLocalIPsecPolicyMerge'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  9.3.7 (L1) Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SYSTEMROOT%\System32\logfiles\firewall\publicfw.log'
       Registry 'LogFilePathPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
          ValueName    = 'LogFilePath'
          ValueType    = 'String'
          ValueData    = '%windir%\system32\logfiles\firewall\publicfirewall.log'
       }

       #  9.3.8 (L1) Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'
       Registry 'LogFileSizePublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
          ValueName    = 'LogFileSize'
          ValueType    = 'Dword'
          ValueData    = '16384'
       }

       #  9.3.9 (L1) Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'
       Registry 'LogDroppedPacketsPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
          ValueName    = 'LogDroppedPackets'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  9.3.10 (L1) Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'
       Registry 'LogSuccessfulConnectionsPublic' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
          ValueName    = 'LogSuccessfulConnections'
          ValueType    = 'DWord'
          ValueData    = '1'
       }
 
       }

  }
}

CIS_setup_firewall
