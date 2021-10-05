#Configuration Definition
Configuration CIS_Add_Edge_Findings {

   # ADR Note: this configuration must be added to the existing core configuration
   # ADR Note: or it will likely undo another
   # ADR Note: tested on DSVM in AAE
   # ADR Note: Admin can log in remotely and work after applying
   # ADR Note: Users (as remote desktop users group members) can log in remotely and work after applying
   # ADR Note: Azure run command works via portal after applying
   # ADR Note: To Install, put the amended DSC code somewhere and run it - see above for inclusion in existing config
   # ADR Note: .\CIS_Add_Edge_Findings.ps1
   # ADR Note: Start-DscConfiguration -Path .\CIS_Add_Edge_Findings\  -Force -Verbose -Wait *> .\CIS_Add_Edge_Findings.log

   param (
       [string[]]$NodeName ='localhost'
       )


   Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
   Import-DscResource -ModuleName 'AuditPolicyDsc'
   Import-DscResource -ModuleName 'SecurityPolicyDsc'


   Node $NodeName {
    #Source: https://github.com/PowerShell/SecurityPolicyDsc/blob/dev/Examples/Resources/AccountPolicy/1-AccountPolicy_Config.ps1

       #  2.2.2 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS' (DC only)
       UserRightsAssignment Accessthiscomputerfromthenetwork {
          Policy       = 'Access_this_computer_from_the_network'
          Identity     = 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS'
       }

      #  2.2.21 (L1) Ensure 'Deny access to this computer from the network' is set to 'Guests, Local account and member of Administrators group' (MS only)
       UserRightsAssignment Denyaccesstothiscomputerfromthenetwork {
          Policy       = 'Deny_access_to_this_computer_from_the_network'
          Identity     = 'Guests, Local account, Administrators'
       }

      # 2.2.25 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests' (DC only)
       UserRightsAssignment DenylogonthroughRemoteDesktopServices {
          Policy       = 'Deny_log_on_through_Remote_Desktop_Services'
          Identity     = 'Guests'
       }

       # 17.5.1 (L1) Ensure 'Audit Account Lockout' is set to 'Success and Failure'
       AuditPolicySubcategory 'Audit Account Lockout (Success)' {
          Name      = 'Account Lockout'
          Ensure    = 'Present'
          AuditFlag = 'Success'
       }

       AuditPolicySubcategory 'Audit Account Lockout (Failure)' {
          Name      = 'Account Lockout'
          Ensure    = 'Present'
          AuditFlag = 'Failure'
       }
        
       #  18.8.37.1 (L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)
       Registry 'EnableAuthEpResolution' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\Rpc'
          ValueName  = 'EnableAuthEpResolution'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.8.2 (L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'
       Registry 'NoAutorun' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName  = 'NoAutorun'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.30.2 (L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'
       Registry 'NoDataExecutionPrevention' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
          ValueName  = 'NoDataExecutionPrevention'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       # 18.9.49.1 (L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
       Registry 'DisableDownLoadingOfEnclosures' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Internet Explorer\Feeds'
          ValueName  = 'DisableEnclosureDownload'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       # 18.9.67.3 (L1) Ensure 'Automatically send memory dumps for OSgenerated error reports' is set to 'Disabled'
       Registry 'DisableSendOSGeneratedErrorReportsMemoryDumpsToMicrosoft' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
          ValueName  = 'AutoApproveOSDumps'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #
       # ADR Note: these settings (below) are as per CIS - but the EDGE ITHC asked for them to be set to enabled
       # ADR Note: my preferenece is to stick with CIS recommendations
       # ADR Note: Rationale Statements
       # ADR Note: 18.9.95.1 There are potential risks of capturing passwords in the PowerShell logs. This setting should only be needed for debugging purposes, and not in normal operation, it is important to ensure this is set to Disabled.
       # ADR Note: 18.9.95.2 If this setting is enabled there is a risk that passwords could get stored in plain text in the PowerShell_transcript output file.
       #
       #  18.9.95.1 (L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Disabled'
       Registry 'EnableScriptBlockLogging' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
          ValueName  = 'EnableScriptBlockLogging'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.95.2 (L1) Ensure 'Turn on PowerShell Transcription' is set to 'Disabled'
       Registry 'EnableTranscripting' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
          ValueName  = 'EnableTranscripting'
          ValueType  = 'DWord'
          ValueData  = '0'
       }
       #
       # ADR Note: these settings (above) are as per CIS - but the EDGE ITHC asked for them to be set to enabled
       # ADR Note: In Microsoft's own hardening guidance, they recommend the opposite value, Enabled, because having this
       # ADR Note: data logged improves investigations of PowerShell attack incidents. However, the default ACL on the
       # ADR Note: PowerShell Operational log allows Interactive User (i.e. any logged on user) to read it, and therefore
       # ADR Note: possibly expose passwords or other sensitive information to unauthorized users. If Microsoft locks down
       # ADR Note: the default ACL on that log in the future (e.g. to restrict it only to Administrators), then we will revisit
       # ADR Note: this recommendation in a future release.
       #


   }

}

CIS_Add_Edge_Findings