# Configuration Definition
Configuration CIS_Fix_AAE {
   param (
       [string[]]$NodeName ='localhost'
       )


   Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
   Import-DscResource -ModuleName 'AuditPolicyDsc'
   Import-DscResource -ModuleName 'SecurityPolicyDsc'

   Node $NodeName {
      #Source: https://github.com/PowerShell/SecurityPolicyDsc/blob/dev/Examples/Resources/AccountPolicy/1-AccountPolicy_Config.ps1
      AccountPolicy AccountPolicies
        {
            Name                                        = 'PasswordPolicies'
            # 1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)'
            Enforce_password_history                    = 24
            # 1.1.2 (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'
            Maximum_Password_Age                        = 60
            # 1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'
            Minimum_Password_Age                        = 1
            # 1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'
            Minimum_Password_Length                     = 14
            # 1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'
            Password_must_meet_complexity_requirements  = 'Enabled'
            # 1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
            Store_passwords_using_reversible_encryption = 'Disabled'
            # 1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'
            Account_lockout_duration                    = 15
            # 1.2.2 (L1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'
            Account_lockout_threshold                   = 10
            # 1.2.3 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'
            Reset_account_lockout_counter_after         = 15
        }

      #  2.2.11 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
       UserRightsAssignment Changethesystemtime {
          Policy       = 'Change_the_system_time'
          Identity     = 'Administrators, LOCAL SERVICE'
       }

      #  2.2.12 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'
       UserRightsAssignment Changethetimezone {
          Policy       = 'Change_the_time_zone'
          Identity     = 'Administrators, LOCAL SERVICE'
       }

      #  2.2.13 (L1) Ensure 'Create a pagefile' is set to 'Administrators'
       UserRightsAssignment Createapagefile {
          Policy       = 'Create_a_pagefile'
          Identity     = 'Administrators'
       }

      #  2.2.19 (L1) Ensure 'Debug programs' is set to 'Administrators'
       UserRightsAssignment Debugprograms {
          Policy       = 'Debug_programs'
          Identity     = 'Administrators'
       }

      #  2.2.22 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'
       UserRightsAssignment Denylogonasabatchjob {
          Policy       = 'Deny_log_on_as_a_batch_job'
          Identity     = 'Guests'
       }

      #  2.2.23 (L1) Ensure 'Deny log on as a service' to include 'Guests'
       UserRightsAssignment Denylogonasaservice {
          Policy       = 'Deny_log_on_as_a_service'
          Identity     = 'Guests'
       }

      #  2.2.24 (L1) Ensure 'Deny log on locally' to include 'Guests'
       UserRightsAssignment Denylogonlocally {
          Policy       = 'Deny_log_on_locally'
          Identity     = 'Guests'
       }

      #  2.2.28 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One' (MS only)
       UserRightsAssignment Enablecomputeranduseraccountstobetrustedfordelegation {
          Policy       = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
          Identity     = ''
       }

      #  2.2.29 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'
       UserRightsAssignment Forceshutdownfromaremotesystem {
          Policy       = 'Force_shutdown_from_a_remote_system'
          Identity     = 'Administrators'
       }

      #  2.2.30 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
       UserRightsAssignment Generatesecurityaudits {
          Policy       = 'Generate_security_audits'
          Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
       }

      #  2.2.35 (L1) Ensure 'Lock pages in memory' is set to 'No One'
       UserRightsAssignment Lockpagesinmemory {
          Policy       = 'Lock_pages_in_memory'
          Identity     = ''
       }

      #  2.2.38 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators' (MS only)
       UserRightsAssignment Manageauditingandsecuritylog {
          Policy       = 'Manage_auditing_and_security_log'
          Identity     = 'Administrators'
       }

       #Source: https://github.com/PowerShell/SecurityPolicyDsc
       SecurityOption AccountSecurityOptions {
         Name                                   = 'AccountSecurityOptions'
         # 2.3.1.2 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'
         Accounts_Block_Microsoft_accounts = 'Users cant add or log on with Microsoft accounts'
         # 2.3.1.3 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only)
         Accounts_Guest_account_status = 'Disabled'
       }

       # 17.1.1 (L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure'
       AuditPolicySubcategory "Audit Credential Validation (Success)"
       {
           Name      = 'Credential Validation'
           Ensure    = 'Present'
           AuditFlag = 'Success'
       }

       AuditPolicySubcategory 'Audit Credential Validation (Failure)'
       {
           Name      = 'Credential Validation'
           Ensure    = 'Present'
           AuditFlag = 'Failure'
       }

       # 17.2.1 (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Application Group Management (Success)'
        {
            Name      = 'Application Group Management'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Application Group Management (Failure)'
        {
            Name      = 'Application Group Management'    
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        # 17.2.2 (L1) Ensure 'Audit Computer Account Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Computer Account Management (Failure)' 
        {
            Name      = 'Computer Account Management'
            Ensure    = 'Present'
            AuditFlag = 'Failure'      
         }

         AuditPolicySubcategory 'Audit Computer Account Management (Success)' {
            Name      = 'Computer Account Management'
            Ensure    = 'Present'   
            AuditFlag = 'Success'      
         }

       # 17.2.3 (L1) Ensure 'Audit Distribution Group Management' is set to 'Success and Failure' (DC only)
       AuditPolicySubcategory 'Audit Distribution Group Management (Failure)' {
         Name      = 'Distribution Group Management'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
         }

     AuditPolicySubcategory 'Audit Distribution Group Management (Success)' {
         Name      = 'Distribution Group Management'
         Ensure    = 'Present'
         AuditFlag = 'Success'
         }

       # 17.2.4 (L1) Ensure 'Audit Other Account Management Events' is set to 'Success and Failure'
       AuditPolicySubcategory 'Audit Other Account Management Events (Failure)' {
         Name      = 'Other Account Management Events'
         Ensure    = 'Present'
         AuditFlag = 'Failure'
         }

     AuditPolicySubcategory 'Audit Other Account Management Events (Success)' {
         Name      = 'Other Account Management Events'
         Ensure    = 'Present'
         AuditFlag = 'Success'
         }

        # 17.2.5 (L1) Ensure 'Audit Security Group Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Security Group Management (Failure)' {
            Name      = 'Security Group Management'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Security Group Management (Success)' {
            Name      = 'Security Group Management'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        # 17.2.6 (L1) Ensure 'Audit User Account Management' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit User Account Management (Failure)' {
            Name      = 'User Account Management'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit User Account Management (Success)' {
            Name      = 'User Account Management'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        # 17.3.1 (L1) Ensure 'Audit PNP Activity' is set to 'Success' 
        AuditPolicySubcategory 'Audit PNP Activity (Success)' {
            Name      = 'Plug and Play Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit PNP Activity (Failure)' {
            Name      = 'Plug and Play Events'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }

        # 17.3.2 (L1) Ensure 'Audit Process Creation' is set to 'Success'
        AuditPolicySubcategory 'Audit Process Creation (Success)' {
            Name      = 'Process Creation'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Process Creation (Failure)' {
            Name      = 'Process Creation'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }

        # 17.4.1 (L1) Ensure 'Audit Directory Service Access' is set to 'Success and Failure' (DC only)
        AuditPolicySubcategory 'Audit Directory Service Access (Success)' {
            Name      = 'Directory Service Access'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Directory Service Access (Failure)' {
            Name      = 'Directory Service Access'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        # 17.4.2 (L1) Ensure 'Audit Directory Service Changes' is set to 'Success and Failure' (DC only)
        AuditPolicySubcategory 'Audit Directory Service Changes (Success)' {
            Name      = 'Directory Service Changes'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Directory Service Changes (Failure)' {
            Name      = 'Directory Service Changes'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
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
        
        # 17.5.2 (L1) Ensure 'Audit Group Membership' is set to 'Success'
        AuditPolicySubcategory 'Audit Group Membership (Success)' {
            Name      = 'Group Membership'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Group Membership (Failure)' {
            Name      = 'Group Membership'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
         }
        
        # 17.5.3 (L1) Ensure 'Audit Logoff' is set to 'Success'
        AuditPolicySubcategory 'Audit Logoff (Success)' {
            Name      = 'Logoff'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Logoff (Failure)' {
            Name      = 'Logoff'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }
        
        # 17.5.4 (L1) Ensure 'Audit Logon' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Logon (Success)' {
            Name      = 'Logon'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Logon (Failure)' {
            Name      = 'Logon'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 17.5.5 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure)' {
            Name      = 'Other Logon/Logoff Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success)' {
            Name      = 'Other Logon/Logoff Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.5.6 (L1) Ensure 'Audit Special Logon' is set to 'Success'
        AuditPolicySubcategory 'Audit Special Logon (Success)' {
            Name      = 'Special Logon'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Special Logon (Failure)' {
            Name      = 'Special Logon'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }
        
        # 17.6.1 (L1) Ensure 'Audit Detailed File Share' is set to include 'Failure'
        AuditPolicySubcategory 'Audit Detailed File Share (Success)' {
            Name      = 'Detailed File Share'
            Ensure    = 'Absent'
            AuditFlag = 'Success'
         }

        AuditPolicySubcategory 'Audit Detailed File Share (Failure)' {
            Name      = 'Detailed File Share'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
         }       

        # 17.6.2 (L1) Ensure 'Audit  File Share' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit File Share (Success)' {
            Name      = 'File Share'
            Ensure    = 'Present'
            AuditFlag = 'Success'
         }

        AuditPolicySubcategory 'Audit File Share (Failure)' {
            Name      = 'File Share'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
         }   

        # 17.6.3 (L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other Object Access Events (Success)' {
            Name      = 'Other Object Access Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Other Object Access Events (Failure)' {
            Name      = 'Other Object Access Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 17.6.4 (L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Removable Storage (Success)' {
            Name      = 'Removable Storage'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Removable Storage (Failure)' {
            Name      = 'Removable Storage'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 17.7.1 (L1) Ensure 'Audit Audit Policy Change' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Policy Change (Success)' {
            Name      = 'Audit Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Policy Change (Failure)' {
            Name      = 'Audit Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }
        
        # 17.7.2 (L1) Ensure 'Audit Authentication Policy Change' is set to 'Success'
        AuditPolicySubcategory 'Audit Authentication Policy Change (Success)' {
            Name      = 'Authentication Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Authentication Policy Change (Failure)' {
            Name      = 'Authentication Policy Change'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }
        
        # 17.7.3 (L1) Ensure 'Audit Authorization Policy Change' is set to 'Success'
        AuditPolicySubcategory 'Audit Authorization Policy Change (Success)' {
            Name      = 'Authorization Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Authorization Policy Change (Failure)' {
            Name      = 'Authorization Policy Change'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }

        # 17.7.4 (L1) Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Success)' {
            Name      = 'MPSSVC Rule-Level Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Failure)' {
            Name      = 'MPSSVC Rule-Level Policy Change'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        # 17.7.5 (L1) Ensure 'Audit Other Policy Change Events' is set to include 'Failure'
        AuditPolicySubcategory 'Audit Other Policy Change Events (Success)' {
            Name      = 'Other Policy Change Events'
            Ensure    = 'Absent'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Other Policy Change Events (Failure)' {
            Name      = 'Other Policy Change Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        # 17.8.1 (L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure)' {
            Name      = 'Sensitive Privilege Use'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success)' {
            Name      = 'Sensitive Privilege Use'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.9.1 (L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit IPsec Driver (Failure)' {
            Name      = 'IPsec Driver'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit IPsec Driver (Success)' {
            Name      = 'IPsec Driver'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.9.2 (L1) Ensure 'Audit Other System Events' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Other System Events (Failure)' {
            Name      = 'Other System Events'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Other System Events (Success)' {
            Name      = 'Other System Events'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.9.3 (L1) Ensure 'Audit Security State Change' is set to 'Success'
        AuditPolicySubcategory 'Audit Security State Change (Success)' {
            Name      = 'Security State Change'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }

        AuditPolicySubcategory 'Audit Security State Change (Failure)' {
            Name      = 'Security State Change'
            Ensure    = 'Absent'
            AuditFlag = 'Failure'
        }
        
        # 17.9.4 (L1) Ensure 'Audit Security System Extension' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit Security System Extension (Failure)' {
            Name      = 'Security System Extension'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit Security System Extension (Success)' {
            Name      = 'Security System Extension'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
        
        # 17.9.5 (L1) Ensure 'Audit System Integrity' is set to 'Success and Failure'
        AuditPolicySubcategory 'Audit System Integrity (Failure)' {
            Name      = 'System Integrity'
            Ensure    = 'Present'
            AuditFlag = 'Failure'
        }

        AuditPolicySubcategory 'Audit System Integrity (Success)' {
            Name      = 'System Integrity'
            Ensure    = 'Present'
            AuditFlag = 'Success'
        }
       
       # 18.1.1.1 (L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'
       Registry 'NoLockScreenCamera' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
           ValueName   = 'NoLockScreenCamera' 
           ValueType   = 'DWord' 
           ValueData   = '1' 
       }

       #  18.1.1.2 (L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'
       Registry 'NoLockScreenSlideshow' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization'
          ValueName    = 'NoLockScreenSlideshow'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.1.2.2 (L1) Ensure 'Allow input personalization' is set to 'Disabled'
       Registry 'AllowInputPersonalization' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization'
          ValueName    = 'AllowInputPersonalization'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.2.2 (L1) Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled' (MS only)
       Registry 'PwdExpirationProtectionEnabled' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\MicrosoftServices\AdmPwd'
          ValueName    = 'PwdExpirationProtectionEnabled'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.2.4 (L1) Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters' (MS only)
       Registry 'PasswordComplexity' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\MicrosoftServices\AdmPwd'
          ValueName    = 'PasswordComplexity'
          ValueType    = 'DWord'
          ValueData    = '4'

       }
       #  18.2.5 (L1) Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more' (MS only)
       Registry 'PasswordLength' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd'
          ValueName    = 'PasswordLength'
          ValueType    = 'DWord'
          ValueData    = '15'
       }

       #  18.2.6 (L1) Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer' (MS only)
       Registry 'PasswordAgeDays' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\MicrosoftServices\AdmPwd'
          ValueName    = 'PasswordAgeDays'
          ValueType    = 'DWord'
          ValueData    = '30'
       }

       #  18.3.2 (L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver'
       Registry 'Start' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10'
          ValueName    = 'Start'
          ValueType    = 'DWord'
          ValueData    = '4'
       }

       #  18.3.3 (L1) Ensure 'Configure SMB v1 server' is set to 'Disabled'
       Registry 'SMB1' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
          ValueName    = 'SMB1'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.3.5 (L1) Ensure 'Extended Protection for LDAP Authentication (Domain Controllers only)' is set to 'Enabled: Enabled, always (recommended)' (DC Only)
       Registry 'LDAPExtendedProtection' {
         Ensure       = 'Present'
         Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
         ValueName    = 'LdapEnforceChannelBinding'
         ValueType    = 'DWord'
         ValueData    = '2'
        }

       #  18.3.6 (L1) Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'
       Registry 'NetBTNodeType' {
         Ensure       = 'Present'
         Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
         ValueName    = 'NodeType'
         ValueType    = 'DWord'
         ValueData    = '2'
       }
       #  18.3.7 (L1) Ensure 'WDigest Authentication' is set to 'Disabled'
       Registry 'UseLogonCredential' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
          ValueName    = 'UseLogonCredential'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.4.1 (L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'
       Registry 'AutoAdminLogon' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon'
          ValueName    = 'AutoAdminLogon'
          ValueType    = 'String'
          ValueData    = '0'
       }

       #  18.4.2 (L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
       Registry 'DisableIPSourceRouting' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
          ValueName    = 'DisableIPSourceRouting'
          ValueType    = 'DWord'
          ValueData    = '2'
       }

       #  18.4.3 (L1) Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
       Registry 'DisableIPSourceRouting2' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
          ValueName    = 'DisableIPSourceRouting'
          ValueType    = 'DWord'
          ValueData    = '2'
       }

       #  18.4.4 (L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'
       Registry 'EnableICMPRedirect' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
          ValueName    = 'EnableICMPRedirect'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.4.6 (L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled
       Registry 'NoNameReleaseOnDemand' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'
          ValueName    = 'NoNameReleaseOnDemand'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.4.9 (L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'
       Registry 'ScreenSaverGracePeriod' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon'
          ValueName    = 'ScreenSaverGracePeriod'
          ValueType    = 'String'
          ValueData    = '5'
       }

       #  18.4.12 (L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'
       Registry 'WarningLevel' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
          ValueName    = 'WarningLevel'
          ValueType    = 'DWord'
          ValueData    = '90'
       }

       #  18.5.4.1 (L1) Ensure 'Turn off multicast name resolution' is set to 'Enabled' (MS Only)
       Registry 'EnableMulticast' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\DNSClient'
          ValueName    = 'EnableMulticast'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.5.8.1 (L1) Ensure 'Enable insecure guest logons' is set to 'Disabled'
       Registry 'AllowInsecureGuestAuth' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
          ValueName    = 'AllowInsecureGuestAuth'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.5.11.2 (L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'
       Registry 'NC_AllowNetBridge_NLA' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections'
          ValueName    = 'NC_AllowNetBridge_NLA'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.5.11.3 (L1) Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'
       Registry 'NC_ShowSharedAccessUI' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections'
          ValueName    = 'NC_ShowSharedAccessUI'
          ValueType    = 'DWord'
          ValueData    = '0'
       }

       #  18.5.11.4 (L1) Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'
       Registry 'NC_StdDomainUserSetLocation' {
          Ensure       = 'Present'
          Key          = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkConnections'
          ValueName    = 'NC_StdDomainUserSetLocation'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  18.5.21.1 (L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled'
       Registry 'fMinimizeConnections' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
          ValueName  = 'fMinimizeConnections'
          ValueType  = 'DWord'
          ValueData  = '1'
       }
       
       #  18.8.14.1 (L1) Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'
       Registry 'DriverLoadPolicy' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
          ValueName  = 'DriverLoadPolicy'
          ValueType  = 'DWord'
          ValueData  = '3'
       }

       #  18.8.21.2 (L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
       Registry 'NoBackgroundPolicy' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GroupPolicy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
          ValueName  = 'NoBackgroundPolicy'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.21.3 (L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'
       Registry 'NoGPOListChanges' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GroupPolicy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
          ValueName  = 'NoGPOListChanges'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.21.4 (L1) Ensure 'Continue experiences on this device' is set to 'Disabled'
       Registry 'EnableCdp' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'EnableCdp'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.21.5 (L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'
       Registry 'DisableBkGndGroupPolicy' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          ValueName  = 'DisableBkGndGroupPolicy'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.22.1.1 (L1) Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
       Registry 'DisableWebPnPDownload' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\Printers'
          ValueName  = 'DisableWebPnPDownload'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.22.1.5 (L1) Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
       Registry 'NoWebServices' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName  = 'NoWebServices'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.22.1.6 (L1) Ensure 'Turn off printing over HTTP' is set to 'Enabled'
       Registry 'DisableHTTPPrinting' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsNT\Printers'
          ValueName  = 'DisableHTTPPrinting'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.28.1 (L1) Ensure 'Block user from showing account details on signin' is set to 'Enabled'
       Registry 'BlockUserFromShowingAccountDetailsOnSignin' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
         ValueName  = 'BlockUserFromShowingAccountDetailsOnSignin'
         ValueType  = 'DWord'
         ValueData  = '1'
      }

       #  18.8.28.2 (L1) Ensure 'Do not display network selection UI' is set to 'Enabled'
       Registry 'DontDisplayNetworkSelectionUI' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'DontDisplayNetworkSelectionUI'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.28.3 (L1) Ensure 'Do not enumerate connected users on domainjoined computers' is set to 'Enabled'
       Registry 'DontEnumerateConnectedUsers' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'DontEnumerateConnectedUsers'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.28.4 (L1) Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled' (MS only)
       Registry 'EnumerateLocalUsers' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'EnumerateLocalUsers'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.28.5 (L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'
       Registry 'DisableLockScreenAppNotifications' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'DisableLockScreenAppNotifications'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.28.6 (L1) Ensure 'Turn off picture password sign-in' is set to 'Enabled'
       Registry 'BlockDomainPicturePassword' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'BlockDomainPicturePassword'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.28.7 (L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'
       Registry 'AllowDomainPINLogon' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
          ValueName  = 'AllowDomainPINLogon'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       # 18.8.31.2 (L2) Ensure 'Allow upload of User Activities' is set to 'Disabled'
       Registry 'AllowCrossDeviceClipboard' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System'
         ValueName  = 'UploadUserActivities'
         ValueType  = 'DWord'
         ValueData  = '0'
      }

       #  18.8.34.6.1 (L2) Ensure 'Allow network connectivity during connectedstandby (on battery)' is set to 'Disabled'
       Registry 'DCSettingIndex' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'
         ValueName  = 'DCSettingIndex'
         ValueType  = 'DWord'
         ValueData  = '0'
      }

       #  18.8.34.6.2 (L2) Ensure 'Allow network connectivity during connectedstandby (plugged in)' is set to 'Disabled'
       Registry 'ACSettingIndex' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'
          ValueName  = 'ACSettingIndex'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.34.6.3 (L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'
       Registry 'DCSettingIndex2' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb100d-47d6-a2d5-f7d2daa51f51'
          ValueName  = 'DCSettingIndex'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.34.6.4 (L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'
       Registry 'ACSettingIndex2' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb100d-47d6-a2d5-f7d2daa51f51'
          ValueName  = 'ACSettingIndex'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.8.36.1 (L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
       Registry 'fAllowUnsolicited' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'fAllowUnsolicited'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.8.36.2 (L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
       Registry 'fAllowToGetHelp' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'fAllowToGetHelp'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.6.1 (L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'
       Registry 'MSAOptional' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          ValueName  = 'MSAOptional'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.8.1 (L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'
       Registry 'NoAutoplayfornonVolume' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
          ValueName  = 'NoAutoplayfornonVolume'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.8.3 (L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'
       Registry 'NoDriveTypeAutoRun' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
          ValueName  = 'NoDriveTypeAutoRun'
          ValueType  = 'DWord'
          ValueData  = '255'
       }
       
       #  18.9.10.1.1 (L1) Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'
       Registry 'EnhancedAntiSpoofing' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Biometrics\FacialFeatures'
          ValueName  = 'EnhancedAntiSpoofing'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.13.1 (L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'
       Registry 'DisableWindowsConsumerFeatures' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
          ValueName  = 'DisableWindowsConsumerFeatures'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.14.1 (L1) Ensure 'Require pin for pairing' is set to 'Enabled'
       Registry 'RequirePinForPairing' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Connect'
          ValueName  = 'RequirePinForPairing'
          ValueType  = 'DWord'
          ValueData  = '1'
       }       
       
       # 18.9.15.1 (L1) Ensure 'Do not display the password reveal button' is set to 'Enabled'
       Registry 'DisablePasswordReveal' {
           Ensure      = 'Present'
           Key         = 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CredUI'
           ValueName   = 'DisablePasswordReveal'
           ValueType   = 'DWord'
           ValueData   = '1'
       }

       #  18.9.15.2 (L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'
       Registry 'EnumerateAdministrators' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
          ValueName  = 'EnumerateAdministrators'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.16.1 (L1) Ensure 'Allow Telemetry' is set to 'Enabled: 0 - Security [Enterprise Only]' or 'Enabled: 1 - Basic'
       Registry 'AllowTelemetry' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
          ValueName  = 'AllowTelemetry'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.16.3 (L1) Ensure 'Do not show feedback notifications' is set to 'Enabled'
       Registry 'DoNotShowFeedbackNotifications' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
          ValueName  = 'DoNotShowFeedbackNotifications'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.16.4 (L1) Ensure 'Toggle user control over Insider builds' is set to 'Disabled'
       Registry 'AllowBuildPreview' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds'
          ValueName  = 'AllowBuildPreview'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.26.1.1 (L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
       Registry 'RetentionApplicationLog' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
          ValueName  = 'Retention'
          ValueType  = 'String'
          ValueData  = '0'
       }

       #  18.9.26.1.2 (L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
       Registry 'MaxSizeApplicationLog' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
          ValueName  = 'MaxSize'
          ValueType  = 'DWord'
          ValueData  = '32768'
       }

       #  18.9.26.2.1 (L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
       Registry 'RetentionSecurityLog' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
          ValueName  = 'Retention'
          ValueType  = 'String'
          ValueData  = '0'
       }

       #  18.9.26.2.2 (L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'
       Registry 'MaxSizeSecurityLog' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
          ValueName  = 'MaxSize'
          ValueType  = 'DWord'
          ValueData  = '196608'
       }

       #  18.9.26.3.1 (L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
       Registry 'RetentionSetupLog' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
          ValueName  = 'Retention'
          ValueType  = 'String'
          ValueData  = '0'
       }

       #  18.9.26.3.2 (L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
       Registry 'MaxSizeSetupLog' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'
          ValueName  = 'MaxSize'
          ValueType  = 'DWord'
          ValueData  = '32768'
       }

       #  18.9.26.4.1 (L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'
       Registry 'RetentionSystemLog' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
          ValueName  = 'Retention'
          ValueType  = 'String'
          ValueData  = '0'
       }

       #  18.9.26.4.2 (L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'
       Registry 'MaxSizeSystemLog' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
          ValueName  = 'MaxSize'
          ValueType  = 'DWord'
          ValueData  = '32768'
       }

       #  18.9.30.3 (L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled'
       Registry 'NoHeapTerminationOnCorruption' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer'
          ValueName  = 'NoHeapTerminationOnCorruption'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.44.1 (L1) Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'
       Registry 'DisableUserAuth' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftAccount'
          ValueName  = 'DisableUserAuth'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.52.1 (L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'
       Registry 'DisableFileSyncNGSC' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
          ValueName  = 'DisableFileSyncNGSC'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.59.2.2 (L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
       Registry 'DisablePasswordSaving' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'DisablePasswordSaving'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.59.3.3.2 (L1) Ensure 'Do not allow drive redirection' is set to 'Enabled'
       Registry 'fDisableCdm' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'fDisableCdm'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.59.3.9.1 (L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled'
       Registry 'fPromptForPassword' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'fPromptForPassword'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.59.3.9.2 (L1) Ensure 'Require secure RPC communication' is set to 'Enabled'
       Registry 'fEncryptRPCTraffic' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'fEncryptRPCTraffic'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.59.3.9.3 (L1) Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'
       Registry 'SecurityLayer' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
         ValueName  = 'SecurityLayer'
         ValueType  = 'DWord'
         ValueData  = '2'
      }
      
      #  18.9.59.3.9.4 (L1) Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'
      Registry 'UserAuthentication' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
         ValueName  = 'UserAuthentication'
         ValueType  = 'DWord'
         ValueData  = '1'
      }

       #  18.9.59.3.9.5 (L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
       Registry 'MinEncryptionLevel' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'MinEncryptionLevel'
          ValueType  = 'DWord'
          ValueData  = '3'
       }

       #  18.9.59.3.11.1 (L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'
       Registry 'DeleteTempDirsOnExit' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'DeleteTempDirsOnExit'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.59.3.11.2 (L1) Ensure 'Do not use temporary folders per session' is set to 'Disabled'
       Registry 'PerSessionTempDir' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
          ValueName  = 'PerSessionTempDir'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.61.3 (L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled'
       Registry 'AllowIndexingEncryptedStoresOrItems' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsSearch'
          ValueName  = 'AllowIndexingEncryptedStoresOrItems'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.66.1 (L2) Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'
       Registry 'NoGenTicket' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'
          ValueName  = 'NoGenTicket'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.77.10.2  (L1) Ensure 'Turn on e-mail scanning' is set to 'Enabled'
       Registry 'EnableEmailScanning' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsDefender\Scan'
          ValueName  = 'EnableEmailScanning'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.77.15 (L1) Ensure 'Turn off Windows Defender AntiVirus' is set to 'Disabled'
       Registry 'DisableAntiSpyware' {
         Ensure     = 'Present'
         Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsDefender'
         ValueName  = 'DisableAntiSpyware'
         ValueType  = 'DWord'
         ValueData  = '0'
      }
       
       #  18.9.86.1 (L1) Ensure 'Sign-in last interactive user automatically after a system-initiated restart' is set to 'Disabled'
       Registry 'DisableAutomaticRestartSignOn' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
          ValueName  = 'DisableAutomaticRestartSignOn'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.97.1.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled'
       Registry 'AllowBasic' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
          ValueName  = 'AllowBasic'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.97.1.2 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'
       Registry 'AllowUnencryptedTraffic' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
          ValueName  = 'AllowUnencryptedTraffic'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.97.1.3 (L1) Ensure 'Disallow Digest authentication' is set to 'Enabled'
       Registry 'AllowDigest' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
          ValueName  = 'AllowDigest'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.97.2.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled'
       Registry 'AllowBasic2' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
          ValueName  = 'AllowBasic'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.97.2.3 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled'
       Registry 'AllowUnencryptedTraffic2' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
          ValueName  = 'AllowUnencryptedTraffic'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.97.2.4 (L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'
       Registry 'DisableRunAs' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
          ValueName  = 'DisableRunAs'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.102.1.1 (L1) Ensure 'Manage preview builds' is set to 'Enabled: Disable preview builds'
       Registry 'ManagePreviewBuilds' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
          ValueName  = 'ManagePreviewBuilds'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.102.1.1 (L1) Ensure 'Manage preview builds' is set to 'Enabled: Disable preview builds'
       Registry 'ManagePreviewBuildsPolicyValue' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
          ValueName  = 'ManagePreviewBuildsPolicyValue'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.102.1.2 (L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'
       Registry 'DeferFeatureUpdates' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
          ValueName  = 'DeferFeatureUpdates'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.102.1.2 (L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'
       Registry 'DeferFeatureUpdatesPeriodInDays' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
          ValueName  = 'DeferFeatureUpdatesPeriodInDays'
          ValueType  = 'DWord'
          ValueData  = '180'
       }

       #  18.9.102.1.2 (L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: Semi-Annual Channel, 180 or more days'
       Registry 'BranchReadinessLevel' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
          ValueName  = 'BranchReadinessLevel'
          ValueType  = 'DWord'
          ValueData  = '32'
       }

       #  18.9.102.1.3 (L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'
       Registry 'DeferQualityUpdates' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
          ValueName  = 'DeferQualityUpdates'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.102.1.3 (L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'
       Registry 'DeferQualityUpdatesPeriodInDays' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
          ValueName  = 'DeferQualityUpdatesPeriodInDays'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.102.2 (L1) Ensure 'Configure Automatic Updates' is set to 'Enabled'
       Registry 'NoAutoUpdate' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
          ValueName  = 'NoAutoUpdate'
          ValueType  = 'DWord'
          ValueData  = '1'
       }

       #  18.9.102.3 (L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'
       Registry 'ScheduledInstallDay' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
          ValueName  = 'ScheduledInstallDay'
          ValueType  = 'DWord'
          ValueData  = '0'
       }

       #  18.9.102.4 (L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'
       Registry 'NoAutoRebootWithLoggedOnUsers' {
          Ensure     = 'Present'
          Key        = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
          ValueName  = 'NoAutoRebootWithLoggedOnUsers'
          ValueType  = 'DWord'
          ValueData  = '0'
       }


       # 19.1.3.1 (L1) Ensure 'Enable screen saver' is set to 'Enabled'
       Registry 'ScreenSaveActive' {
           Ensure      = 'Present'
           Key         = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
           ValueName   = 'ScreenSaveActive'
           ValueType   = 'String'
           ValueData   = '1'
       }

       #  19.1.3.2 (L1) Ensure 'Force specific screen saver: Screen saver executable name' is set to 'Enabled: scrnsave.scr'
       Registry 'SCRNSAVE.EXE' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
          ValueName    = 'SCRNSAVE.EXE'
          ValueType    = 'String'
         ValueData    = 'scrnsave.scr'
       }

       #  19.1.3.3 (L1) Ensure 'Password protect the screen saver' is set to 'Enabled'
       Registry 'ScreenSaverIsSecure' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
          ValueName    = 'ScreenSaverIsSecure'
          ValueType    = 'String'
          ValueData    = '1'
       }

       #  19.1.3.4 (L1) Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0'
       Registry 'ScreenSaveTimeOut' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
          ValueName    = 'ScreenSaveTimeOut'
          ValueType    = 'DWord'
          ValueData    = '900'
       }

       #  19.5.1.1 (L1) Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'
       Registry 'NoToastApplicationNotificationOnLockScreen' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
          ValueName    = 'NoToastApplicationNotificationOnLockScreen'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  19.6.5.1.1 (L2) Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'
       Registry 'NoImplicitFeedback' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0'
          ValueName    = 'NoImplicitFeedback'
          ValueType    = 'DWord'
          ValueData    = '1'
       }

       #  19.7.4.2 (L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'
       Registry 'ScanWithAntiVirus' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
          ValueName    = 'ScanWithAntiVirus'
          ValueType    = 'DWord'
          ValueData    = '3'
       }

       #  19.7.7.1 (L1) Ensure 'Configure Windows spotlight on lock screen' is set to Disabled'
       Registry 'ConfigureWindowsSpotlight' {
          Ensure       = 'Present'
          Key          = 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent'
          ValueName    = 'ConfigureWindowsSpotlight'
          ValueType    = 'DWord'
          ValueData    = '2'
       }

   }
}

CIS_Fix_AAE