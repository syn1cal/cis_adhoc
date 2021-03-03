# Configuration Definition
Configuration CIS_set_audit {
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
         # 2.3.2.1 (L1) Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'
         Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
         # 2.3.2.2 (L1) Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
         Audit_Shut_down_system_immediately_if_unable_to_log_security_audits = 'Disabled'
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
   }
}

CIS_set_audit