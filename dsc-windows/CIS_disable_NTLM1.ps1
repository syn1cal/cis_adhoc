# Configuration Definition
Configuration CIS_disable_NTLM1 {
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
          # 2.3.11.7 (L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
          Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM' 
          # 2.3.17.1 (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled' 
          User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
          # 2.3.17.2 (L1) Ensure 'User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop' is set to 'Disabled' 
          User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
          # 2.3.17.3 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' 
          User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
          # 2.3.17.4 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests' 
          User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
          # 2.3.17.5 (L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled' 
          User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
          # 2.3.17.6 (L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled' 
          User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
          # 2.3.17.7 (L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'
          User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
          # 2.3.17.8 (L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled' 
          User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'
          # 2.3.17.9 (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'
          User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
        }

   }
}

CIS_disable_NTLM1
