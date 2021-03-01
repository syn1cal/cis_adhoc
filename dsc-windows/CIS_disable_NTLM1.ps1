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
        }

   }
}

CIS_disable_NTLM1
