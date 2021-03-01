# Configuration Definition
Configuration CIS_Enforce_User_Rights_Assignment {
   param (
       [string[]]$NodeName ='localhost'
       )


   Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
   Import-DscResource -ModuleName 'AuditPolicyDsc'
   Import-DscResource -ModuleName 'SecurityPolicyDsc'

   Node $NodeName {

     #  2.2.4 (L1) Ensure 'Act as part of the operating system' is set to 'No One'
     UserRightsAssignment Actaspartoftheoperatingsystem {
        Policy       = 'Act_as_part_of_the_operating_system'
        Identity     = ''
     }

    #  2.2.5 (L1) Ensure 'Add workstations to domain' is set to 'Administrators' (DC only)
     UserRightsAssignment Addworkstationstodomain {
        Policy       = 'Add_workstations_to_domain'
        Identity     = 'Administrators'
     }

    #  2.2.6 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
    UserRightsAssignment Adjustmemoryquotasforaprocess {
       Policy       = 'Adjust_memory_quotas_for_a_process'
       Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
    }

    #  2.2.10 (L1) Ensure 'Back up files and directories' is set to 'Administrators'
     UserRightsAssignment Backupfilesanddirectories {
        Policy       = 'Back_up_files_and_directories'
        Identity     = 'Administrators'
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

    #  2.2.14 (L1) Ensure 'Create a token object' is set to 'No One'
     UserRightsAssignment Createatokenobject {
        Policy       = 'Create_a_token_object'
        Identity     = ''
     }

    #  2.2.15 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
     UserRightsAssignment Createglobalobjects {
        Policy       = 'Create_global_objects'
        Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
     }

    #  2.2.16 (L1) Ensure 'Create permanent shared objects' is set to 'No One'
     UserRightsAssignment Createpermanentsharedobjects {
        Policy       = 'Create_permanent_shared_objects'
        Identity     = ''
     }

    #  2.2.17 (L1) Ensure 'Create symbolic links' is set to 'Administrators' (DC only)
     UserRightsAssignment Createsymboliclinks {
        Policy       = 'Create_symbolic_links'
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

    # 2.2.25 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests' (DC only)
     UserRightsAssignment DenylogonthroughRemoteDesktopServices {
        Policy       = 'Deny_log_on_through_Remote_Desktop_Services'
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

    #  2.2.31 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (DC only)
     UserRightsAssignment Impersonateaclientafterauthentication {
        Policy       = 'Impersonate_a_client_after_authentication'
        Identity     = 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
     }

    #  2.2.33 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators'
     UserRightsAssignment Increaseschedulingpriority {
        Policy       = 'Increase_scheduling_priority'
        Identity     = 'Administrators'
     }

    #  2.2.34 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'
     UserRightsAssignment Loadandunloaddevicedrivers {
        Policy       = 'Load_and_unload_device_drivers'
        Identity     = 'Administrators'
     }

    #  2.2.35 (L1) Ensure 'Lock pages in memory' is set to 'No One'
     UserRightsAssignment Lockpagesinmemory {
        Policy       = 'Lock_pages_in_memory'
        Identity     = ''
     }

    #  2.2.36 (L2) Ensure 'Log on as a batch job' is set to 'Administrators' (DC Only)
     UserRightsAssignment Logonasabatchjob {
        Policy       = 'Log_on_as_a_batch_job'
        Identity     = 'Administrators'
     }

    #  2.2.38 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators' (MS only)
     UserRightsAssignment Manageauditingandsecuritylog {
        Policy       = 'Manage_auditing_and_security_log'
        Identity     = 'Administrators'
     }

    #  2.2.39 (L1) Ensure 'Modify an object label' is set to 'No One'
     UserRightsAssignment Modifyanobjectlabel {
        Policy       = 'Modify_an_object_label'
        Identity     = ''
     }

    # 2.2.40 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'
     UserRightsAssignment Modifyfirmwareenvironmentvalues {
        Policy       = 'Modify_firmware_environment_values'
        Identity     = 'Administrators'
     }

    #  2.2.41 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
     UserRightsAssignment Performvolumemaintenancetasks {
        Policy       = 'Perform_volume_maintenance_tasks'
        Identity     = 'Administrators'
     }

    #  2.2.42 (L1) Ensure 'Profile single process' is set to 'Administrators'
     UserRightsAssignment Profilesingleprocess {
        Policy       = 'Profile_single_process'
        Identity     = 'Administrators'
     }

    #  2.2.43 (L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
     UserRightsAssignment Profilesystemperformance {
        Policy       = 'Profile_system_performance'
        Identity     = 'Administrators, NT SERVICE\WdiServiceHost'
     }

    #  2.2.44 (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
     UserRightsAssignment Replaceaprocessleveltoken {
        Policy       = 'Replace_a_process_level_token'
        Identity     = 'LOCAL SERVICE, NETWORK SERVICE'
     }

    #  2.2.45 (L1) Ensure 'Restore files and directories' is set to 'Administrators'
     UserRightsAssignment Restorefilesanddirectories {
        Policy       = 'Restore_files_and_directories'
        Identity     = 'Administrators'
     }

    #  2.2.46 (L1) Ensure 'Shut down the system' is set to 'Administrators'
     UserRightsAssignment Shutdownthesystem {
        Policy       = 'Shut_down_the_system'
        Identity     = 'Administrators'
     }

    #  2.2.47 (L1) Ensure 'Synchronize directory service data' is set to 'No One' (DC only)
     UserRightsAssignment Synchronizedirectoryservicedata {
        Policy       = 'Synchronize_directory_service_data'
        Identity     = ''
     }

    #  2.2.48 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'
     UserRightsAssignment Takeownershipoffilesorotherobjects {
        Policy       = 'Take_ownership_of_files_or_other_objects'
        Identity     = 'Administrators'
     }

   }
}

CIS_Enforce_User_Rights_Assignment