# LimaCharlie Sample Events

<!-- Developed by Digital Defense Institute (https://digitaldefenseinstitute.com) -->

This document contains sample event structures for various LimaCharlie event types to aid in detection rule development and LCQL query construction.

## Table of Contents
- [Windows Events](#windows-events)
  - [NEW_PROCESS](#new_process)
  - [EXISTING_PROCESS](#existing_process)
  - [NEW_DOCUMENT](#new_document)
  - [CODE_IDENTITY](#code_identity)
  - [REGISTRY_WRITE](#registry_write)
  - [WEL (Windows Event Logs)](#wel-windows-event-logs)
  - [Sysmon Events](#sysmon-events)
- [Azure/O365 Events](#azureo365-events)
  - [NonInteractiveUserSignInLogs](#noninteractiveusersigninlogs)
  - [SignInLogs](#signinlogs)
  - [Administrative](#administrative)
  - [Add-MailboxPermission](#add-mailboxpermission)
  - [UserLoggedIn](#userloggedin)
  - [Consent to application](#consent-to-application)
  - [UserLoginFailed](#userloginfailed)
  - [Set-MailboxAuditBypassAssociation](#set-mailboxauditbypassassociation)
  - [AlertTriggered](#alerttriggered)

## Windows Events

### NEW_PROCESS
Process creation event capturing full command line, parent process information, and file signatures.

```json
{
    "event": {
        "BASE_ADDRESS": 140697158615040,
        "COMMAND_LINE": "C:\\WINDOWS\\system32\\svchost.exe -k netsvcs -p -s wlidsvc",
        "FILE_IS_SIGNED": 1,
        "FILE_PATH": "C:\\WINDOWS\\system32\\svchost.exe",
        "HASH": "b0b36bff7ae4057f687d839cd4b3d81159ab646f1ee1b22106a927e93decbb61",
        "MEMORY_USAGE": 26750976,
        "PARENT": {
            "FILE_IS_SIGNED": 1,
            "FILE_PATH": "\\Device\\HarddiskVolume4\\Windows\\System32\\services.exe",
            "HASH": "4a912dc98c977788131aad0ae468d86792211ed225f80b2c344a3690b4437428",
            "MEMORY_USAGE": 11943936,
            "PARENT_ATOM": "7f74d2e5114a8dcfc4b07d5c6837348c",
            "PARENT_PROCESS_ID": 880,
            "PROCESS_ID": 952,
            "THIS_ATOM": "4ac2f4172cf8d55d935a19f76837348c",
            "THREADS": 11,
            "TIMESTAMP": 1748448396224,
            "USER_NAME": "NT AUTHORITY\\SYSTEM"
        },
        "PARENT_PROCESS_ID": 952,
        "PROCESS_ID": 728,
        "THREADS": 17,
        "USER_NAME": "NT AUTHORITY\\SYSTEM"
    },
    "routing": {
        "event_type": "NEW_PROCESS",
        "hostname": "DESKTOP-ABC123",
        "plat": 268435456
    }
}
```

### EXISTING_PROCESS
Discovery of already running processes during sensor startup or periodic scans.

```json
{
    "event": {
        "BASE_ADDRESS": 140701487005696,
        "COMMAND_LINE": "\"C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\137.0.3296.93\\msedgewebview2.exe\" --embedded-browser-webview=1 --webview-exe-name=ms-teams.exe",
        "CREATION_TIME": 1751204438899,
        "FILE_IS_SIGNED": 1,
        "FILE_PATH": "C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\137.0.3296.93\\msedgewebview2.exe",
        "HASH": "f985650d229148704d7037c8d5485a780ed6d6cd27eba497bcf8d29c3c5a101d",
        "MEMORY_USAGE": 154771456,
        "PARENT": {
            "BASE_ADDRESS": 140700942467072,
            "COMMAND_LINE": "\"C:\\Program Files\\WindowsApps\\MSTeams_25153.1010.3727.5483_x64__8wekyb3d8bbwe\\ms-teams.exe\" msteams:system-initiated",
            "CREATION_TIME": 1751204437859,
            "FILE_IS_SIGNED": 1,
            "FILE_PATH": "C:\\Program Files\\WindowsApps\\MSTeams_25153.1010.3727.5483_x64__8wekyb3d8bbwe\\ms-teams.exe",
            "HASH": "9ab0e290352c8826e3126eab13e8598260a06149de9e39206705510aa5a03b1e",
            "PARENT_PROCESS_ID": 14948,
            "PROCESS_ID": 15012,
            "USER_NAME": "EXAMPLE\\user4"
        },
        "PARENT_PROCESS_ID": 15012,
        "PROCESS_ID": 15244,
        "THREADS": 58,
        "USER_NAME": "EXAMPLE\\user4"
    },
    "routing": {
        "event_type": "EXISTING_PROCESS",
        "hostname": "WORKSTATION-01.example.local",
        "plat": 268435456
    }
}
```

### NEW_DOCUMENT
File creation or modification event.

```json
{
    "event": {
        "FILE_PATH": "C:\\Program Files\\Microsoft Office\\Updates\\Download\\PackageFiles\\CC11FB1D-0600-463E-9462-E18524A8BD3F\\root\\Office16\\SDXHelper.exe",
        "HASH": "dc085d7c231407873741084230963d52add21549244402b542944d2dcc510a41",
        "PROCESS_ID": 3280
    },
    "routing": {
        "event_type": "NEW_DOCUMENT",
        "hostname": "USER-PC.example.local",
        "plat": 268435456
    }
}
```

### CODE_IDENTITY
Code signing and file integrity information.

```json
{
    "event": {
        "ACCESS_TIME": 1748873818900,
        "ATTRIBUTES": 0,
        "CREATION_TIME": 1748873818864,
        "ERROR": 0,
        "FILE_INFO": "10.0.19041.5794",
        "FILE_PATH": "C:\\Users\\user\\AppData\\Local\\Temp\\684D3A0B-ED71-49D6-8BB7-DEC757335566\\CbsProvider.dll",
        "FILE_SIZE": 931768,
        "HASH": "0c481144f28e4a5f7e16377b948fb8ca1e8ff9f57ab50a4906b0222beeaf4171",
        "HASH_MD5": "ebcfb482742ed8f409e72b535abb9eee",
        "HASH_SHA1": "26eb93819449c01928ff3e9a620b651984bd548a",
        "MODIFICATION_TIME": 1747764624419,
        "ORIGINAL_FILE_NAME": "CbsProvider.dll",
        "SIGNATURE": {
            "CERT_ISSUER": "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows Production PCA 2011",
            "CERT_SUBJECT": "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows",
            "FILE_CERT_IS_VERIFIED_LOCAL": 1,
            "FILE_IS_SIGNED": 1,
            "FILE_PATH": "C:\\Users\\user\\AppData\\Local\\Temp\\684D3A0B-ED71-49D6-8BB7-DEC757335566\\CbsProvider.dll"
        }
    },
    "routing": {
        "event_type": "CODE_IDENTITY",
        "hostname": "DESKTOP-XYZ789.example.local",
        "plat": 268435456
    }
}
```

### REGISTRY_WRITE
Registry modification event, often indicating tool execution or persistence mechanisms.

```json
{
  "event": {
    "PROCESS_ID": 10828,
    "REGISTRY_KEY": "\\REGISTRY\\USER\\S-1-5-21-2760201226-1107251346-1237796511-1120\\SOFTWARE\\Sysinternals\\PsExec\\EulaAccepted",
    "REGISTRY_VALUE": "AQAAAA==",
    "SIZE": 4,
    "TYPE": 4
  },
  "routing": {
    "event_type": "REGISTRY_WRITE",
    "hostname": "eng-01.initechsw.com",
    "plat": 268435456,
    "tags": [
      "yara_detection_memory"
    ],
    "this": "ae547bc0db3d64d935347698688fb5f5",
    "parent": "276d27eb487c9aa66967d765688fb594"
  }
}
```

### WEL (Windows Event Logs)

#### Event ID 4662 - Object Access
```json
{
    "event": {
        "EVENT": {
            "EventData": {
                "AccessList": "%%5649",
                "AccessMask": "0x2",
                "HandleId": "0x26d0defdaa0",
                "ObjectName": "Policy\\Secrets\\$MACHINE.ACC",
                "ObjectServer": "LSA",
                "ObjectType": "SecretObject",
                "OperationType": "Query",
                "SubjectDomainName": "NT AUTHORITY",
                "SubjectLogonId": "0x3e5",
                "SubjectUserName": "LOCAL SERVICE",
                "SubjectUserSid": "S-1-5-19"
            },
            "System": {
                "Channel": "Security",
                "Computer": "DC01.example.corp",
                "EventID": "4662",
                "EventRecordID": "7842175",
                "Provider": {
                    "Name": "Microsoft-Windows-Security-Auditing"
                }
            }
        }
    },
    "routing": {
        "event_type": "WEL",
        "hostname": "DC01.example.corp",
        "plat": 268435456
    }
}
```

#### Event ID 4768 - Kerberos TGT Request
```json
{
    "event": {
        "EVENT": {
            "EventData": {
                "IpAddress": "::ffff:10.0.0.19",
                "IpPort": "57077",
                "PreAuthType": "2",
                "ServiceName": "krbtgt",
                "TargetDomainName": "EXAMPLE",
                "TargetUserName": "admin.user",
                "TicketEncryptionType": "0x12",
                "TicketOptions": "0x40810010"
            },
            "System": {
                "Channel": "Security",
                "Computer": "DC02.example.corp",
                "EventID": "4768"
            }
        }
    },
    "routing": {
        "event_type": "WEL",
        "hostname": "DC02.example.corp",
        "plat": 268435456
    }
}
```

#### Event ID 4624 - Successful Logon
```json
{
    "event": {
        "EVENT": {
            "EventData": {
                "AuthenticationPackageName": "Kerberos",
                "IpAddress": "10.0.0.70",
                "IpPort": "52496",
                "LogonType": "3",
                "TargetDomainName": "EXAMPLE.LOCAL",
                "TargetUserName": "jsmith",
                "TargetUserSid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
                "WorkstationName": "-"
            },
            "System": {
                "Channel": "Security",
                "Computer": "SERVER01.example.local",
                "EventID": "4624"
            }
        }
    },
    "routing": {
        "event_type": "WEL",
        "hostname": "SERVER01.example.local",
        "plat": 268435456
    }
}
```

### Sysmon Events
Sysmon events are specialized Windows Event Log entries from the System Monitor service that provides detailed information about process creation, network connections, and other security-relevant activities.

#### Sysmon Event ID 1 - Process Creation
```json
{
  "event": {
    "EVENT": {
      "EventData": {
        "CommandLine": "\"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\" /c",
        "Company": "Microsoft Corporation",
        "CurrentDirectory": "C:\\Windows\\system32\\",
        "Description": "Microsoft Edge Update",
        "FileVersion": "1.3.135.41",
        "Hashes": "MD5=8661FBB97161096BE503CD295AA46409,SHA256=BEF9DBED290AF17CF3F30CC43FC0A94CDADC540F171C25DF1363B2E852D0A042,IMPHASH=30AD68B9DC9737D8C720DD9284051ADD",
        "Image": "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe",
        "IntegrityLevel": "System",
        "LogonGuid": "{2e1d7508-65ef-6882-e703-000000000000}",
        "LogonId": "0x3e7",
        "OriginalFileName": "msedgeupdate.dll",
        "ParentCommandLine": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule",
        "ParentImage": "C:\\Windows\\System32\\svchost.exe",
        "ParentProcessGuid": "{2e1d7508-65f0-6882-2a00-000000000800}",
        "ParentProcessId": "1768",
        "ParentUser": "NT AUTHORITY\\SYSTEM",
        "ProcessGuid": "{2e1d7508-6acf-6882-9204-000000000800}",
        "ProcessId": "5568",
        "Product": "Microsoft Edge Update",
        "RuleName": "-",
        "TerminalSessionId": "0",
        "User": "NT AUTHORITY\\SYSTEM",
        "UtcTime": "2025-07-24 17:18:07.837"
      },
      "System": {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "FS-01.example.corp",
        "EventID": "1",
        "EventRecordID": "1346",
        "Provider": {
          "Name": "Microsoft-Windows-Sysmon"
        }
      }
    }
  },
  "routing": {
    "event_type": "WEL",
    "hostname": "FS-01.example.corp",
    "plat": 268435456
  }
}
```

#### Sysmon Event ID 2 - File Creation Time Changed
```json
{
  "event": {
    "EVENT": {
      "EventData": {
        "CreationUtcTime": "2025-07-24 18:24:11.703",
        "Image": "C:\\Windows\\system32\\cleanmgr.exe",
        "PreviousCreationUtcTime": "2025-07-24 18:24:11.703",
        "ProcessGuid": "{7d2d41cb-7a4a-6882-1a03-000000000600}",
        "ProcessId": "3540",
        "RuleName": "T1099",
        "TargetFilename": "C:\\Users\\user1\\AppData\\Local\\Temp\\50EFA3E9-EBA2-48C2-8D7F-7961D7696110\\DismHost.exe",
        "User": "EXAMPLE\\user1",
        "UtcTime": "2025-07-24 18:24:43.790"
      },
      "System": {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "WS-07.example.corp",
        "EventID": "2"
      }
    }
  },
  "routing": {
    "event_type": "WEL",
    "hostname": "WS-07.example.corp",
    "plat": 268435456
  }
}
```

#### Sysmon Event ID 3 - Network Connection
```json
{
  "event": {
    "EVENT": {
      "EventData": {
        "DestinationHostname": "-",
        "DestinationIp": "203.0.113.100",
        "DestinationIsIpv6": "false",
        "DestinationPort": "443",
        "DestinationPortName": "https",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "Initiated": "true",
        "ProcessGuid": "{2e1d7508-65f5-6882-5b00-000000000800}",
        "ProcessId": "4088",
        "Protocol": "tcp",
        "RuleName": "-",
        "SourceHostname": "FS-01.example.corp",
        "SourceIp": "10.0.0.208",
        "SourceIsIpv6": "false",
        "SourcePort": "60577",
        "SourcePortName": "-",
        "User": "NT AUTHORITY\\SYSTEM",
        "UtcTime": "2025-07-24 17:11:23.544"
      },
      "System": {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "FS-01.example.corp",
        "EventID": "3"
      }
    }
  },
  "routing": {
    "event_type": "WEL",
    "hostname": "FS-01.example.corp",
    "plat": 268435456
  }
}
```

#### Sysmon Event ID 5 - Process Terminated
```json
{
  "event": {
    "EVENT": {
      "EventData": {
        "Image": "C:\\Users\\user2\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
        "ProcessGuid": "{7d2d41cb-63b9-6882-2101-000000000600}",
        "ProcessId": "6120",
        "RuleName": "-",
        "User": "EXAMPLE\\user2",
        "UtcTime": "2025-07-24 17:08:55.023"
      },
      "System": {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "WS-05.example.corp",
        "EventID": "5"
      }
    }
  },
  "routing": {
    "event_type": "WEL",
    "hostname": "WS-05.example.corp",
    "plat": 268435456
  }
}
```

#### Sysmon Event ID 7 - Image/DLL Loaded
```json
{
  "event": {
    "EVENT": {
      "EventData": {
        "Company": "Microsoft Corporation",
        "Description": "Windows Socket 2.0 32-Bit DLL",
        "FileVersion": "10.0.19041.1 (WinBuild.160101.0800)",
        "Hashes": "MD5=E4D8F39C40026BEFC5B014F60CA5D668,SHA256=1CF97A5FB2DC48C5443E7DBDAD421AC48B5C5EC946E74F0506E39DD9B9F5A9BB,IMPHASH=DEBC04AC93FA32D5E6D1DDB9875E7B8C",
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ImageLoaded": "C:\\Windows\\System32\\ws2_32.dll",
        "OriginalFileName": "ws2_32.dll",
        "ProcessGuid": "{2e1d7508-65f5-6882-5b00-000000000800}",
        "ProcessId": "4088",
        "Product": "Microsoft® Windows® Operating System",
        "RuleName": "-",
        "Signature": "Microsoft Windows",
        "SignatureStatus": "Valid",
        "Signed": "true",
        "User": "NT AUTHORITY\\SYSTEM",
        "UtcTime": "2025-07-24 17:11:21.234"
      },
      "System": {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "FS-01.example.corp",
        "EventID": "7"
      }
    }
  },
  "routing": {
    "event_type": "WEL",
    "hostname": "FS-01.example.corp",
    "plat": 268435456
  }
}
```

#### Sysmon Event ID 8 - CreateRemoteThread
```json
{
  "event": {
    "EVENT": {
      "EventData": {
        "NewThreadId": "8704",
        "RuleName": "-",
        "SourceImage": "<unknown process>",
        "SourceProcessGuid": "{7d2d41cb-6305-6882-0900-000000000600}",
        "SourceProcessId": "492",
        "SourceUser": "NT AUTHORITY\\SYSTEM",
        "StartAddress": "0x00007FFB8E09B880",
        "StartFunction": "CtrlRoutine",
        "StartModule": "C:\\Windows\\System32\\KERNELBASE.dll",
        "TargetImage": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "TargetProcessGuid": "{7d2d41cb-649f-6882-7401-000000000600}",
        "TargetProcessId": "1476",
        "TargetUser": "EXAMPLE\\user2",
        "UtcTime": "2025-07-24 17:08:55.198"
      },
      "System": {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "WS-05.example.corp",
        "EventID": "8"
      }
    }
  },
  "routing": {
    "event_type": "WEL",
    "hostname": "WS-05.example.corp",
    "plat": 268435456
  }
}
```

#### Sysmon Event ID 10 - Process Access
```json
{
  "event": {
    "EVENT": {
      "EventData": {
        "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9f9a4|C:\\Windows\\System32\\KERNELBASE.dll+793a6|c:\\windows\\system32\\lsm.dll+d7e6|C:\\Windows\\System32\\RPCRT4.dll+768f3|C:\\Windows\\System32\\RPCRT4.dll+da7d9|C:\\Windows\\System32\\RPCRT4.dll+5dcfc|C:\\Windows\\System32\\RPCRT4.dll+5a9c2|C:\\Windows\\System32\\RPCRT4.dll+3814f|C:\\Windows\\System32\\RPCRT4.dll+37a88|C:\\Windows\\System32\\RPCRT4.dll+43fac|C:\\Windows\\System32\\RPCRT4.dll+43417|C:\\Windows\\System32\\RPCRT4.dll+42aad|C:\\Windows\\System32\\RPCRT4.dll+42781|C:\\Windows\\System32\\RPCRT4.dll+423b7|C:\\Windows\\System32\\RPCRT4.dll+46ad9|C:\\Windows\\SYSTEM32\\ntdll.dll+7ad0|C:\\Windows\\SYSTEM32\\ntdll.dll+b8e8|C:\\Windows\\System32\\KERNEL32.DLL+14de0|C:\\Windows\\SYSTEM32\\ntdll.dll+7e44b",
        "GrantedAccess": "0x1000",
        "RuleName": "-",
        "SourceImage": "C:\\Windows\\system32\\svchost.exe",
        "SourceProcessGUID": "{2e1d7508-65ef-6882-1100-000000000800}",
        "SourceProcessId": "900",
        "SourceThreadId": "2324",
        "SourceUser": "NT AUTHORITY\\SYSTEM",
        "TargetImage": "C:\\Windows\\system32\\lsass.exe",
        "TargetProcessGUID": "{2e1d7508-65ef-6882-0c00-000000000800}",
        "TargetProcessId": "612",
        "TargetUser": "NT AUTHORITY\\SYSTEM",
        "UtcTime": "2025-07-24 17:17:21.845"
      },
      "System": {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "FS-01.example.corp",
        "EventID": "10"
      }
    }
  },
  "routing": {
    "event_type": "WEL",
    "hostname": "FS-01.example.corp",
    "plat": 268435456
  }
}
```

#### Sysmon Event ID 11 - File Created
```json
{
  "event": {
    "EVENT": {
      "EventData": {
        "CreationUtcTime": "2025-07-24 17:34:15.829",
        "Image": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "ProcessGuid": "{7d2d41cb-6c46-6882-7a01-000000000600}",
        "ProcessId": "5932",
        "RuleName": "-",
        "TargetFilename": "C:\\Users\\USER3~1\\AppData\\Local\\Temp\\5932_1645556261\\_platform_specific\\win_x64\\widevinecdm.dll",
        "User": "EXAMPLE\\user3",
        "UtcTime": "2025-07-24 17:34:15.829"
      },
      "System": {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "WS-09.example.corp",
        "EventID": "11"
      }
    }
  },
  "routing": {
    "event_type": "WEL",
    "hostname": "WS-09.example.corp",
    "plat": 268435456
  }
}
```

#### Sysmon Event ID 13 - Registry Value Set
```json
{
  "event": {
    "EVENT": {
      "EventData": {
        "Details": "LimaCharlie",
        "EventType": "SetValue",
        "Image": "C:\\Windows\\system32\\compattelrunner.exe",
        "ProcessGuid": "{2e1d7508-6948-6882-8d04-000000000800}",
        "ProcessId": "2296",
        "RuleName": "InvDB-Pub",
        "TargetObject": "\\REGISTRY\\A\\{dc48c367-820e-664e-02ca-f3fea4d29c26}\\Root\\InventoryApplication\\000030a06cd4ccda9d4b3846fd844441b08400000904\\Publisher",
        "User": "NT AUTHORITY\\SYSTEM",
        "UtcTime": "2025-07-24 17:11:37.153"
      },
      "System": {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "FS-01.example.corp",
        "EventID": "13"
      }
    }
  },
  "routing": {
    "event_type": "WEL",
    "hostname": "FS-01.example.corp",
    "plat": 268435456
  }
}
```

#### Sysmon Event ID 17 - Pipe Created
```json
{
  "event": {
    "EVENT": {
      "EventData": {
        "EventType": "CreatePipe",
        "Image": "C:\\Windows\\System32\\svchost.exe",
        "PipeName": "\\wkssvc",
        "ProcessGuid": "{2e1d7508-65ef-6882-1100-000000000800}",
        "ProcessId": "900",
        "RuleName": "-",
        "User": "NT AUTHORITY\\SYSTEM",
        "UtcTime": "2025-07-24 17:15:45.123"
      },
      "System": {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "FS-01.example.corp",
        "EventID": "17"
      }
    }
  },
  "routing": {
    "event_type": "WEL",
    "hostname": "FS-01.example.corp",
    "plat": 268435456
  }
}
```

#### Sysmon Event ID 18 - Pipe Connected
```json
{
  "event": {
    "EVENT": {
      "EventData": {
        "EventType": "ConnectPipe",
        "Image": "C:\\Windows\\System32\\net.exe",
        "PipeName": "\\wkssvc",
        "ProcessGuid": "{2e1d7508-6af2-6882-8f04-000000000800}",
        "ProcessId": "3892",
        "RuleName": "-",
        "User": "EXAMPLE\\admin",
        "UtcTime": "2025-07-24 17:15:45.234"
      },
      "System": {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "FS-01.example.corp",
        "EventID": "18"
      }
    }
  },
  "routing": {
    "event_type": "WEL",
    "hostname": "FS-01.example.corp",
    "plat": 268435456
  }
}
```

#### Sysmon Event ID 22 - DNS Query
```json
{
  "event": {
    "EVENT": {
      "EventData": {
        "Image": "C:\\Windows\\System32\\rphcp.exe",
        "ProcessGuid": "{2e1d7508-6928-6882-8c04-000000000800}",
        "ProcessId": "2212",
        "QueryName": "suspicious-domain.example.com",
        "QueryResults": "127.0.0.1;",
        "QueryStatus": "0",
        "RuleName": "-",
        "User": "NT AUTHORITY\\SYSTEM",
        "UtcTime": "2025-07-24 17:16:11.049"
      },
      "System": {
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Computer": "FS-01.example.corp",
        "EventID": "22"
      }
    }
  },
  "routing": {
    "event_type": "WEL",
    "hostname": "FS-01.example.corp",
    "plat": 268435456
  }
}
```

## Azure/O365 Events

### NonInteractiveUserSignInLogs
Non-interactive (refresh token) sign-ins to Azure AD.

```json
{
    "event": {
        "Level": 4,
        "callerIpAddress": "203.0.113.10",
        "category": "NonInteractiveUserSignInLogs",
        "correlationId": "00000000-0000-0000-0000-000000000001",
        "identity": "John Doe",
        "location": "US",
        "operationName": "Sign-in activity",
        "properties": {
            "appDisplayName": "Azure Portal",
            "appId": "00000000-0000-0000-0000-000000000002",
            "authenticationRequirement": "multiFactorAuthentication",
            "clientAppUsed": "Browser",
            "conditionalAccessStatus": "notApplied",
            "deviceDetail": {
                "browser": "Firefox 139.0",
                "operatingSystem": "Windows10"
            },
            "ipAddress": "203.0.113.10",
            "isInteractive": false,
            "location": {
                "city": "Anytown",
                "countryOrRegion": "US",
                "state": "State"
            },
            "status": {
                "errorCode": 0
            },
            "userDisplayName": "John Doe",
            "userPrincipalName": "john.doe@example.com"
        }
    },
    "routing": {
        "event_type": "NonInteractiveUserSignInLogs",
        "hostname": "adapter-azure-signinlogs",
        "plat": 352321536
    }
}
```

### SignInLogs
Interactive user sign-in attempts (successful and failed).

```json
{
    "event": {
        "Level": 4,
        "callerIpAddress": "198.51.100.20",
        "category": "SignInLogs",
        "identity": "Jane Smith",
        "location": "US",
        "operationName": "Sign-in activity",
        "properties": {
            "appDisplayName": "Azure Portal",
            "authenticationDetails": [
                {
                    "authenticationMethod": "Password",
                    "authenticationStepResultDetail": "Invalid username or password or Invalid on-premise username or password.",
                    "succeeded": false
                }
            ],
            "clientAppUsed": "Browser",
            "deviceDetail": {
                "browser": "Firefox 139.0",
                "operatingSystem": "MacOs"
            },
            "ipAddress": "198.51.100.20",
            "isInteractive": true,
            "status": {
                "errorCode": 50126,
                "failureReason": "Invalid username or password or Invalid on-premise username or password."
            },
            "userPrincipalName": "jane.smith@example.com"
        },
        "resultType": "50126"
    },
    "routing": {
        "event_type": "SignInLogs",
        "hostname": "adapter-azure-signinlogs",
        "plat": 352321536
    }
}
```

### Administrative
Azure administrative actions and resource management.

```json
{
    "event": {
        "callerIpAddress": "192.0.2.30",
        "category": "Administrative",
        "correlationId": "00000000-0000-0000-0000-000000000003",
        "identity": {
            "authorization": {
                "action": "Microsoft.SerialConsole/serialPorts/connect/action",
                "scope": "/subscriptions/00000000-0000-0000-0000-000000000004/resourcegroups/Example-RG/providers/Microsoft.Compute/virtualMachines/VM-Example/providers/Microsoft.SerialConsole/serialPorts/0"
            },
            "claims": {
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "admin@example.com",
                "ipaddr": "192.0.2.30"
            }
        },
        "operationName": "MICROSOFT.SERIALCONSOLE/SERIALPORTS/CONNECT/ACTION",
        "properties": {
            "statusCode": "OK"
        },
        "resourceId": "/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000004/RESOURCEGROUPS/EXAMPLE-RG/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/VM-EXAMPLE",
        "resultSignature": "Succeeded.OK",
        "resultType": "Success"
    },
    "routing": {
        "event_type": "Administrative",
        "hostname": "adapter-azure-activity_logs",
        "plat": 352321536
    }
}
```

### Add-MailboxPermission
Exchange mailbox permission modifications.

```json
{
    "event": {
        "ClientIP": "192.0.2.40:30129",
        "CreationTime": "2025-05-20T17:22:44",
        "ObjectId": "Test User",
        "Operation": "Add-MailboxPermission",
        "OrganizationName": "example.onmicrosoft.com",
        "Parameters": [
            {
                "Name": "Identity",
                "Value": "00000000-0000-0000-0000-000000000005"
            },
            {
                "Name": "User",
                "Value": "00000000-0000-0000-0000-000000000006"
            },
            {
                "Name": "AccessRights",
                "Value": "FullAccess"
            }
        ],
        "ResultStatus": "True",
        "UserId": "user@example.com",
        "Workload": "Exchange"
    },
    "routing": {
        "event_type": "Add-MailboxPermission",
        "hostname": "adapter-o365",
        "plat": 3758096384
    }
}
```

### UserLoggedIn
Successful user authentication to O365/Azure AD.

```json
{
    "event": {
        "ActorIpAddress": "203.0.113.50",
        "ApplicationId": "00000000-0000-0000-0000-000000000007",
        "ClientIP": "203.0.113.50",
        "CreationTime": "2025-05-20T18:47:59",
        "DeviceProperties": [
            {
                "Name": "DisplayName",
                "Value": "DEVICE-001"
            },
            {
                "Name": "IsCompliant",
                "Value": "True"
            }
        ],
        "ObjectId": "00000000-0000-0000-0000-000000000008",
        "Operation": "UserLoggedIn",
        "ResultStatus": "Success",
        "UserId": "kelly.user@example.com",
        "Workload": "AzureActiveDirectory"
    },
    "routing": {
        "event_type": "UserLoggedIn",
        "hostname": "adapter-o365",
        "plat": 3758096384
    }
}
```

### Consent to application
OAuth application consent grants.

```json
{
    "event": {
        "ActorContextId": "00000000-0000-0000-0000-000000000009",
        "CreationTime": "2025-06-16T13:53:48",
        "ModifiedProperties": [
            {
                "Name": "ConsentContext.IsAdminConsent",
                "NewValue": "True"
            },
            {
                "Name": "ConsentAction.Permissions",
                "NewValue": "[] => [[Id: AAAAAAAAAAAAAAAAAAAAAIQuTnhXlT1NpRiARvdFTeQ, ClientId: 00000000-0000-0000-0000-000000000000, PrincipalId: , ResourceId: 00000000-0000-0000-0000-000000000010, ConsentType: AllPrincipals, Scope:  openid profile email User.Read offline_access]]"
            }
        ],
        "ObjectId": "00000000-0000-0000-0000-000000000011",
        "Operation": "Consent to application.",
        "ResultStatus": "Success",
        "Target": [
            {
                "ID": "ExampleApp",
                "Type": 1
            }
        ],
        "UserId": "chris.user@example.com",
        "Workload": "AzureActiveDirectory"
    },
    "routing": {
        "event_type": "Consent to application.",
        "hostname": "adapter-o365",
        "plat": 3758096384
    }
}
```

### UserLoginFailed
Failed authentication attempts.

```json
{
    "event": {
        "ActorIpAddress": "198.51.100.60",
        "ApplicationId": "00000000-0000-0000-0000-000000000012",
        "ClientIP": "198.51.100.60",
        "CreationTime": "2025-06-16T19:20:08",
        "ErrorNumber": "50155",
        "LogonError": "DeviceAuthenticationFailed",
        "Operation": "UserLoginFailed",
        "ResultStatus": "Failed",
        "UserId": "terry@example.com",
        "Workload": "AzureActiveDirectory"
    },
    "routing": {
        "event_type": "UserLoginFailed",
        "hostname": "adapter-o365",
        "plat": 3758096384
    }
}
```

### Set-MailboxAuditBypassAssociation
Mailbox audit bypass configuration changes.

```json
{
    "event": {
        "ClientIP": "192.0.2.70:45186",
        "CreationTime": "2025-07-07T14:14:04",
        "ObjectId": "testuser",
        "Operation": "Set-MailboxAuditBypassAssociation",
        "OrganizationName": "example.onmicrosoft.com",
        "Parameters": [
            {
                "Name": "Identity",
                "Value": "john.doe@example.com"
            },
            {
                "Name": "AuditBypassEnabled",
                "Value": "True"
            }
        ],
        "ResultStatus": "True",
        "UserId": "john.doe@example.com",
        "Workload": "Exchange"
    },
    "routing": {
        "event_type": "Set-MailboxAuditBypassAssociation",
        "hostname": "adapter-o365",
        "plat": 3758096384
    }
}
```

### AlertTriggered
Security and compliance alerts.

```json
{
    "event": {
        "AlertId": "00000000-0000-0000-0000-000000000013",
        "AlertType": "System",
        "Category": "ThreatManagement",
        "CreationTime": "2025-07-08T16:01:29",
        "Data": "{\"als\":\"Protection\",\"op\":\"Protection\",\"ad\":\"Malicious emails were delivered and later removed -V1.0.0.2\",\"an\":\"Email messages removed after delivery\",\"sev\":\"Informational\"}",
        "Name": "Email messages removed after delivery",
        "Operation": "AlertTriggered",
        "ResultStatus": "Succeeded",
        "Severity": "Informational",
        "Source": "Office 365 Security & Compliance",
        "Status": "Active",
        "UserId": "SecurityComplianceAlerts",
        "Workload": "SecurityComplianceCenter"
    },
    "routing": {
        "event_type": "AlertTriggered",
        "hostname": "adapter-o365",
        "plat": 3758096384
    }
}
```

## Using Sample Events

### In Detection Rules
Reference these event structures when creating detection rules:

```yaml
# Example: Detect suspicious svchost.exe without proper parent
op: and
rules:
  - op: is
    path: event_type
    value: NEW_PROCESS
  - op: contains
    path: event.FILE_PATH
    value: svchost.exe
  - op: not
    path: event.PARENT.FILE_PATH
    value: services.exe
```

### In LCQL Queries
Use the field paths from these samples in your LCQL queries:

```lcql
# Find failed logons from specific IP ranges
-1h | plat==windows | WEL | event/EVENT/System/EventID == "4625" AND event/EVENT/EventData/IpAddress contains "10." | event/EVENT/EventData/TargetUserName as User event/EVENT/EventData/IpAddress as IP
```

### With AI Generation
When using the AI generation tools, reference specific event types:

```python
# Generate detection for suspicious mailbox permissions
detection = generate_dr_rule_detection(
    description="Detect Add-MailboxPermission with FullAccess rights granted to external users"
)
```

## Field Path Reference

### Common Windows Event Paths
- `event.FILE_PATH` - Process executable path
- `event.COMMAND_LINE` - Full command line
- `event.PARENT.FILE_PATH` - Parent process path
- `event.HASH` - File hash (SHA256)
- `event.USER_NAME` - Process user context
- `event.FILE_IS_SIGNED` - Code signing status (0/1)
- `event.REGISTRY_KEY` - Registry key path (REGISTRY_WRITE events)
- `event.REGISTRY_VALUE` - Registry value data (REGISTRY_WRITE events)
- `event.PROCESS_ID` - Process ID performing the action

### Common WEL Paths
- `event.EVENT.System.EventID` - Windows Event ID
- `event.EVENT.System.Computer` - Source computer name
- `event.EVENT.EventData.*` - Event-specific data fields

### Common Sysmon Event Paths
- `event.EVENT.System.EventID` - Sysmon Event ID (1, 3, 5, 8, 10, 13, 22, etc.)
- `event.EVENT.System.Channel` - Always "Microsoft-Windows-Sysmon/Operational"
- `event.EVENT.EventData.ProcessGuid` - Unique process identifier
- `event.EVENT.EventData.Image` - Process executable path
- `event.EVENT.EventData.CommandLine` - Full command line (Event ID 1)
- `event.EVENT.EventData.Hashes` - File hashes (MD5, SHA256, IMPHASH)
- `event.EVENT.EventData.ParentProcessGuid` - Parent process GUID
- `event.EVENT.EventData.TargetImage` - Target process for access/injection
- `event.EVENT.EventData.DestinationIp` - Network destination IP (Event ID 3)
- `event.EVENT.EventData.DestinationPort` - Network destination port (Event ID 3)
- `event.EVENT.EventData.QueryName` - DNS query name (Event ID 22)
- `event.EVENT.EventData.CallTrace` - Stack trace for process access (Event ID 10)
- `event.EVENT.EventData.TargetFilename` - File being timestomped (Event ID 2), File created (Event ID 11)
- `event.EVENT.EventData.CreationUtcTime` - File creation time (Event ID 2, 11)
- `event.EVENT.EventData.PreviousCreationUtcTime` - Original creation time (Event ID 2)
- `event.EVENT.EventData.ImageLoaded` - DLL path being loaded (Event ID 7)
- `event.EVENT.EventData.Signature` - DLL signature info (Event ID 7)
- `event.EVENT.EventData.SignatureStatus` - Valid/Invalid signature (Event ID 7)
- `event.EVENT.EventData.PipeName` - Named pipe path (Event ID 17, 18)
- `event.EVENT.EventData.EventType` - CreatePipe or ConnectPipe (Event ID 17, 18)

### Common O365/Azure Paths
- `event.Operation` - Activity name
- `event.UserId` - User performing action
- `event.ClientIP` - Source IP address
- `event.ResultStatus` - Success/Failed
- `event.Parameters` - Operation parameters array