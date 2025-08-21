
## 1. 事件日志基础

`Windows Event Logs` 是 Windows 操作系统的固有部分，存储来自系统不同组件的日志，包括系统本身、在其上运行的应用程序、ETW 提供程序、服务等。Windows 事件日志记录提供了针对应用程序错误、安全事件和诊断信息的全面日志记录功能。作为网络安全专业人员，我们广泛利用这些日志进行分析和入侵检测。日志被分类为不同的事件日志，例如“应用程序”、“系统”、“安全”等，以根据事件的来源或目的来组织事件。可以使用 `Event Viewer` 应用程序或使用 API（例如 Windows 事件日志 API）以编程方式访问事件日志。以管理用户身份访问 `Windows Event Viewer` 允许我们探索各种可用的日志。

默认 Windows 事件日志由 `Application` 、 `Security` 、 `Setup` 、 `System` 和 `Forwarded Events` 组成。虽然前四个日志涵盖应用程序错误、安全事件、系统设置活动和一般系统信息，但“转发的事件”部分是独特的，显示从其他计算机转发的事件日志数据。事实证明，这种中央日志记录功能对于需要统一视图的系统管理员来说非常有价值。在我们当前的分析中，我们关注来自单台机器的事件日志。应该注意的是，Windows 事件查看器能够打开并显示以前保存的 `.evtx` 文件，这些文件可以在“保存的日志”部分中找到。

### 事件日志剖析 Anatomy

`Application`

在检查 `Application` 日志时，我们遇到两个不同级别的事件： `information` 和 `error` 。`information`事件提供有关应用程序的一般使用详细信息，例如其启动或停止事件。相反， `error`事件突出显示特定错误，并且通常提供对遇到的问题的详细见解。

Windows 事件日志中的每个条目都是一个“事件”，并包含以下主要组件：日志名称，记录事件的软件，事件ID，事件目的或用途，事件的严重性。

在过滤特定类型事件的事件日志时， `Keywords` 字段特别有用。通过允许我们指定感兴趣的事件，它可以显着提高搜索查询的精度，从而使日志管理更加高效和有效。

仔细查看上面的事件日志，我们观察到几个关键元素。左上角的 `Event ID` 作为唯一标识符，可以在 Microsoft 网站上进一步研究以收集其他信息。事件 ID 旁边的“SideBySide”标签表示事件源。下面，我们找到一般错误描述，通常包含丰富的详细信息。通过单击详细信息，我们可以使用 XML 或格式良好的视图进一步分析事件的影响。此外，我们还可以从事件日志中提取补充信息，例如发生错误的进程ID，从而实现更精确的分析。

`Security`

将我们的注意力转移到`security`日志上，让我们考虑事件 ID 4624，这是一个常见的事件（详细信息请参见 https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624）。根据 Microsoft 的文档，此事件表示在目标计算机上创建登录会话，该登录会话源自建立会话的被访问计算机。在此日志中，我们找到了重要的详细信息，包括“登录 ID”，它允许我们将此登录与共享相同“登录 ID”的其他事件关联起来。另一个重要的细节是“登录类型”，指示登录的类型。在本例中，它指定了服务登录类型，表明“SYSTEM”启动了新服务。然而，需要利用关联技术和“登录 ID”等附加数据进行进一步调查，以确定所涉及的具体服务。

### 利用自定义XML查询 Queries

```powershell

*[EventData[Data[@Name='ProcessID']='1234']]

```

### 有用的Windows事件日志 

> System Logs:

`1074`: System Shutdown/Restart，系统关闭或重启

`6005`: Event log service was started，事件日志服务启动

`6006`: Event log service was stopped，事件日志服务关闭

`6013`: Windows uptime，系统正常运行时间

`7040`: Service status change，服务启动类型发生更改


> Security Logs:

`1102`：审计日志被清除；

`1116`：检测到恶意软件；`1118`：删除或者隔离检测到的恶意软件；

`1119`：删除隔离恶意软件工作已完成；`1120`：删除隔离恶意软件失败；

`4624`：成功的登录事件；`4625`：失败的登录尝试；

`4648`：显式凭据登录以运行程序；

`4656`：请求对象的句柄；

`4672`：超级用户登录；

`4698`：创建计划任务触发；`4700&4701`：计划任务启动或禁用；`4702`：计划任务更新；

`4719`：审核策略的更改；

`4738`：用户账户的更改；

`4771`：失败的Kerberos身份验证；`4776`：跟踪DC进行凭据验证的尝试；

`5001`：Defender实时防护已更改；

`5140`：访问已知的网络共享；`5142`：创建新的网络共享；`5145`：尝试访问未知的网络共享；

`5157`：Windows过滤器阻止连接；

`7045`: 未知服务的安装；



## 2. 使用Sysmon与Event Logs分析可疑活动

### Sysmon 基础

在调查恶意事件时，多个事件 ID 可以作为常见的危害指标。例如， `Event ID 4624` 提供对新登录事件的洞察，使我们能够监控和检测可疑的用户访问和登录模式。同样， `Event ID 4688` 提供有关新创建进程的信息，帮助识别异常或恶意进程启动。为了增强事件日志覆盖范围，我们可以通过合并 Sysmon 来扩展功能，Sysmon 提供额外的事件日志记录功能。	

`System Monitor (Sysmon)` 是 Windows 系统服务和设备驱动程序，在系统重新启动后仍驻留以监视系统活动并将其记录到 Windows 事件日志中。 Sysmon 提供有关进程创建、网络连接、文件创建时间更改等的详细信息。

`Sysmon` 的主要组件包括：

- 用于监视系统活动的 Windows 服务; 
- 帮助捕获系统活动数据的设备驱动程序; 
- 用于显示捕获的活动数据的事件日志。

Sysmon 的独特功能在于它能够记录通常不会出现在安全事件日志中的信息，这使其成为深度系统监控和网络安全取证分析的强大工具。Sysmon 使用事件 ID 对不同类型的系统活动进行分类，其中每个 ID 对应于特定类型的事件。例如， `Event ID 1` 对应“进程创建”事件， `Event ID 3` 指“网络连接”事件。 Sysmon 事件 ID 的完整列表可以在此处找到。

- 参考链接/下载链接：https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

为了更精细地控制记录的事件，Sysmon 使用基于 `XML` 的配置文件。配置文件允许您根据`进程名称`、`IP 地址`等不同属性包含或排除某些类型的事件。我们可以参考有用的 Sysmon 配置文件的流行示例：

- 如需全面的配置，我们可以访问：https://github.com/SwiftOnSecurity/sysmon-config

- 另一个选择是：https://github.com/olafhartong/sysmon-modular，它提供了模块化方法

下载后，打开管理员命令提示符并执行以下命令来安装 Sysmon：（Sysmon for Linux 也存在）

```powershell
# 安装sysmon
sysmon.exe -i -accepteula -h md5,sha256,imphash -l -n

# 安装后的sysmon自定义配置
sysmon.exe -c filename.xml
```

### Sysmon检测DLL劫持

> Event Type 7

下载配置文件，并修改xml的模块`ImageLoad`，将Include更改为Exclude，以确保捕获必要的数据。

利用更新的sysmon配置，执行下列命令：

```powershell
sysmon.exe -c sysmonconfig-export.xml
```

要查看这些`ImageLoad`事件，请导航到`EventViewer`并访问“应用程序和服务”->“Microsoft”->“Windows”->“Sysmon”。快速检查将显示目标事件 ID 是否存在。

事件日志包含 DLL 的签名状态（在本例中为 Microsoft 签名）、负责加载 DLL 的进程或映像以及已加载的特定 DLL。在我们的示例中，我们观察到“MMC.exe”加载了“psapi.dll”，它也是 Microsoft 签名的。这两个文件都位于 System32 目录中。

现在，让我们继续构建检测机制。为了更深入地了解 DLL 劫持，进行研究至关重要。我们偶然发现了一篇内容丰富的博客文章，https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows，其中提供了各种 DLL 劫持技术的详尽列表。出于检测目的，我们将重点关注涉及易受攻击的可执行文件 calc.exe 的特定劫持以及可劫持的 DLL 列表。

利用此DLL与calc.exe，https://github.com/stephenfewer/ReflectiveDLLInjection/tree/master/bin，将 `reflective_dll.x64.dll` 重命名为 `WININET.dll`，与calc.exe一起放入可写Desktop目录，并执行calc.exe，检查劫持效果与影响。

通过过滤当前事件日志，关注Event ID 7，随后我们通过`Find`功能查找`calc.exe`，识别与我们劫持相关的DLL。让我们探讨一下IOC妥协指标，

- calc.exe应当在指定目录，不应在可写目录找到
- DLL所在位置
- WININET.dll未签名

### Sysmon检测非托管PowerShell/C#注入

> Event Type 7

额外检测工具：Process Hacker



### Sysmon检测凭证转储

凭证转储工具：mimikatz.exe

> Event ID 10: Process Access





事件ID 10： Process Access

----

>  额外的遥测源

## 3. Windows事件追踪介绍 (ETW) 

What is ETW

ETW Architecture & Components

Interacting With ETW: 

1. Logman
2. Perfmon

Useful Providers

Restricted Providers

### 4. 进军ETW

1）检测奇怪的父子关系 Detecting Strange Parent-Child Relationships: 

执行父PID欺骗Spoofing：psgetsystem

```powershell
powershell -ep bypass
Import-Module .\psgetsys.ps1 
# 
[MyProcess]::CreateProcessFromParent([Process ID of spoolsv.exe],"C:\Windows\System32\cmd.exe","")
```



检查深度的父子关系：Process Hacker、SilkETW

```powershell
logman.exe query providers | findstr "Process"
```



```powershell
SilkETW.exe -t user -pn Microsoft-Windows-Kernel-Process -ot file -p C:\windows\temp\etw.json
```



2）检测恶意.NE程序集加载 Detecting Malicious .NET Assembly Loading

.NET环境检测

模拟.NET程序集：Seatbelt

检查ImageLoaded：Sysmon

检查深度的ETW：

```powershell
SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\windows\temp\etw.json
```



### 5. Get-WinEvent



```powershell
# 检索所有日志列表
Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsClassicLog, IsEnabled, LogMode, LogType | Format-Table -AutoSize

# 检索事件日志列表
Get-WinEvent -ListProvider * | Format-Table -AutoSize

# 从系统日志中检索事件
Get-WinEvent -LogName 'System' -MaxEvents 50 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

# 从 Microsoft-Windows-WinRM/Operational 检索事件
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 30 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

# 搜索最近的
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -Oldest -MaxEvents 30 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

# 从.evtx文件中检索事件
Get-WinEvent -Path 'C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\exec_sysmon_1_lolbin_pcalua.evtx' -MaxEvents 5 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

# 使用 FilterHashtable 过滤事件
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize
# 基于日期进行过滤
$startDate = (Get-Date -Year 2023 -Month 5 -Day 28).Date
$endDate   = (Get-Date -Year 2023 -Month 6 -Day 3).Date
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3; StartTime=$startDate; EndTime=$endDate} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

# 
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=3} |
`ForEach-Object {
$xml = [xml]$_.ToXml()
$eventData = $xml.Event.EventData.Data
New-Object PSObject -Property @{
    SourceIP = $eventData | Where-Object {$_.Name -eq "SourceIp"} | Select-Object -ExpandProperty '#text'
    DestinationIP = $eventData | Where-Object {$_.Name -eq "DestinationIp"} | Select-Object -ExpandProperty '#text'
    ProcessGuid = $eventData | Where-Object {$_.Name -eq "ProcessGuid"} | Select-Object -ExpandProperty '#text'
    ProcessId = $eventData | Where-Object {$_.Name -eq "ProcessId"} | Select-Object -ExpandProperty '#text'
}
}  | Where-Object {$_.DestinationIP -eq "52.113.194.132"}

```





检测恶意DLL加载

```powershell
# 
$Query = @"
	<QueryList>
		<Query Id="0">
			<Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventID=7)]] and *[EventData[Data='mscoree.dll']] or *[EventData[Data='clr.dll']]
			</Select>
		</Query>
	</QueryList>
"@
# 利用FilterXml
Get-WinEvent -FilterXml $Query | ForEach-Object {Write-Host $_.Message `n}	
```



识别任何 Sysinterals 工具的安装

```powershell
# 
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[EventData[Data[@Name='Image']='C:\Windows\System32\reg.exe']] and *[EventData[Data[@Name='CommandLine']='`"C:\Windows\system32\reg.exe`" ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f']]" | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSi
```

识别与可疑IP地址的连接

```powershell
# 
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=3] and EventData[Data[@Name='DestinationIp']='52.113.194.132']]"
```



