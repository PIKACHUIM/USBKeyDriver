# BJCA（北京数字认证）USBKey 逆向分析与对接

> **目标**：把 `Library/BJCA USBKEY DRIVER` 里的 BJCA 客户端组件接入 `Manager`（USBKey 管理端），
> 实现**枚举、登录、改密、解锁、证书管理**，重点实现 **重置 USBKey（清空内容）+ 重设管理口令/用户 PIN**。
>
> **状态**：✅ 已完成并**实机验证**（真实设备：林果 LG3073，VID:PID `6588:1514`，SN `5303201812001784`）。
>
> **日期**：2026-09-21 · 工具：`tools/bjca_analyze.py`、`tools/bjca_typelib.ps1`、`Manager/tools/BjcaProbe`

---

## 1. 结论速览

| 项目 | 结论 |
|------|------|
| 对接 DLL | `XTXAppCOM.dll`（32 位，管理器为 x86 宿主）/ `XTXAppCOM_x64.dll`（64 位） |
| CoClass CLSID | `{3F367B74-92D9-4C5E-AB93-234F8A91D5E6}`（ProgID `XTXAppCOM.XTXApp.1`） |
| 接口 IID | `{6C12D5B5-343C-4D55-B37E-7E7A151DCE71}`（`IXTXApp`，dual/dispatch） |
| 注册方式 | **无需 regsvr32**：LoadLibrary → `DllGetClassObject` → `IClassFactory::CreateInstance` |
| 调用方式 | **`IDispatch::Invoke` 按 dispid**（dispid == `COM.idl` 的 `[id(N)]`），参数走 `DISPPARAMS/VARIANT` |
| 重置入口 | `InitDeviceEx(sn, 管理口令, 用户PIN, KeyLabel, 管理重试上限, 用户PIN重试上限)`（dispid 95），成功返回 `VARIANT_TRUE` |
| 导入证书 | ✅ 卡内生成密钥 → CSR → CA 签发 → `ImportSignCert`；❌ **外部 PFX（含私钥）不可导入**（硬件安全设计） |
| 注意事项 | 组件在需要口令时会**弹出自身密码框**（`#32770` / `inputpasswdui`），无界面场景会阻塞 |
| 覆盖型号 | 由 `Driver\driver.ini` 自动分派：中孚 C3200/C3201、飞天 ePass2000/3000/3001GM、林果 3056/3073、天地融、握奇 USK218、AK5018/5019、蓝牙 1509… |

---

## 2. 目标目录结构（`Library/BJCA USBKEY DRIVER`）

```
BJCAClient/CertAppEnvV3.7.418.0052/
  Program/            ← 应用层：XTXAppCOM[_x64].dll（核心）、COM.idl、XTXAppCOM.ini、trust.pem
  Driver/             ← 设备驱动层：driver.ini（VID/PID → 驱动 DLL 映射）+ x86/ x64/ 各型号 DLL
  BjcaCertAide/       ← 官方客户端「证书助手」：errorinfo.json（错误码表）、DriverCfg/（CSP 配置）
system32/  SysWOW64/  ← 已安装的 bjcakey_*.dll（设备族级 BJCAKey API）与 bjcacsp11_*.dll（PKCS#11）
SJK1312_HID(AK5018-D)/← 中孚 AK5018-D 蓝牙/OTG Key 专用驱动与 CSP 安装器
```

设备通信最终由 **已安装的厂商驱动 + PC/SC 读卡器**（本机可见两个 `USB Token 32 Holder` 虚拟读卡器）完成，
因此**目标机器必须先安装官方 BJCA 客户端**（安装包会把 `InstallPath` 写入注册表，
并把支持列表登记到 `HKLM\SOFTWARE\WOW6432Node\BJCA\Update\Clients`）。

`Program\COM.idl` 是随包发布的接口定义，但 **与二进制不完全一致**（见 §4），仅可作参考。

---

## 3. 免注册激活（核心结论）

`XTXAppCOM.dll` 同时是一个标准 in-proc COM 服务器：

* 导出 `DllGetClassObject` / `DllRegisterServer` / `DllUnregisterServer`；
* 内嵌 RGS 注册脚本，写明 `InprocServer32 = %MODULE%`、`ThreadingModel = Apartment`、
  `TypeLib = {B8490A7B-56F2-482F-A71D-3D5B26DC61BB}`。

因此可以不写任何注册表项，直接：

```csharp
LoadLibraryEx(dll, 0, LOAD_WITH_ALTERED_SEARCH_PATH);
pfn = GetProcAddress(h, "DllGetClassObject");
pfn(CLSID_XTXApp, IID_IClassFactory, out pcf);          // vtable[3] = CreateInstance
createInstance(pcf, null, IID_IXTXApp, out self);       // 得到 CXTXApp 对象
var disp = (IDispatch)Marshal.GetObjectForIUnknown(self);
```

实测 `GetIDsOfNames("InitDeviceEx") → dispid=95`，与 `COM.idl` 的 `[id(95)]` 完全一致；
`GetTypeInfoCount/GetTypeInfo` 亦可用（内嵌 typelib 自解释）。

> **注意**：`COM.idl` 把 CLSID 写成了 IXTXApp 的 `uuid`，而 DLL 内嵌 typelib 显示
> IXTXApp 的 IID 实为 `{6C12D5B5-…}`。**以 DLL 内嵌 typelib 为准**（`tools/bjca_typelib.ps1` 可复现）。

---

## 4. 为什么用 `IDispatch::Invoke` 而不是按名字 P/Invoke 导出函数

该 DLL 除 `DllGetClassObject` 外，还**按名字导出了 141 个接口方法实现**（`InitDevice`、`InitDeviceEx`、
`ChangeAdminPass`、`SOF_Login`…），直觉上可以直接 `GetProcAddress` + 委托调用。但实测发现：

1. 这些导出是 **`__stdcall` 自由函数，第一个参数是 `CXTXApp*`**（`this`），
   入参个数等于「接口参数个数 + 1」，返回值即业务返回码；
2. **导出函数的真实参数个数与 `COM.idl` 声明不一致**（用 `ret imm16` 自动推算，见
   `tools/bjca_analyze.py argcounts`）。例如：

   | 函数 | COM.idl 参数（含 retval） | 二进制 `ret` 推算 | DLL 内嵌 TypeLib |
   |------|--------------------------|------------------|------------------|
   | `InitDevice` | 3（sn, adminPass, `[out,retval]BOOL*`） | 3（this+2，**无 retval**） | 2（sn, adminPass）→ 返回 BOOL |
   | `InitDeviceEx` | 6 + retval | 7（this+6，**无 retval**） | 6 → 返回 BOOL |
   | `GetDeviceCount` | 1（`[out,retval]LONG*`） | 2（this+1 out 指针） | 0 → 返回 LONG |
   | `SOF_GetVersion` | 1（`[out,retval]BSTR*`） | 3（this+2） | 0 → 返回 BSTR |

   三种来源两两不一致 ⇒ **按 `ret imm16` 硬编码 ABI 风险极高**（一旦不符就是栈损坏）。

结论：**统一走 `IDispatch::Invoke`**。参数经 `DISPPARAMS`（`VARIANT` 数组）传递，
由组件自身的 `CXTXApp::Invoke` 按它的 dispatch map 解释并调用内部实现，
**与 C++ 导出 ABI 无关**，不存在 ABI 错配导致崩溃的可能；且 dispid 在组件各版本间稳定。

参数顺序取自 DLL 内嵌 TypeLib（`tools/bjca_typelib.ps1` 导出的
`tools/bjca_typelib_IXTXApp.txt`）：

* 方法**直接返回业务值**（`VT_BOOL` / `VT_BSTR` / `VT_I4`），不是 `HRESULT + [out,retval]`；
* 因此 `IDispatch::Invoke` 的 HRESULT 恒为 `S_OK`，
  **业务失败要看返回值**（`FALSE` / `0` / 空串），并可配合 `SOF_GetLastError`(31) / `SOF_GetLastErrMsg`(67) 取诊断信息。

> 另：**不要在自动化流程里调用 `SOF_SelectFile`(96)** —— 它会弹出系统文件选择对话框，导致进程阻塞。

---

## 5. 关键方法（dispid / 参数 / 返回）

完整清单见 `tools/bjca_typelib_IXTXApp.txt`（195 项，前 7 项为 IUnknown/IDispatch）。
下表为管理器实际使用的方法（与 `BjcaNative.cs` 中的常量一一对应）：

### 5.1 设备与重置（重点）

| dispid | 方法 | 参数 | 返回 | 说明 |
|-------:|------|------|------|------|
| 32 | `GetDeviceCount` | — | LONG | 已连接设备数 |
| 33 | `GetAllDeviceSN` | — | BSTR | 序列号列表，**以 `;` 分隔**（如 `5303201812001784;`） |
| 34 | `GetDeviceSNByIndex` | iIndex | BSTR | 按索引取序列号 |
| 35 | `GetDeviceInfo` | sDeviceSN, iType | BSTR | 设备信息字段，见 §6 |
| 61 | `IsDeviceExist` | sDeviceSN | BOOL | — |
| 116/117 | `GetDeviceCountEx` / `GetAllDeviceSNEx` | type | LONG / BSTR | type 0/1 对应 硬/软 设备 |
| 133 | `EnumSupportDeviceList` | — | BSTR | 支持型号，**以 `&&&` 分隔**（如 `6588_1514&&&`） |
| **95** | **`InitDeviceEx`** | **sn, 管理口令, 用户PIN, KeyLabel, 管理重试上限, 用户PIN重试上限** | **BOOL** | **重置/初始化：清空全部容器+证书+密钥，并重设管理口令与用户 PIN** |
| 47 | `InitDevice` | sn, 管理口令 | BOOL | 同上，内部固定 用户PIN=`111111`、标签=`BJCA-UserKey`、重试 10/10（反汇编常量） |
| 36 | `ChangeAdminPass` | sn, 旧管理口令, 新管理口令 | BOOL | 改管理口令（SO PIN） |
| 37 | `UnlockUserPass` | sn, 管理口令, 新用户PIN | BOOL | 用管理口令解锁/重设用户 PIN |
| 72 | `UnlockUserPassEx` | sn, 管理口令, 新用户PIN | BOOL | 同上（扩展版） |
| 62 | `GetContainerCount` | sn | LONG | 容器数 |
| 79 | `SOF_GetAllContainerName` | sn | BSTR | 容器名列表 |
| 122 | `EnumFilesInDevice` | sn | BSTR | 设备内文件列表 |
| 59/60 | `GetENVSN` / `SetENVSN` | sn[, envsn] | BSTR / BOOL | 环境序列号 |

### 5.2 证书 / 容器

| dispid | 方法 | 参数 | 返回 |
|-------:|------|------|------|
| 5 | `SOF_GetUserList` | — | BSTR（证书/容器 ID 列表，即登录用的 `CertID`） |
| 6 | `SOF_ExportUserCert` | CertID | BSTR（证书，裸 base64 或 PEM） |
| 10 | `SOF_GetCertInfo` | Cert, type | BSTR |
| 11 | `SOF_GetCertInfoByOid` | Cert, Oid | BSTR |
| 58 | `SOF_ValidateCert` | Cert | LONG |
| 91 | `SOF_GetCertEntity` | sCert | BSTR |
| 44/45/73 | `IsContainerExist` / `DeleteContainer` / `DeleteOldContainer` | sn[, containerName] | BOOL |
| 38/39/46 | `GenerateKeyPair` / `ExportPubKey` / `ExportPKCS10` | sn, containerName, … | BOOL / BSTR |
| 40/113 | `ImportSignCert` / `ImportPfxToDevice` | sn, containerName, … | BOOL |

### 5.3 口令 / 登录 / 其它

| dispid | 方法 | 参数 | 返回 |
|-------:|------|------|------|
| 7 | `SOF_Login` | CertID, PIN | BOOL |
| 85 / 131 | `SOF_Logout` / `SOF_IsLogin` | CertID | BOOL |
| 9 | `SOF_ChangePassWd` | CertID, 旧PIN, 新PIN | BOOL |
| 8 / 78 | `SOF_GetPinRetryCount` / `SOF_GetRetryCount` | CertID | LONG |
| 89 / 120 | `OTP_GetChallengeCode[Ex]` | CertID[, …] | BSTR（仅 OTP 型号） |
| 26 / 68 / 69 | `SOF_GenRandom` / `Base64Encode` / `Base64Decode` | … | BSTR |
| 31 / 67 | `SOF_GetLastError` / `SOF_GetLastErrMsg` | — | LONG / BSTR |
| 56 / 161 | `SOF_GetVersion` / `SOF_GetProductVersion` | — | BSTR（实测 `3.7.415.52` / `3.7.418.0052`） |
| 96 | `SOF_SelectFile` | — | BSTR | ⚠️ 会弹文件对话框，勿用 |

---

## 6. 设备信息字段语义（`GetDeviceInfo(sn, iType)`，实测推断）

在 林果 LG3073（SM2）上的实测值：

| iType | 含义 | 实测值 |
|------:|------|--------|
| 1 | 密钥标签 KeyLabel | `BJCA-UserKey` |
| 2 | 存储容量（字节） | `72576`（≈70KB） |
| 3 | 设备序列号 | `5303201812001784` |
| 4 | 算法 | `SM2` |
| 5 | 管理口令最大重试次数 | `10` |
| 6 | 用户口令最大重试次数 | `10` |
| 7 | 设备类型（硬/软） | `HARD` |
| 8 | 设备驱动 DLL | `lgu3073_p1514_gm.dll` |

PID 可由字段 8 的驱动名反推（`…_p1514_…` → `0x1514`），VID 由 `EnumSupportDeviceList` 的首项给出。

---

## 7. 重置（初始化）流程与实机验证

### 7.1 调用语义

```csharp
InitDeviceEx(
    sDeviceSN          : "5303201812001784",
    sAdminPass         : "111111",        // ★ 这里是「要设置成的新管理口令」，不是旧口令
    sUserPin           : "123456",        // 要设置成的新用户 PIN（6~16 位，PinRules ^.{6,16}$）
    sKeyLabel          : "BJCA-UserKey",  // 设备标签
    adminPinMaxRetry   : 10,
    userPinMaxRetry    : 10)  -> VARIANT_TRUE(成功) / VARIANT_FALSE(失败)
```

**关键实测结论：`sAdminPass` 是「新管理口令」**，初始化**不需要**提供旧口令/当前 PIN
（等价于 PKCS#11 的 `C_InitToken` 语义）。因此 `IKeyProvider.ResetRequiresCurrentPin = false`。

### 7.2 实机结果（2026-09-21）

```
目标设备　: 5303201812001784（林果 LG3073 / SM2 / 6588:1514）
新用户PIN : 123456
管理口令  : 111111（默认）
InitDeviceEx(sn, 管理口令, 用户PIN, BJCA-UserKey, 10, 10) → 成功
重置后容器数: 0
说明      : 设备上无容器，用户 PIN 将在首次创建容器时生效（无法用 SOF_Login 复验）
```

> 因为该 Key 当时**本身没有任何容器/证书**，重置前后容器数均为 0；
> 「初始化成功」由组件返回值确认。若卡上原有证书，本操作会将其全部清除。

### 7.3 管理器中的入参映射

`IKeyProvider.ResetDevice(device, newPin, puk, adminKey, currentPin)` → BJCA：

| 接口参数 | BJCA 语义 |
|----------|-----------|
| `newPin` | `sUserPin`（新用户 PIN） |
| `adminKey` | `sAdminPass`（新管理口令 / SO PIN），未填则用默认 `111111` |
| `puk` | `sKeyLabel`（设备标签），未填则用默认 `BJCA-UserKey`（**接口无独立标签参数，故借用 puk 承载**） |
| `currentPin` | 仅在未给 `adminKey` 时作为候选管理口令（兼容「要求旧口令」的型号） |

失败时依次尝试 `InitDeviceEx` → `InitDevice`，并把每一步真实返回码/错误描述写入
`BjcaProvider.LastResetReport`，由 `MainForm.DoReset` 汇总展示。

---

## 8. 证书 / 密钥链路实测结论（2026-09-21，林果 LG3073）

用 `BjcaProbe certtest` 在真实设备上逐项实测（脚本已内建清理）：

| # | 操作 | dispid | 实测结果 |
|--:|------|-------:|----------|
| 1 | `GenerateKeyPair`（卡内生成密钥对/建容器） | 38 | ✅ 成功。`keyType` 扫描：**0/4/5/6 失败，1/2/3 成功**（1 为 RSA，卡内生成耗时 30~90 秒） |
| 2 | `ExportPubKey` | 39 | ✅ 返回 base64 公钥 |
| 3 | `ExportPKCS10`（CSR） | 46 | ✅ 返回 PKCS#10，Subject 按传入 DN 生成 |
| 4 | `ImportSignCert`（导入**公钥不匹配**的证书） | 40 | ✅ 被正确拒绝（返回 FALSE）——证书公钥必须与容器内密钥匹配 |
| 4b | `ImportSignCert`（导入**本机测试 CA 为设备 CSR 签发**的证书） | 40 | ✅ **成功**（base64 DER，612 字节） |
| 5 | `ImportPfxToDevice`（导入本地 PFX） | 113 | ❌ **失败**（bSign true/false 均失败）。且**失败后会在设备上留下一个空容器**，必须调用方清理 |
| 6 | `SOF_GetAllContainerName` | 79 | ✅ 分隔符为 **`&&&`**（如 `BJCATEST&&&`） |
| 7 | `GetContainerCount` | 62 | ✅ 容器数随建/删同步变化 |
| 8 | `DeleteContainer` | 45 | ✅ 成功（但见下方「弹窗」问题） |
| 9 | `DeleteOldContainer` | 73 | ❌ 失败（仅用于旧格式容器，常规设备无此项） |
| 10 | `SOF_GetCertInfo` / `ValidateCert` / `GetCertInfoByOid` | 10/58/11 | ✅ 入参是**证书内容**（base64），无需 CertID，可正常解析 |
| 11 | `SOF_GetUserList`（取 CertID 的关键） | 5 | ❌ **始终返回空**（见 §8.3） |
| 12 | `SOF_Login` | 7 | ❌ 所有 CertID 候选都失败，`SOF_GetLastErrMsg = 打开设备失败` |

### 8.1 `SOF_GetCertInfo(cert, type)` 字段语义（实测，`type` 为 `VT_I2`）

| type | 含义 | 实测值 |
|-----:|------|--------|
| 1 | 证书版本 | `V3` |
| 2 | 证书序列号（十六进制） | `648B635ECCA31BA3` |
| 3 | 公钥算法 | `RSA` |
| 8 | 签发者 CN | `BJCA Probe Test CA` |
| 11 | 生效时间 `yyyyMMddHHmmss` | `20260920160301` |
| 12 | 失效时间 `yyyyMMddHHmmss` | `20270921160301` |
| 13 | 主题 RDN 类型 | `CN` |
| 14 | 主题 O（组织） | `USBKeyDriver` |
| 15 | 主题 OU | `Test` |
| 17 | 主题 CN | `BJCATEST` |
| 20 | 公钥（base64 SubjectPublicKeyInfo） | `MIGJAoGB…` |

> 这套接口可直接用于填充 `KeyContainer` 的 Subject/Issuer/有效期/算法/公钥，**不需要 CertID**。


### 8.2 关键结论：**BJCA 不支持「导入外部私钥（PFX）」**

`ImportPfxToDevice` 在本型号上无法把本地 PFX（含私钥）写入卡内——
这符合 USBKey 的安全设计（**私钥在卡内生成、不可导出也不可导入**）。

**正确流程（已在 `BjcaProvider` 中提供为公开方法）**：

```
① GenerateKeyPair(sn, containerName, keyType=1, sign=true)   卡内生成密钥对
② ExportPkcs10(sn, containerName, dn, sign)                 取回 CSR
③ 提交 CA 签发（可离线/自建 CA）
④ ImportCertificate(sn, containerName, certBase64OrPem)     证书导回卡内
⑤ SOF_Login(CertID, 用户PIN) → SOF_ChangePassWd / 签名等
```

对应 `BjcaProvider` 新增 API：`GenerateKeyPair` / `ExportPublicKey` / `ExportPkcs10` /
`ImportCertificate` / `RemoveContainer`。

> 因此 `IKeyProvider.ImportPfx`（语义为「把本地 PFX 导入 Key」）在 BJCA 上**能力受限**：
> 实现会先按真实 API 尝试，失败后清理残留容器，并抛出带完整指引的 `NotSupportedException`。

### 8.3 ⚠️ 未闭环：`SOF_GetUserList` 恒为空 ⇒ 拿不到 CertID

`SOF_Login` / `SOF_ChangePassWd` / `SOF_ExportUserCert` / `SOF_GetPinRetryCount` 等**都要一个 `CertID`**，
而 `SOF_GetUserList`（唯一公开的 CertID 来源）在实测中**始终返回空字符串**，即使设备上已经
「建好容器 + 成功导入证书」。已排除的可能：

| 假设 | 实测 |
|------|------|
| CertID = 容器名（`BJCATEST`） | ❌ `GetPinRetryCount` 返回 **-8**（无效） |
| CertID = 容器名+后缀（`|0` `:0` `_0` `0`） | ❌ 均 -8 |
| CertID = `序列号:容器名` / `序列号\|容器名` | ❌ 均 -8 |
| CertID = 证书内容（base64） | ❌ -8 |
| 先调 `SOF_UpdateCert(CertID=容器名, 0/1)` 刷新缓存 | 返回 `1`，但 `GetUserList` 仍为空 |
| 先调 `SOF_Initialize("USBKeyManager")`（按导出名，非 IDispatch） | 返回 `0`（成功），但 `GetUserList` 仍为空 |
| `SOF_GetLastLoginCertID()` | 空 |

**推断**：`SOF_GetUserList` 的数据源不是「卡内容器」，而是 BJCA 客户端维护的**证书缓存 / 用户注册表**
（组件内含 `CacheManager`、`CSS`、`XTXAppCOM.ini` 的 `CSSUpdateCert`、`C:\BJCAROOT\XTXTrust\`，
以及 USBKeyPnPActiveX 的 `GetSavedPass/SaveUserPass` 等），只有走官方客户端（BjcaCertAide）
或银行展期流程写入缓存后才有条目。因此**无法用裸 API 自举**「登录/改密/导出」这条链路。

### 8.4 另一条可行路线：直接对接 SKF（GM/T 0016）

`Driver\driver.ini` 显示本设备（林果 LG3073，`6588:1514`）的 `type = SKF`、`dll = lgu3073_p1514_gm.dll`，
组件内部对 SKF 型设备也是调 `SKF_OpenApplication/CreateApplication/DeleteApplication/VerifyPIN...`
（二进制里有对应日志串）。因此若需要「登录/改密/解锁/容器读写」的完整能力，
可以**绕过 XTXAppCOM，直接 P/Invoke `lgu3073_p1514_gm.dll` 的 SKF 接口**——
这条路不依赖 BJCA 的证书缓存，是更彻底的做法（工作量为一次独立的 SKF 对接）。

### 8.5 关键结论：组件会**弹出自身的口令输入框**（阻塞风险）

实测发现 `XTXAppCOM.dll` 在需要用户口令时会创建 ATL 对话框：

```
窗口类 : #32770（标准对话框）
窗口标题: inputpasswdui
所属进程: 调用方进程（即我们的宿主）
```

只要用户不输入口令，该调用就**一直阻塞**（本次实测中 `DeleteContainer` 触发了它）。影响：

* **管理端（GUI）**：用户可以正常在弹出的窗口里输入口令，功能可用；
  但调用发生在 `BjcaSession` 的 **STA 工作线程** 上，主界面会一直等待，
  表现为「界面卡住 + 一个 BJCA 密码框」。
* **无界面场景（REST API / 服务 / 无人值守）**：会永久阻塞，必须避免调用会触发的操作。
* 规避方向（待确认）：`SOF_EnableLoginWindow(dispid 143, Parm)`、`XTXAppCOM.ini` 的
  `ProgressPrompt`、以及 `GetPassSaveState/SaveUserPass`（USBKeyPnPActiveX 控件提供，
  可预存口令从而不弹窗）。

---

## 9. 代码落点

| 文件 | 职责 |
|------|------|
| `Manager/src/USBKey.Core/UsbKey/BjcaNative.cs` | `BjcaSession`：免注册激活 + STA 工作线程 + `IDispatch` 调用 + 全部方法封装（dispid 常量、VARIANT 编解码） |
| `Manager/src/USBKey.Core/UsbKey/BjcaProvider.cs` | `IKeyProvider` 实现：枚举/详情/容器/导入导出/登录/改密/解锁/重置，含 DLL 定位（注册表 → `Library\BJCA` → 递归） |
| `Manager/src/USBKey.Manager/AppContext.cs` | 注册 `bjca` 平台 provider |
| `Manager/src/USBKey.Manager/MainForm.cs` | 重置对话框的 BJCA 分支（询问管理口令/标签）+ 执行报告展示 |
| `Manager/config/config.json` | `platform` 增加 `bjca`，`keyslist` 增加 `bjca` |
| `Manager/tools/BjcaProbe/` | 联调探针（typelib 导出 / 免注册激活自检 / 只读探测 / 生产实现联调 / 重置实测） |
| `tools/bjca_analyze.py` | PE 静态分析（导出表、RVA、字符串、GUID、`ret imm16` 推算参数个数） |
| `tools/bjca_typelib.ps1` | 读取 DLL 内嵌 TypeLib，导出接口/方法/参数的权威签名 |
| `tools/bjca_typelib_IXTXApp.txt` | `IXTXApp` 完整签名导出结果（195 项） |

### 复现命令

```powershell
# 1) 权威接口签名（重生成 tools/bjca_typelib_IXTXApp.txt 的依据）
cd Manager\tools\BjcaProbe
dotnet run -- typelib IXTXApp

# 2) 免注册激活 + 连通性自检（导出地址 vs vtable、GetIDsOfNames、只读调用）
dotnet run -- probe

# 3) 只读探测真实设备（设备信息 / 容器 / 证书 / 重试次数）
dotnet run -- readonly

# 4) 联调生产实现 BjcaProvider（枚举 / 详情 / 容器）
dotnet run -- provider

# 5) 重置设备（不可撤销；末尾必须加 --yes 才真正执行）
dotnet run -- reset 123456 111111 --yes
```

---

## 10. 部署要求

1. **必须先安装官方 BJCA 客户端**（`CertAppEnv*`）。设备通信依赖其安装的驱动与虚拟读卡器
   （本机可见两个 `USB Token 32 Holder`），仅拷贝 DLL 无法完成读卡。
   安装后会写入 `HKLM\SOFTWARE\WOW6432Node\BJCA\InstallPath`。
2. 管理器 `BjcaProvider.LocateDll()` 的查找顺序：
   ① 注册表 `InstallPath\Program\XTXAppCOM[_x64].dll` →
   ② `<Library>\BJCA\XTXAppCOM[_x64].dll` →
   ③ 递归 `<Library>`（优先 `...\Program\`）。
3. 宿主位数：管理器为 **x86**（受 LNCA 驱动约束），因此加载 **32 位** `XTXAppCOM.dll`；
   若将来改为 x64 宿主，会自动改加载 `XTXAppCOM_x64.dll`。
4. 组件会读写 `C:\BJCAROOT\`（日志、信任目录）与 `XTXAppCOM.ini`（日志级别、PinRules），
   这些在其安装目录内，无需额外配置。

---

## 11. 遗留问题 / 待确认

1. **`SOF_Login` 与「无容器」设备**：设备上没有容器时不存在用户 PIN，无法用 `SOF_Login` 复验
   「重置后的用户 PIN」。当前策略是如实报告，不做假复验。
2. **改密/删除按钮**：`config.json` 中 `changepin` / `delcert` 默认 `disabled`，需按需开启
   （`CambioPin` 依赖 `SOF_ChangePassWd`，需要先有容器；`DeleteContainer` 用的是容器名）。
3. **挑战码解锁**：`OTP_GetChallengeCode[Ex]` 只对 OTP/蓝牙型号有效，当前型号返回空，
   实现里明确抛 `NotSupportedException` 而不是假装成功。
4. **软设备/云证书**（`CreateSoftDevice`、`EnableSoftDevice`、`ImportKeyCertToSoftDevice` 等
   共 40 余个未使用方法）尚未对接，如需「软证书 / 云证书」能力可继续扩展。
5. `GetDeviceInfo` 的 `iType` 语义目前是**实测推断**（§6），不同型号可能有差异；
   实现已做容错（解析失败仅影响展示，不影响功能）。
6. **证书链路卡在 CertID（最高优先级待解）**：实测 `GenerateKeyPair → ExportPKCS10 → CA 签发 →
   ImportSignCert` **全部成功**，但 `SOF_GetUserList` 始终为空，拿不到 `CertID`，
   导致 `SOF_Login / SOF_ChangePassWd / SOF_ExportUserCert` 无法调用（详见 §8.3）。
   下一步二选一：
   ① 用官方客户端（BjcaCertAide）在本卡上正常走一次「申请→签发→导入」，再观察 `SOF_GetUserList`
      是否出现条目、`CertID` 长什么样，然后照此实现；
   ② 直接对接 `lgu3073_p1514_gm.dll` 的 **SKF（GM/T 0016）** 接口（`SKF_OpenApplication`/`SKF_VerifyPIN`/
      `SKF_ChangePIN`/`SKF_UnblockPIN` 等），彻底绕开 BJCA 的证书缓存依赖（见 §8.4）。
7. **`inputpasswdui` 弹窗的规避方式待确认**：候选手段为 `SOF_EnableLoginWindow(143)`
   （启用/禁用组件自带登录窗）、`XTXAppCOM.ini` 的 `ProgressPrompt`、
   以及 USBKeyPnPActiveX 的 `SaveUserPass/GetPassSaveState`（预存口令）。
   在确认前，**REST API/服务等无人值守通道不要调用可能弹窗的证书/容器操作**。

---

## 12. 变更记录

| 日期 | 变更 |
|------|------|
| 2026-09-21 | 完成逆向分析与对接；新增 `BjcaProvider`/`BjcaSession`；接入 `config.json`/`AppContext`/`MainForm`；实机验证重置成功 |
| 2026-09-21 | 实测证书链路（§8）：确认卡内建容器/导出公钥/导出 CSR/**导入证书**/删除容器可用；确认 `ImportPfxToDevice` 不可用并补齐正确流程 API（`GenerateKeyPair`/`ExportPkcs10`/`ImportCertificate`/`RemoveContainer`）；给出 `SOF_GetCertInfo` 字段语义表（§8.1）；定位 CertID 阻塞点（§8.3）；发现 `inputpasswdui` 弹窗阻塞行为并在 `ImportPfx` 中加入失败残留容器清理 |
