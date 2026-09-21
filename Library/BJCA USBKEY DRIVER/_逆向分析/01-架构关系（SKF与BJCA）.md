# SKF 与 BJCA 的架构关系

> 结论：**两者不是并列的两条路，而是「上层门户」与「它底下可选的一种接口规范」的关系**。
>
> 最后更新：2026-09-21

---

## 1. 决定性证据：BJCA 自己的配置文件

`Library\BJCA USBKEY DRIVER\BJCAClient\CertAppEnvV3.7.418.0052\Driver\driver.ini`
（BJCA 客户端自带，非本文档推测）：

```ini
#driver.ini文件说明
#type 标识该设备的类型 目前支持的类型为 SKF BJCAKey CSP
#vid  硬件设备的Vendor ID
#pid  硬件设备的Product ID
#dll  硬件设备所依赖的动态库 在类型为SKF和BJCAKey时有效
#csp  硬件设备对应的CSP名称 在类型为BJCAKey和CSP时有效

[LG3073]
type = SKF                       ← 林果 LG3073 被 BJCA 归为「SKF 类型」
vid  = 0x6588
pid  = 0x1514
dll  = lgu3073_p1514_gm.dll

[ZTXA]
type = SKFGB                     ← 天地融用的是 SKF 的另一种变体
vid  = 0x22FB
pid  = 0x1014
dll  = USK218_GM.dll
```

同目录 `x86\` 下的驱动清单与之逐一对应，且**全是各厂商的国密（SKF）驱动**：

```
lgu3073_p1514_gm.dll   林果 3073
lgu3056_p1020_gm.dll   林果 3056
ft3001_p0313_gm.dll    飞天 ePass3001 GM
USK218_GM.dll          握奇 USK218
axtx5018_gm.dll        AK5018
BJCA1509_GM.dll        蓝牙 1509
```

**即：BJCA 把 SKF 明确列为「它支持的一种设备类型」，林果只是其中之一。**

---

## 2. 层级关系

```
                    Manager（USBKey 管理端）
                ┌────────────┴────────────┐
           BJCA 通道                   SKF 通道
         XTXAppCOM.dll          lgu3073_p1514_gm.dll
       （COM / IDispatch）        （GM/T 0016 国标 C 接口）
                │                          │
                │  按 driver.ini 分派       │
                ├─ type = SKF ─────────────┤  ← LG3073 走这条
                ├─ type = BJCAKey → bjcakey_*.dll
                └─ type = CSP     → Windows CSP
                                           │
                                  厂商 USB 驱动 + PC/SC
                                           │
                                  同一张物理卡（6588:1514）
```

**关键点：BJCA 组件在处理 LG3073 时，它自己也是在调 `lgu3073_p1514_gm.dll`（即 SKF 接口）。**
绕过 BJCA 直接调 SKF，本质上是跳过中间那一层，直接调用它底下同一个库。

---

## 3. 三条交叉印证

| 证据 | 说明 |
|------|------|
| `driver.ini` 中 `type = SKF` | BJCA 官方把 SKF 列为它的设备类型之一 |
| SKF 枚举出的卡内应用名 = **`BJCA-Application`** | 卡内应用是 BJCA 建的，但 SKF 中间件能直接打开 |
| 两侧看到同一 SN `5303201812001784`、同一容器 `UserKey` | 访问的是同一份卡内数据 |
| **组件 trace 显示 BJCA 删容器内部调 `SKF_DeleteContainer`** | 见下节，最直接的运行期证据 |

---

## 4. 运行期铁证：BJCA 的删除就是 SKF 的删除

组件 trace 日志（`C:\BJCAROOT\BJCAlog\xtx\XTXAppCOM.log`）：

```
CXTXApp::DeleteContainer                     (XTXApp.cpp:1221)
  → CryptokenBucket::DeleteContainer         (cryptobucket.cpp:4406)
    → SKFApplicationWrap::DeleteContainer    (cryptousbicwrap.cpp:1158)
      → SKF_DeleteContainer(...)             ← 就是标准的 SKF 国标接口
         [error] status=0x0a00002e
      → 最终对外包装成 0x0b000028「删除容器失败」
```

同一条日志还显示 BJCA 的其它操作同样直通 SKF：

```
CXTXApp::GenerateKeyPair
  → SKFContainerWrap::GenRSAKeyPair → SKF_GenRSAKeyPair

SKFDeviceWrap::OpenApplication → SKF_OpenApplication / SKF_EnumApplication
SKFApplicationWrap::VerifyPIN  → SKF_VerifyPIN
SKFApplicationWrap::CreateContainer → SKF_CreateContainer
```

---

## 5. 能力分工（为什么两条都要保留）

| 能力 | BJCA 通道 | SKF 通道 |
|------|-----------|----------|
| 枚举设备 | 可以 | 可以 |
| 重置 / 初始化 | `InitDeviceEx`（dispid 95） | 标准接口组合（删容器+删文件+改密+解锁） |
| 登录 | **不行** —— `SOF_GetUserList` 实测恒空，链路无法自举 | `SKF_VerifyPIN` 直通 |
| 改密 / 解锁 | 受登录链路拖累 | `SKF_ChangePIN` / `SKF_UnblockPIN` |
| 删容器 | 直接失败（内部 SKF 调用报错后被包装） | `SKF_DeleteContainer`（需先认证） |
| 列容器 / 证书 | 依赖组件缓存，会出现卡上不存在的「悬空条目」 | 实时读卡，所见即真值 |
| 私钥导入 | `ImportPfxToDevice` 内部有实现，但最后一步失败 | `SKF_ImportRSAKeyPair` 缺前置通道（详见 02） |

**为什么保留 BJCA**：不是所有卡都提供 SKF —— `driver.ini` 中只有 `type = SKF` 的型号才有；
`BJCAKey` / `CSP` 类型的设备**只能**走 BJCA 通道。

**对本卡的实践结论**：
- **管理类操作（删除、改密、解锁、重置）走 SKF**
- **CA 业务类操作（登记 / CSR / 证书导入）两侧都可，SKF 更可靠**
