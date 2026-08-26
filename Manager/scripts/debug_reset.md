# 动态调试 USBKey_Reset 步骤

## 目标
找出官方工具 GP_ADM_LNCA.exe 如何正确调用 `USBKey_Reset` 函数

## 步骤

### 1. 附加调试器
```
x32dbg.exe -a 68908
或手动: File -> Attach -> 选择 GP_ADM_LNCA.exe (PID: 68908)
```

### 2. 在 JIT_USBKEY_HD.dll 中找到 USBKey_Reset
```
- 在符号窗口搜索: USBKey_Reset
- 或在模块列表找到 JIT_USBKEY_HD.dll，右键 -> 在反汇编器中跟随
- 在导出表中找到 USBKey_Reset
```

### 3. 设置断点
```
- 在 USBKey_Reset 函数入口设置断点 (F2)
- 或使用命令: bp JIT_USBKEY_HD.USBKey_Reset
```

### 4. 触发调用
```
- 在官方工具中点击"初始化设备"或"重置"按钮
- 调试器会中断
```

### 5. 查看参数
```
在断点处查看栈上的参数 (__stdcall 约定):
[ESP+4]  = hKey (IntPtr)
[ESP+8]  = pData (byte*)
[ESP+12] = dataLen (uint)

重点关注:
- pData 指向的数据内容（可能需要特定格式）
- dataLen 的值
```

### 6. 记录结果
```
记录:
1. hKey 的值
2. pData 指向的数据（前 64 字节）
3. dataLen 的值
4. 函数返回值（EAX）
```

## 预期结果

如果成功，应该看到:
- dataLen 可能是 0，或者特定值（如 16、32）
- pData 可能指向特定格式的数据（管理员密钥？）
- 返回值应该是 0

## 备选方案

如果官方工具没有调用 USBKey_Reset:
1. 检查它是否调用了其他函数（如 InitKey）
2. 检查是否先删除了所有证书文件
3. 检查是否使用了文件系统操作
