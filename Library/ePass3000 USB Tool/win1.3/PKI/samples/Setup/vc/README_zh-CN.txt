一、安装包的组成：

安装包包括NGSetup.DLL和NGSetup.DAT两个文件。NGSetup.DLL为安装中间件执行动态库，NGSetup.DAT为中间件安装卸载时所需的资源文件。

二、动态库的导出函数：

对于调用一个接口即可完成安装操作的相关函数一共有4个。他们的接口类型与调用参数类型如下：
1、DWORD WINAPI instMW_Install(const char* szParam);
2、DWORD WINAPI instMW_Uninstall(const char* szParam);
3、DWORD WINAPI instMW_IsHaveInstalled(const char* szParam);
4、DWORD WINAPI instMW_IsNeedReboot(void);

三、函数接口参数说明：
1、instMW_Install
    传入为字符串，可以使多个参数的组合，其间由";"分隔。
    参数1：安装卸载所需要的dat文件名称 传入的参数全写为"path=****.DAT"(其中的"****.DAT"用实际的文件名称替换)。
            为了保持对旧版本的兼容，该参数设置比较灵活如果该参数不设置，默认为"path=NGSetup.DAT"。也可以只设置 “****.DAT”，系统自动判断补充“path=”。
    参数2：如果该设备为智能卡设备，可以选择是否“支持智能卡或VPN登录”功能。
            如果不支持，不设置该参数。如果支持，设置参数"regatr=true"。
    例如：如果DAT文件名称为NGSetup.DAT，支持智能卡或VPN登录，传入的参数可以是"path=NGSetup.DAT;regatr=true"， 可以省略为 “NGSetup.DAT;regatr=true”，因为NGSetup.DAT文件名称是默认文件名，还可以省略为“regatr=true”。
2、instMW_Uninstall 传入DAT文件路径，如果为空，默认为“NGSetup.DAT”（注意：只有一个参数，没有“path=”部分）。
3、instMW_IsHaveInstalled 同2，略。
4、instMW_IsNeedReboot 无参数。

四、函数返回值说明：
1、对于instMW_Install和instMW_Uninstall的返回值如下：
#define ESA_SUCCESS			0x0000 //成功
#define ESA_ERR_FILE_NOT_FOUND		0x0001 //文件没找到
#define ESA_ERR_COPY_FILES		0x0002 //拷贝文件失败
#define ESA_ERR_REG			0x0003 //注册文件或启动文件失败
#define ESA_ERR_REG_CSP			0x0004 //注册CSP失败
#define ESA_ERR_UNREG			0x0005 //卸载CSP失败
#define ESA_ERR_DEL_FILES		0x0006 //删除文件失败
#define ESA_ERR_DEL_DIR			0x0007 //删除目录失败
#define ESA_ERR_EXCTOR_FILES		0x0008 //把资源文件解到临时文件夹中失败
#define ESA_ERR_HOST_MEMORY		0x0009 //内存错误
#define ESA_ERR_REG_CARD_REG		0x000A //安装驱动失败
#define ESA_ERR_PRODUCT_ALD_INST	0x000B //本产品已经安装过了，卸载后才能安装
#define ESA_ERR_NEEDREBOOT		0x000C //由于某个文件标志着下次重启后拷贝或者删除，所以只有重启以后才能正常安装或者卸载
2、对于instMW_IsHaveInstalled 的返回值如下：
#define ESA_NEVER_INSTALL		0 //本产品没安装过
#define ESA_DEST_DVERSION_OLD		1 //本产品安装过并且比安装文件版本老
#define ESA_DEST_DVERSION_EQUAL		2 //本产品安装过并且和安装文件版本相同
#define ESA_DEST_DVERSION_NEW		3 //本产品安装过并且比安装文件版本新
3、对于instMW_IsNeedReboot 的返回值如下:
如果返回1代表需要重启，返回0代表不需要重启。 

五、注意：
1、它需要依赖Lib\lib_x86\setup\目录下的NGSetup.dat、NGSetup.dll，NGSetup.lib等文件
2、请确认系统目录下有msvcp60.dll，如果没有请将Lib目录下的msvcp60.dll拷贝到系统目录下。
3、用这个示例程序进行安装卸载需要在管理员用户下进行。

