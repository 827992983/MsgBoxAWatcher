# MsgBoxAWatcher
全局API函数调用监视器

## 监控程序
负责过 MessageBoxA 写拷贝，HOOK MessageBoxA，并打印 MessageBoxA 调用记录。

## 驱动程序
负责给监控程序提权，记录 MessageBoxA 调用记录，并在监控程序发出请求时向它发送调用记录。

## 编译环境
vs2010 + wdk7600

## 运行环境
Windows XP 32位

## 项目说明
https://blog.csdn.net/Kwansy
