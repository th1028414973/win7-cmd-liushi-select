win7微软不更新了吗？那我帮忙更新下哈： 补丁功能，win7 64位(32位请自行编译)cmd 修改原先矩形选中为win10cmd 流式选中风格功能 。\r\n
使用方法：先备份"C:\Windows\System32\conhost.exe",
关闭全部cmd和 conhost 进程,
把这个项目里conhost.exe(版本 6.1.7601.24388)和 atrow.dll 放到C:\Windows\System32 下替换原先的conhost.exe，开始流式选中之旅吧~。
本项目采用IAThook,如果不放心安全你也可以自己编译源码mian.cpp。 使用Stud_PE把编译出来的dll文件挂到conhost.exe里，再替换原先的conhost.exe。

