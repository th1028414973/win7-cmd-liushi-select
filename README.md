win7微软不更新了吗？那我帮忙更新下哈： 补丁功能，win7 64位(32位请自行编译)cmd 修改原先矩形选中为win10cmd 流式选中风格功能 。

使用方法：先备份"C:\Windows\System32\conhost.exe",

关闭全部cmd和 conhost 进程,

把这个项目里conhost.exe(版本 6.1.7601.24388)和 atrow.dll 放到C:\Windows\System32 下替换原先的conhost.exe，开始流式选中之旅吧~。

本项目采用IAThook,如果不放心安全你也可以自己编译源码mian.cpp。 

使用Stud_PE把编译出来的dll文件挂到conhost.exe里，再替换原先的conhost.exe。

原先cmd选中效果
<img width="716" height="532" alt="未标题-1" src="https://github.com/user-attachments/assets/dd0b29be-6f58-444a-9891-633d6cf44589" />

替换后cmd选中效果
<img width="659" height="502" alt="未标题-2" src="https://github.com/user-attachments/assets/422afcf2-074a-4601-903a-60809c02c751" />

有什么问题可以留言。
