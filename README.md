# oFx

一个应用于web安全领域的漏洞扫描框架，刷洞，刷肉鸡用（取决于你的漏洞）  

虽说是框架，但目前的规模仅是笔者自用及与身边小伙伴分享的工具  

![show](img/3.png)

黑底蓝字代表无漏洞  
![show](img/1.png)

黑底绿字代表存在漏洞  
![show](img/4.png)

黑底青字目标不可达  
![show](img/2.png)



TODO  
~~插件调用~~  
~~html报告导出~~  
~~log记录与打印~~   
~~多线程~~   
添加启动时环境监测机制    
添加系统目录初始化操作  
添加系统参数初始化操作  
调整模块导入细节，参考pocsuite3的console.py开头部分  
添加按键退出功能，参考start函数    
添加fofa-api接口，参考pocsuite3/plugins/target_from_fofa.py  
html报告版面优化，参考pocsuite3/plugins/html_report.py  
插件模版制作，参考pocsuite3/pocs/demo_poc.py     
添加自动更新功能，该功能放弃广大win用户，请见谅，参考pocsuite3/lib/core/update.py  