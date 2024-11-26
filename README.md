可以让HFish蜜罐平台的结果直接展现在博客页面，会进行按：蜜罐种类->请求日期 进行排序的分类
目前设置了专门的检测规则，针对GET请求会检测访问url，针对所有请求都检测请求body，以匹配如下各类攻击模式
![keyword](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20241126115637.png)
主要涵盖各类代码执行打点、持久化行为来进行进一步筛选，以提高0day/1day捕捉的专注性


用法：

pip install pypinyin

python3 honeypot_api.py --hfish_domain [你的Hfish平台ip或域名] --api_key [平台apikey，在后台自寻] --output_dir [输出html文件的文件夹]
![use](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/bb2d7d2e3d6eee00a15b5fb2a2e4a05.png).
效果:

部署示例请移步 https://ba1100n.tech/honeypot/index.html
![show_result](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20241122222259.png).
会进行分类，筛选可能存在高价值exp的请求包，并按蜜罐种类进行分类
![show_result2](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20241126115918.png).
蜜罐种类内部还会按时间进行进一步分类
![show result3](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20241126120038.png).
高价值exp抓到的东西类似如下
![show result3](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20241126120158.png).
有时候会抓到僵尸网络的行为，比如mozi僵尸网络
![zombot](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20241126120251.png).
![threat_intelligence](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20241126120347.png).
