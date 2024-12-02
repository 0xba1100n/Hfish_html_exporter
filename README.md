# 简介
## 功能
可以让开源蜜罐平台HFish的结果直接展现在博客页面，会进行按：蜜罐种类->请求日期 进行排序的分类

还会根据某些攻击阶段用到的字符去匹配、筛选值得分析的结果，这也是hfish尚有欠缺的功能之一，然后如果用户提供了openai的key，还会让llm来分析一下结果
![keyword](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20241126115637.png)
## 目的
做这个的初衷之一是想抓0day和1day，或者活跃的僵尸网络,感觉改源代码来做可能高价值exp的筛选有点麻烦，这样输出结果然后进行匹配，就能轻松自定义筛选字符来抓exp，无需变动HFish官方源代码

做这个的初衷之二是这样做既不会暴露真正的蜜罐机器是哪个ip，而又能输出结果到一个方便查看的地方。让蜜罐后台仅限定某前台ip访问，然后之后只在这个前台ip处查看，这样既不需要使用固定ip跳板代理访问，又能取得较好的蜜罐隐蔽效果，

主要涵盖各类代码执行打点、持久化行为来进行进一步筛选，以提高0day/1day或者僵尸网络捕捉的专注性，并且，这种爬取+筛选的模式，挺方便对结果进行自己想要的操作的

## 用法：
```
pip install pypinyin

pip install openai==0.28

python3 honeypot_api.py --hfish_domain [你的Hfish平台ip或域名] --api_key [平台apikey，在后台自寻] --output_dir [输出html文件的文件夹] --openai_api_key [你的openai apikey(可选，如果不填写就没有gpt分析功能)]
```
![howtouse](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20241202101026.png)

# 效果展示
## 示例demo 
https://ba1100n.tech/honeypot/index.html

## 分类模式
筛选可能存在高价值exp的请求包单独一类，并按蜜罐种类进行分类
![show_result1](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20241202102135.png)

点击蜜罐种类内部，还会按时间进行进一步分类
![show_result2](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20241202102226.png)
## 0day/1day捕捉专注
高价值exp抓到的东西类似如下，有时候可以分析一下是不是0day
![image.png](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20241202102418.png)
![image.png](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20241202102555.png)
(如果给定openai key才会有analysis，否则没有，这个功能最大的好处目前看来是可以帮助提取一下ioc，或者提供基础的分析，但看起来3.5有时候分析并不算精确)
## 僵尸网络行为捕捉
是的，经常会抓到僵尸网络的行为，比如这里能看到mozi僵尸网络，又在传播恶意样本了👁️
![show_result3](https://balloonblogsrcs.oss-cn-shanghai.aliyuncs.com/20241202101208.png)
# 总结
还不完美，欢迎使用和提需求改进

也可以直接看demo那个网站，不需要自己部署
