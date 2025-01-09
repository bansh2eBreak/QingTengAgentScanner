# QingTengAgentScanner

适用于企业内使用AWS云，并且部署了青藤云HIDS安全工具的情况。

## 1. 说明
介绍了两种进行青藤HIDS agent覆盖率监控的方式：
- 通过使用不同Aws Account账号的ak/sk进行服务器资产采集，然后通过青藤云API获取agent覆盖率
- 通过读取S3桶里面存储的Aws Config 数据进行服务器资产采集，然后通过青藤云API获取agent覆盖率

## 2. 使用方法
根据自己情况，补充如下配置信息，然后直接运行对应的py脚本即可。

 - BASE_URL = "https://qingteng.xxxx.com"
 - USERNAME = "api_user"
 - PASSWORD = "api_password"

和

 - webhook_url = "https://open.larksuite.com/open-apis/bot/v2/hook/aaaaaaa-bbbb-cccc-dddd-efefefefefef"
 - webhook_secret = "xxxxxxxxxxxxxxxxxx"

⚠️
如果是采用ak/sk进行服务器资产采集，需要您将公司所有Aws所有账号的ak/sk准备好；
如果是采用读取S3桶的方式进行服务器资产采集，需要您启用公司所有Aws账号的Aws Config并同步到S3桶。