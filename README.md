# QingTengAgentScanner

适用于企业内使用AWS云，并且部署了青藤云HIDS安全工具的情况。

## 1. 说明
介绍了两种进行青藤HIDS agent覆盖率监控的方式：
- 通过不同aws account的ak/sk进行服务器资产扫描，然后通过青藤云API获取agent覆盖率
- 通过S3桶里面存储的aws config 数据进行服务器资产扫描，然后通过青藤云API获取agent覆盖率

## 2. 使用方法
根据自己情况，补充如下配置信息，然后直接运行对应的py脚本即可。

BASE_URL = "https://qingteng.xxxx.com"

USERNAME = "api_user"

PASSWORD = "api_password"

和

webhook_url = "https://open.larksuite.com/open-apis/bot/v2/hook/aaaaaaa-bbbb-cccc-dddd-efefefefefef"

webhook_secret = "xxxxxxxxxxxxxxxxxx"
