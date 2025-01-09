import boto3
import json
import gzip
from datetime import datetime, timedelta, timezone
import time
import re
import requests
import urllib3
import logging
import base64
import hashlib
import hmac

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# qingteng webapi
BASE_URL = "https://qingteng.xxxx.com"
USERNAME = "api_user"
PASSWORD = "api_password"

# lark webhook api
webhook_url = "https://open.larksuite.com/open-apis/bot/v2/hook/aaaaaaa-bbbb-cccc-dddd-efefefefefef"
webhook_secret = "xxxxxxxxxxxxxxxxxx"

# proxies = {"http": "http://127.0.0.1:8083", "https": "http://127.0.0.1:8083"}
proxies = {}

class QingtengScan:
    def __init__(self, bucket_name):
        self.s3 = boto3.client('s3')
        self.bucket = bucket_name
        self.com_id = ""
        self.jwt_token = ""
        self.sign_key = ""
        self.timestamp = ""
        self.sign = ""
        self.req_session = requests.Session()
        self.req_session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
        })
        self.req_session.proxies.update(
            proxies
        )
        self.req_session.verify = False

        # 设置日志配置
        # logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logging = logging.basicConfig(filename='./log/scanner.log', level=logging.INFO,format='%(asctime)s - %(levelname)s - %(message)s')

    # 登录请求调用示例
    def login(self):
        try:
            url = BASE_URL + "/v1/api/auth"
            headers = {"Content-Type": "application/json"}
            body = {"username": USERNAME, "password": PASSWORD}

            r = self.req_session.post(url, data=json.dumps(body), headers=headers, verify=False, proxies=proxies)
            # print(r.text)
            j = json.loads(r.text)
            self.com_id = j["data"]["comId"]
            self.jwt_token = j["data"]["jwt"]
            self.sign_key = j["data"]["signKey"]
            self.req_session.headers.update({
                'Authorization': "Bearer " + self.jwt_token,
                'comId': self.com_id
            })
        except Exception as e:
            print(e)

    def do_sign(self, method, ts, data):
        """
        字符串签名
        @param method: 请求方法 GET、POST。。。
        @param ts: 时间戳
        @param data: 请求参数
        @return: 签名后的字符串
        """
        # 当前时间戳
        method = method.upper()
        if data is not None:
            info = ""
            if method == "GET":
                # 对参数key进行字典排序
                keys = sorted(data.keys())
                for key in keys:
                    info = info + key + str(data.get(key))
                    # print(info)
            elif method == "POST" or method == "PUT" or method == "DELETE":
                info = json.dumps(data)
            # 拼接待签名字符串
            to_sign = self.com_id + info + ts + self.sign_key
        else:
            # 拼接待签名字符串
            to_sign = self.com_id + ts + self.sign_key
        # print(to_sign)

        signed_str = hashlib.sha1(to_sign.encode()).hexdigest()
        return signed_str

    def get_agent(self, osname, ip):
        '''
        对于get请求，将请求参数按照参数名排序(自然升序)，将排序后的请求参数及值，和comId、timestamp、signKey按照以下形式拼接，得到string-to-sign
        :param osname: 平台类型：linux or windows
        :param ip: 待查询的IP地址
        :return: True or False：表示根据IP地址查询是否安装青藤agent
        '''
        flag = False
        try:
            if osname.lower() == "linux":
                url = BASE_URL + "/external/api/assets/host/linux"
            elif osname.lower() == "win":
                url = BASE_URL + "/external/api/assets/host/win"
            else:
                raise Exception('[!] osname must be one of win or linux')

            ts = str(int(time.time()))
            data = {
                # "page": "1",
                "ip": ip,
                # "sorts": "hostname"
            }
            sign_header = self.do_sign("get", ts, data)
            headers = {
                "timestamp": ts,
                "sign": sign_header
            }
            r = self.req_session.get(url, params=data, headers=headers)
            json_data = r.json()
            # if (ip == '10.20.11.227'):
            #     print(json_data)
            total_result_of_this_ip = json_data.get('total', 0)

            # 如果查询出来多个结果，需要遍历去确认IP是否一致
            if total_result_of_this_ip > 0:
                rows = json_data.get('rows', [])
                for row in rows:
                    internal_ip = row.get('internalIp')
                    #print("aws上的IP：%s -- 青藤上的IP：%s" % (ip, internal_ip))
                    # 将每个row里面的internal_ip和形参ip进行对比，一旦对比一致表示青藤已经安装
                    if internal_ip == ip:
                        flag = True
                        break
            #     if flag:
            #         logging.info("%s 已经安装青藤HIDS" % ip)
            #         print("%s 已经安装青藤HIDS" % ip)
            #     else:
            #         logging.error("%s 未安装青藤HIDS" % ip)
            #         print("%s 未安装青藤HIDS" % ip)
            #         #qt.send_lark(webhook_url, str(int(time.time())), webhook_secret, ip)
            # else:
            #     #说明当前IP在青藤api没查到任何结果，代表这个IP一定没有安装青藤
            #     logging.error("%s 未安装青藤HIDS" % ip)
            #     print("%s 未安装青藤HIDS" % ip)
            #     #qt.send_lark(webhook_url, str(int(time.time())), webhook_secret, ip)
        except Exception as e:
            print(e)

        return flag

    def send_lark(self, webhook_url, timestamp, secret, ipaddress, instance_state):
        '''
        给lark webhook推送消息的函数
        :param webhook_url: lark的webhook_url
        :param timestamp: 时间戳
        :param secret: lark的webhook_url的secret签名密钥
        :param aws_account: aws账号
        :param region: aws region
        :param ipaddress: IP地址
        :param instance_state: aws的实例状态
        :return: None
        '''
        # 拼接timestamp和secret
        string_to_sign = '{}\n{}'.format(timestamp, secret)
        hmac_code = hmac.new(string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
        # 对结果进行base64处理
        sign = base64.b64encode(hmac_code).decode('utf-8')
        headers = {
            "Content-Type": "application/json"
        }

        payload = {
            "timestamp": timestamp,
            "sign": sign,
            "msg_type": "text",
            "content": {
                "text": "IP: %s 未安装青藤agent, 该实例运行状态: %s" % (ipaddress, instance_state)
            }
        }

        response = requests.post(webhook_url, headers=headers, data=json.dumps(payload))

        print(response.text)
        # print(response.status_code)
        # if (response.status_code)
        # logging.info("lark webhook消息推送成功")

    def list_objects(self, pattern=r".*ConfigSnapshot.*\.json\.gz$", past_hours=24):
        """
        列出 S3 存储桶中符合指定模式且修改时间在过去指定小时内的对象

        Args:
            pattern: 文件名匹配模式
            past_hours: 考虑的时间范围（小时）
        """
        paginator = self.s3.get_paginator('list_objects_v2')
        page_iterator = paginator.paginate(Bucket=self.bucket)

        past_time = datetime.now(timezone.utc) - timedelta(hours=past_hours)

        for page in page_iterator:
            for obj in page.get('Contents', []):
                last_modified = obj['LastModified']
                if last_modified >= past_time and re.match(pattern, obj['Key']):
                    yield obj

    def parse_objects(self, objects):
        """
        解析 S3 对象中的 JSON 数据

        Args:
            objects: S3 对象列表
        """
        
        instance_count = 0

        for obj in objects:
            # obj：S3桶里面每一个.json.gz文件
            try:
                response = self.s3.get_object(Bucket=self.bucket, Key=obj['Key'])
                with gzip.open(response['Body'], 'rt') as f:
                    config_data = json.load(f) # config_data：.json.gz文件对应的json文本内容
                    for item in config_data['configurationItems']: # item表示上面json文件里面configurationItems的内容，里面包含各种AWS Config资源，其中就有个AWS::EC2::Instance
                        if item['resourceType'] == "AWS::EC2::Instance":
                            instance_count += 1
                            configuration_data = item['configuration'] # configuration_data：AWS::EC2::Instance类型的资源的configuration部分json内容

                            # 获取实例的类型
                            platform = configuration_data.get('platformDetails', '')
                            if 'linux' in platform.lower():
                                platform = 'linux'
                            else:
                                platform = 'windows'

                            success_flag = False
                            state_name = configuration_data['state']['name']
                            state_code = configuration_data['state']['code']

                            private_ips = set()  # 使用集合去重
                            # 通过下面5行代码，将AWS::EC2::Instance EC2实例资源的所有privateIpAddress都添加到set集合中
                            private_ips.add(configuration_data.get('privateIpAddress', ''))
                            for interface in configuration_data.get('networkInterfaces', []):
                                private_ips.add(interface.get('privateIpAddress', ''))
                                for ip in interface.get('privateIpAddresses', []):
                                    private_ips.add(ip.get('privateIpAddress', ''))

                            # 遍历所有的privateIpAddress，分别去hids接口查询是否安装agent，一旦有任何一个privateIpAddress查询到安装了，就修改标志位并结束循环
                            for ip in private_ips:
                                if qt.get_agent(platform, ip):
                                    success_flag = True
                                    break

                            # 如果标志位是True，表明该实例已经安装青藤Agent
                            if success_flag:
                                #logging.info("----------------------------------------------------")
                                #logging.info("%s 已经安装青藤agent" % ip)
                                logging.info(f"awsAccountId:{item['awsAccountId']}, awsRegion:{item['awsRegion']}, instanceId:{configuration_data['instanceId']}, platformDetails:{configuration_data['platformDetails']}, state:{configuration_data['state']['name']}, IP:{ip}, HidsAgent:已安装")
                                print("%s 已经安装青藤agent" % ip)
                            else:
                                #logging.error("%s 未安装青藤agent" % ip)
                                logging.info(f"awsAccountId:{item['awsAccountId']}, awsRegion:{item['awsRegion']}, instanceId:{configuration_data['instanceId']}, platformDetails:{configuration_data['platformDetails']}, state:{configuration_data['state']['name']},IP:{ip}, HidsAgent:未安装")
                                print("%s 未安装青藤agent" % ip)
                                if (state_code == 16):
                                    pass
                                    # 如果instance实例状态是16：running，就推送lark告警
                                    # qt.send_lark(webhook_url, str(int(time.time())), webhook_secret, ip, state_name) # 推送lark告警请打开这行
                                    # print("推送lark告警，ip：" + ip + "，实例状态：" + state_name)

                            # print(f"resourceType: {item['resourceType']}, instanceId: {configuration_data['instanceId']}, platformDetails: {configuration_data['platformDetails']}, state: {configuration_data['state']['name']}, privateIpAddresses: {list(private_ips)}")
                            # 打印每一台EC2实例的信息
                            #logging.info(f"awsAccountId: {item['awsAccountId']}, awsRegion: {item['awsRegion']}, instanceId: {configuration_data['instanceId']}, platformDetails: {configuration_data['platformDetails']}, state: {configuration_data['state']['name']}, privateIpAddresses: {list(private_ips)}")
            except Exception as e:
                print(f"Error processing {obj['Key']}: {e}")
        print(f"Total instances: {instance_count}")

    def list_and_parse(self, pattern=r".*ConfigSnapshot.*\.json\.gz$", past_hours=24):
        """
        组合方法，列出并解析 S3 对象

        Args:
            pattern: 文件名匹配模式
            past_hours: 考虑的时间范围（小时）
        """
        objects = self.list_objects(pattern, past_hours)
        self.parse_objects(objects)

if __name__ == '__main__':
    qt = QingtengScan('aws-s3-bucket-name')
    qt.login()
    qt.list_and_parse()

