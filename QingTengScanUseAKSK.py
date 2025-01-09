import time
import hashlib
import urllib3
import boto3
import json
import requests
import logging
import base64
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

class qingteng:
    def __init__(self):
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
        self.logging = logging.basicConfig(filename='./log/scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
            total_result_of_this_ip = json_data.get('total', 0)

            # 如果查询出来多个结果，需要遍历去确认IP是否一致
            if total_result_of_this_ip > 0:
                rows = json_data.get('rows', [])
                for row in rows:
                    internal_ip = row.get('internalIp')
                    # 将每个row里面的internal_ip和形参ip进行对比，一旦对比一致表示青藤已经安装
                    if internal_ip == ip:
                        flag = True
                        break
        except Exception as e:
            print(e)

        return flag

    def send_lark(self, webhook_url, timestamp, secret, aws_account, region, ipaddress, instance_state):
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
                "text": "Aws账号: %s , Region: %s , IP: %s 未安装青藤agent, 该实例运行状态: %s" % (aws_account, region, ipaddress, instance_state)
            }
        }

        response = requests.post(webhook_url, headers=headers, data=json.dumps(payload))

        print(response.text)

    def search_ec2_new(self, profile):
        '''
        主函数，循环遍历aws账号、region获取实例IP地址，并通过调用青藤API查询是否安装青藤aget
        :param profile: aws账号的profile
        :return: None
        '''
        session = boto3.Session(profile_name=profile)
        ec2_client = session.client('ec2')
        regions = ec2_client.describe_regions()['Regions']

        logging.info("账号 %s 包含 %d 可用regions" % (profile, len(regions)))
        for region in regions:
            regionName = region['RegionName']

            ec2_client = session.client('ec2', region_name=regionName)
            response = ec2_client.describe_instances()

            instance_count = 0

            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_count += 1
                    success_flag = False
                    privateIpAddress = ''
                    # 获取实例运行状态 The valid values are: 0 (pending), 16 (running), 32 (shutting-down), 48 (terminated), 64 (stopping), and 80 (stopped).
                    state_name = instance.get('State', {}).get('Name')
                    state_code = instance.get('State', {}).get('Code')

                    # 获取实例的PlatformDetails
                    platform = instance.get('PlatformDetails')
                    if 'linux' in platform.lower():
                        platform = 'linux'
                    else:
                        platform = 'windows'

                    # 提取每个网卡的 PrivateIpAddress 值
                    logging.info("账号: %s, Region: %s, instance: %s, state: %s 包含 %d 个网卡" % (profile, regionName, instance.get('InstanceId'), state_name, len(instance.get('NetworkInterfaces'))))
                    for net_interface in instance.get('NetworkInterfaces', []):
                        privateIpAddress = net_interface.get('PrivateIpAddress')
                        if qt.get_agent(platform, privateIpAddress):
                            success_flag = True
                            break

                    if success_flag:
                        logging.info("%s 已经安装青藤agent" % privateIpAddress)
                        print("%s 已经安装青藤agent" % privateIpAddress)
                    else:
                        logging.error("%s 未安装青藤agent" % privateIpAddress)
                        print("%s 未安装青藤agent" % privateIpAddress)
                        if (state_code == 16):
                            # 如果instance实例状态是16：running，就推送lark告警
                            qt.send_lark(webhook_url, str(int(time.time())), webhook_secret, profile, regionName, privateIpAddress, state_name)

            logging.info("当前扫描%s 账号，%s region，总共包含 %d EC2实例" % (profile, regionName, instance_count))
            print("当前扫描%s 账号，%s region，总共包含 %d EC2实例" % (profile, regionName, instance_count))


if __name__ == '__main__':
    environmentList = ['xxx-dev', 'xxx-stg', 'xxx-prod']
    qt = qingteng()
    qt.login()
    for env in environmentList:
        qt.search_ec2_new(env)
