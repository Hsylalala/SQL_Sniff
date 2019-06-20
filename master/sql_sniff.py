# -- coding: utf-8 --
from scapy.all import *
import re
import urllib
def check(test):
        # 获取应用层的字段列表中的TCP中的数据对象名
    for i in test.payload.payload.payload.fields_desc:
        # 获取TCP包的传输信息返回的是字符串类型
        value = test.payload.payload.getfieldval(i.name)
        # print value
        if 'HTTP' in value:
            # 如果列表里包含有HTTP字眼，则对列表里的字符串按\r\n进行分割，并返回分割后的字符串列表
            lst = value.split('\r\n')
            # print lst
            if len(lst) > 0:
                if 'GET' in lst[0]:
                    # 获取GET请求,返回列表类型
                    Get = re.findall(r"\/\?(.*) HTTP", lst[0])
                    # 取出列表值
                    if len(Get) > 0:
                        url = Get[0]
                        a = url.replace("id=1", "")
                        # print a
                        # print "--------------------"

                        with open("./log.txt", "a") as file:
                             file.write(a + '\n')
                        with open("./sql_rule.txt") as file:
                            line = file.readline()
                            while line:
                                # 去除txt文档中的回车换行
                                line = line.replace("\r", "")
                                line = line.replace("\n", "")
                                line = urllib.quote(line)
                                # 匹配get传入语句
                                res = re.search(str(line), str(url))
                                if res is None:
                                    pass
                                else:
                                    print "发现了GET型SQL注入，注入语句为:" + url
                                    time = datetime.now()
                                    print "时间为："+ str(time)
                                    if 'Host' in lst[1]:
                                        ip = re.findall(r"Host: (.*)", lst[1])
                                        print "被攻击的IP地址为:"+ ip[0]
                                    elif 'Host' in lst[2]:
                                        ip = re.findall(r"Host: (.*)", lst[2])
                                        print "被攻击的IP地址为:" + ip[0]
                                line = file.readline()

                elif 'POST' in lst[0]:
                    print lst[-1]
                    if not lst[-1] == None:
                        post = lst[-1]
                        with open("./sql.txt") as file:
                            line = file.readline()
                            while line:
                                line = line.replace("\r", "")
                                line = line.replace("\n", "")
                                line = urllib.quote_plus(line)
                                res = re.search(str(line), str(post))
                                if res is None:
                                    pass
                                else:
                                    print "发现了POST型SQL注入，注入语句为:" + post
                                    time = datetime.now()
                                    print "时间为：" + str(time)
                                    ip = re.findall(r"Host: (.*)", lst[1])
                                    print "IP地址为:" + ip[0]
                                line = file.readline()



def main():
    sniff(filter='host 10.60.17.69', iface="VMware Virtual Ethernet Adapter for VMnet8", prn=check, count=0)


if __name__ == '__main__':
    main()


