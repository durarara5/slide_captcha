# -*- coding:utf-8 -*-

import requests
from lxml import etree
import time
import re
import validate_image
from Crypto.Cipher import AES
from binascii import b2a_hex
from pkcs7 import PKCS7Encoder
import random

session = requests.session()
session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"
        }) 
tracedict = {}

def get_timestamp():
    return int(round(time.time() * 1000))

def download_img(imgurls,imgnames):
    for i,val in enumerate(imgurls):
        r = session.get(f"http://verifycode.58.com{val}", timeout=60)
        with open(f"{imgnames[i]}.jpg", 'wb') as f:
            f.write(r.content)

def load_trace():
    with open("trace.txt") as f:
        for t in f:
            splitlist = t.strip().split("=")
            value = tracedict.get(splitlist[0])
            if value:
                value.append(splitlist[1])
            else:
                tracedict[splitlist[0]] = [splitlist[1],]

def build_track(sildeoffset):
    if sildeoffset % 2 != 0:
        sildeoffset = sildeoffset - 1
    tracklist = tracedict.get(str(sildeoffset))
    trackoffset = sildeoffset #参考路径移动距离
    offsettype = 0 if trackoffset > 120 else 1 #找不到参考路径就向前后寻找
    while not tracklist:
        if trackoffset > 240 or trackoffset < 10:
            print('超出范围1')
            break #识别失败超出范围
        if offsettype:
            tracklist = tracedict.get(str(trackoffset + 2))
            trackoffset = trackoffset + 2
        else:
            tracklist = tracedict.get(str(trackoffset - 2))
            trackoffset = trackoffset - 2

    if not tracklist:
        return ""
    track = tracklist[random.randint(0,len(tracklist) - 1)]
    print("使用轨迹%s" % trackoffset)
    steplist = track.split('|')[0:-1]
    if trackoffset != sildeoffset:
        #移动距离不同，构造剩余或多余步数
        diffoffset = abs(trackoffset - sildeoffset)
        if diffoffset > 6:
            print('超出范围2')
            return "" #差距过大
        if trackoffset > sildeoffset:
            #轨迹多于滑动距离
            start_x = int(steplist[0].split(",")[0])
            end_x = sildeoffset + start_x
            for i in range(len(steplist) - 1,0,-1):
                cur_x = int(steplist[i].split(",")[0])
                if cur_x == end_x or cur_x < end_x:
                    steplist = steplist[0:i + 1]
                    break
        #补齐轨迹
        start_x = int(steplist[0].split(",")[0])
        end_x = sildeoffset + start_x
        curend_x = int(steplist[-1].split(",")[0])
        for i in range(0,int((end_x - curend_x) / 2)):
            laststep = steplist[-1].split(",")
            steplist.append(f"{end_x},{laststep[1]},{int(laststep[2])+random.randint(50,110)}")
        print("调整轨迹%s=>%s" % (trackoffset,sildeoffset))
    #最后一步停留一会
    #laststep_x,laststep_y,laststep_t = steplist[-1].split(",")
    #steplist.append(f"{laststep_x},{int(laststep_y)-random.randint(0,1)},{int(laststep_t)+random.randint(20,200)}")
    return "|".join(steplist) + "|"

def main():
    #从页面获取所需参数 保存验证码图片到本地
    url_getvalue = "http://callback.58.com/firewall/valid/2015689362.do?namespace=zufanglistphp&url=weishanjn.58.com%2fzufang%2f0%2f%3fsort%3dtime%26amp%3bsort_hack%3d1" #滑动验证码页面
    r = session.get(url_getvalue, timeout=60)
    selector = etree.HTML(r.text)
    uuid = selector.xpath("//input[@id='uuid']/@value")
    ip = selector.xpath("//input[@id='ip']/@value")
    if not uuid or not ip:
        print("未获取到参数")
        return
    url_getsid = f"http://callback.58.com//firewall/code/{ip[0]}/{uuid[0]}.do?{get_timestamp()}"
    r = session.get(url_getsid, timeout=60)
    sessionid = r.json()["data"]["sessionId"]
    url_getcaptcha = f"http://verifycode.58.com/captcha/getV3?callback=jQuery{get_timestamp()}_{get_timestamp()}&showType=win&sessionId={sessionid}&_={get_timestamp()}"
    r = session.get(url_getcaptcha, timeout=60)
    # jQuery1101043148205441808063_1526882096877({"message":"成功","data":{"responseId":"c1393e0f17f54cc0bb9e1c06e9ffde64","level":310,"status":0,"puzzleImgUrl":"/captcha/captcha_img?rid=c1393e0f17f54cc0bb9e1c06e9ffde64&it=_puzzle","tip":"请点击并将滑块拖动到指定位置","bgImgUrl":"/captcha/captcha_img?rid=c1393e0f17f54cc0bb9e1c06e9ffde64&it=_big"},"code":0})
    responseid = re.search(r'"responseId":"(?P<id>\S+?)"',r.text).group("id")
    callback = re.match(r'jQuery\d+_\d+',r.text).group()
    puzzleimgurl = re.search(r'"puzzleImgUrl":"(?P<url>\S+?)"',r.text).group("url") #96x270
    bigimgurl = re.search(r'"bgImgUrl":"(?P<url>\S+?)"',r.text).group("url") #480x270
    puzzleimgname,bigimgname = f"{responseid}_puzzle",f"{responseid}_big"
    download_img([puzzleimgurl,bigimgurl],[puzzleimgname,bigimgname])
    #获取滑动距离并构造鼠标轨迹
    sildeoffset = validate_image.get_offset(bigpath=bigimgname + '.jpg',puzzlepath=puzzleimgname + '.jpg')
    track = build_track(sildeoffset)
    if not track:
        return
    data = '{"x":"%s","track":"%s","p":"0,0"}' % (sildeoffset,track)
    key = responseid[:16].encode("utf-8")
    cipher = AES.new(key=key,mode=AES.MODE_CBC,IV=key)
    postdata = str(b2a_hex(cipher.encrypt(PKCS7Encoder(16).encode(data).encode('utf-8'))).upper(),encoding="utf-8")
    r = session.get(f"http://verifycode.58.com/captcha/checkV3?callback={callback}&responseId={responseid}&sessionId={sessionid}&data={postdata}&_={get_timestamp()}",timeout=90)
    print(r.text)
    return "成功" in r.text

if __name__ == "__main__":
    load_trace()
    success = 0
    for i in range(100):
        try:
            if main():
                success+=1
        except Exception as err:
            print("异常:%s" % err)
    print("成功率%f" % (success / 100))