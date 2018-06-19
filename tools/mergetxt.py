# -*- coding:utf-8 -*-
import os

#合并路径文件
tlist = os.listdir("c:/58trace")
with open("c:/trace.txt","a",encoding="utf-8") as tf:
    for t in tlist:
        with open("c:/58trace/"+t,"r",encoding="utf-16") as f:
            tf.write(f.read()+"\n")