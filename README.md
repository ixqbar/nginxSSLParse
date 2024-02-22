# nginxSSLParse

```
NAME:
   nginxSslParse - 扫描检查ssl证书过期时间

USAGE:
   nginxSslParse [global options] command [command options] [arguments...]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --domain value  
   --folder value  
   --suffix value  (default: "conf")
   --day value     (default: 30)
   --help          show help
```

* https://www.toutiao.com/article/7295621320380465690


```
openssl x509 -in bundle.crt -noout -dates
```

### thanks
* https://github.com/usysrc/ssl-expiry
