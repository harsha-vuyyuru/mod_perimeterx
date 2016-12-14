Multiple configurations per VirtualHost
------------------
> This folder contains an example of a implementing multiple sets of configurations in a single Apache server.
> Multiple configurations is done using VirtualHosts, please follow the instruction and the added configuration file.

In order to implement multiple sets of configurations on a single server:

1. Create [multiple VirtualHosts](https://httpd.apache.org/docs/2.4/vhosts/examples.html) on your configuration file
2. Put the following configuration block under every VirtualHost:

```xml
## Site 1 - active blocking
<VirtualHost *:80>
        DocumentRoot /var/www/html1
        <IfModule mod_perimeterx.c>
                PXEnabled On
                CookieKey my_key1
                AppID my_app_id1
                AuthToken my_auth_token1
                BlockingScore 80
                BlockPageURL /block
                ReportPageRequest On
                Captcha On
        </IfModule>
</VirtualHost>

## Site 2 - no blocking, different account parameters
<VirtualHost *:8080>
        DocumentRoot /var/www/html2
        <IfModule mod_perimeterx.c>
                PXEnabled On
                CookieKey my_key2
                AppID my_app_id2
                AuthToken my_auth_token2
                BlockingScore 101
                ReportPageRequest On
                Captcha On
        </IfModule>
</VirtualHost>
```