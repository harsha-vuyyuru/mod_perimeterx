![image](https://843a2be0f3083c485676508ff87beaf088a889c0-www.googledrive.com/host/0B_r_WoIa581oY01QMWNVUElyM2M)

[PerimeterX](http://www.perimeterx.com) Apache Module
===========================================

Dependencies
----------------------------------------
- [openssl 1.0.1] (https://www.openssl.org/source/) 
- [libcurl](https://curl.haxx.se/docs/install.html) 
- [jansson 2.7](http://www.digip.org/jansson/)
- apxs (installed with ```apache2-dev``` package)

You can install dependencies using linux package manager (```yum``` / ```debian``` packages) or install them manually.

#### Ubuntu users:
```shell
$ sudo apt-get install libjansson-dev
$ sudo apt-get install libcurl4-openssl-dev
$ sudo apt-get install apache2-dev 
```

Installation
----------------------------------------
```shell
$ git clone https://github.com/PerimeterX/mod_perimeterx.git
$ cd mod_perimeterx
$ make
$ apache2ctl restart
```
#####Verify installation by listing all installed modules:

```shell
$ apache2ctrl -M
Loaded Modules:
 core_module (static)
 so_module (static)
 watchdog_module (static)
 http_module (static)
 ...
 perimeterx_module (shared)
```

## Directives ##

The directives should be under the server configuration.

### `PXEnabled` ###

when set to ```On``` the module will be applied on the requests.

### `AppId` ###
configure the application ID

### `CookieKey` ###
configure the cookie key.

### `AuthToken` ###
configure perimeterx API auth token.
### `BlockingScore` ###
Minimal score for blocking request, default to 70.

### `Captcha` ###

When On the blocking page served by this module will include captcha.

### `ReportPageRequest` ###

When set to ```On``` the server will send report perimeterx that a page was requested.

### `APITimeout` ###

API calls timeout in seconds, default to 0 (no timeout).

### `IPHeader` ###

In order to extract the real client IP we can define a specific header key. If not defined the IP will be extracted from [```useragent_ip```](https://ci.apache.org/projects/httpd/trunk/doxygen/structrequest__rec.html#a335167cb50483f6015c43e727771c1af)

### Example ###
```xml
<IfModule mod_perimeterx.c>
	PXEnabled On
	CookieKey my_key
	AppID my_app_id
	AuthToken my_auth_token
	BlockingScore 50
	ReportPageRequest On
	IPHeader X-Forwarded-For
</IfModule>
```
