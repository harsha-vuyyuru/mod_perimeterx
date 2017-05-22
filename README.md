[![Build Status](https://travis-ci.org/PerimeterX/mod_perimeterx.svg?branch=travisBuild)](https://travis-ci.org/PerimeterX/mod_perimeterx)

![image](https://s.perimeterx.net/logo.png)

[PerimeterX](http://www.perimeterx.com) Apache Module
===========================================

Table of Contents
-----------------

-   [Usage](#usage)
  -   [Dependencies](#dependencies)
  -   [Installation](#installation)
  -   [Basic Usage Example](#basic-usage)
- [Logging and Troubleshoot](#troubleshoot)
-   [Directives](DIRECTIVES.md)
-   [Contributing](#contributing)
  -   [Tests](#tests)


<a name="Usage"></a>

<a name="dependencies"></a> Dependencies
----------------------------------------
- [openssl 1.0.1](https://www.openssl.org/source/) 
- [libcurl >= 7.19.0](https://curl.haxx.se/docs/install.html) 
- [jansson 2.6](http://www.digip.org/jansson/)
- [Apache Portable Runtime (APR) >=1.4.6](https://apr.apache.org/)
- [pkg-config](https://en.wikipedia.org/wiki/Pkg-config)
- [json-c](https://github.com/json-c/json-c/wiki)

You can install dependencies using the Linux package manager (```yum``` / ```debian``` packages) or install them manually.

#### Ubuntu users:
```shell
$ sudo apt-get install libjansson-dev libjson0 libjson0-dev libssl-dev libcurl4-openssl-dev apache2-dev pkg-config
```

<a name="installation"></a>Installation
----------------------------------------
```shell
$ git clone https://github.com/PerimeterX/mod_perimeterx.git
$ cd mod_perimeterx/src
$ make
$ sudo make install
```

Make sure that the following line is added to your configuration file: 

`LoadModule perimeterx_module $MODULES_PATH/mod_perimeterx.so`

##### Verify installation by listing all installed modules:

```shell
$ httpd -M
Loaded Modules:
 core_module (static)
 so_module (static)
 watchdog_module (static)
 http_module (static)
 ...
 perimeterx_module (shared)
```

### <a name="basic-usage"></a> Basic usage example ###

* Configuration for apache server

```xml
<IfModule mod_perimeterx.c>
	# basic directives
    PXEnabled On
    CookieKey my_key
    AppID my_app_id
    AuthToken my_auth_token
    BlockingScore 90
    ReportPageRequest On
    IPHeader X-True-IP
    CurlPoolSize 100
    Captcha On

    # service monitor directives
    PXServiceMonitor On
    MaxPXErrorsThreshold 100
    PXErrorsCountInterval 30000 # 30 seconds
    
    # filter
    SensitiveRoutes /login
    PXWhitelistRoutes /server-status /staging
    PXWhitelistUserAgents "Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/534.34 (KHTML,  like Gecko) PhantomJS/1.9.0 (development) Safari/534.34"
    
    # background activities send
    BackgroundActivitySend On
    BackgroundActivityWorkers 100
    BackgroundActivityQueueSize 500
</IfModule>
```

* Configuration for specific VirtuaHost

```xml
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        <IfModule mod_perimeterx.c>
                PXEnabled On
                CookieKey my_key
                AppID my_app_id
                AuthToken my_auth_token
                BlockingScore 30
                ReportPageRequest On
                Captcha On
        </IfModule>
</VirtualHost>
```

<a name=""troubleshoot"></a>Logging and Troubleshoot
----------------------------------------
### Log
mod_perimeterx is writing to apace error log. 
In order to log debug messages to apache error log you should set the `LogLevel` [directive](https://httpd.apache.org/docs/2.4/mod/core.html#loglevel): 

```
# apache configuration
LogLevel debug
```

According to your apache configurations you should find in the error log mod_perimeters log, for example: 



<a name="contributing"></a> Contributing
----------------------------------------

The following steps are welcome when contributing to our project.
### Fork/Clone
First and foremost, [Create a fork](https://guides.github.com/activities/forking/) of the repository, and clone it locally.
Create a branch on your fork, preferably using a self descriptive branch name.

### Code/Run
Code your way out of your mess, and help improve our project by implementing missing features, adding capabilites or fixing bugs.

To run the code, simply follow the steps in the [installation guide](#installation). Grab the keys from the PerimeterX Portal, and try refreshing your page several times continously. If no default behaviours have been overriden, you should see the PerimeterX block page. Solve the CAPTCHA to clean yourself and start fresh again.

### Pull Request
After you have completed the process, create a pull request to the Upstream repository. Please provide a complete and thorough description explaining the changes. Remember this code has to be read by our maintainers, so keep it simple, smart and accurate.

### Thanks
After all, you are helping us by contributing to this project, and we want to thank you for it.
We highly appreciate your time invested in contributing to our project, and are glad to have people like you - kind helpers.
