Directives
===========================================

- Basic:
	- [PXEnabled](#enabled)
	- [AppId](#appid)
	- [CookieKey](#cookiekey)
	- [AuthToken](#authtoken)
	- [BlockingScore](#blockingscore)
	- [Captcha](#captcha)
	- [ReportPageRequested](#reportpagerequested)
	- [APITimeout](#apitimeout)
	- [APITimeoutMS](#apitimeoutms)
	- [IPHeader](#ipheader)
	- [BlockPageURL](#blockpageurl)
	- [CurlPoolSize](#curlpoolsize)
	- [BaseURL](#baseurl)
- Filters: 
	- [DisableModByEnvvar](#disablemodbyenvvar)
	- [SensitiveRoutes](#sensitiveroutes)
	- [SensitiveRoutesPrefix](#sensitiveroutesprefix)
	- [PXWhitelistRoutes](#whitelistroutes)
	- [PXWhitelistUserAgents](#whitelistuseragents)
	- [ExtensionWhitelist](#extensionwhitelist)
	- [EnableBlockingByHostname](#blockingbyhostname)
- Customizing block page: 
	- [CustomLogo](#customlogo)
	- [CSSRef](#cssref)
	- [JSRef](#jsref)
- Background activities send: 
	- [BackgroundActivitySend](#backgroundactivitysend)
	- [BackgroundActivityWorkers](#backgroundactivityworkers)
	- [BackgroundActivityQueueSize](#backgroundactivityqueuesize)
- PerimeterX Service monitor:
	- [PXServiceMonitor](#pxervicemonitor)
	- [MaxPXErrorsThreshold](#maxpxerrorsthreshold)
	- [PXErrorsCountInterval](#pxerrorscountinterval)


### <a name="enabled"></a> `PXEnabled` ###
**description** : Enables the PerimeterX module

**required** : yes

**default** : Off

**values** : On|Off

When set to ```On``` the module will be applied on webpage requests.

### <a name="appid"></a> `AppId` ###

**description** : Unique application ID

**required** : yes

**default** : NULL

**values** : string

### <a name="cookiekey"></a> `CookieKey` ###
**description** : Cookie signing key

**required** : yes

**default** : NULL

**values** : string

### <a name="authtoken"></a> `AuthToken` ###
**description** : API authentication token

**required** : yes

**default** : NULL

**values** : string

### <a name="blockingscore"></a>`BlockingScore` ###
**description** : Blocking score. When requests with a score equal to or higher value they will be blocked.

**required** : No

**default** : 70

**values** : Integer between 0 and 100

### <a name="captcha"></a> `Captcha` ###

**description** : Enable reCaptcha on the blocking page. 

***Note***: When using a custom block page with captcha abilities implementation, this option must be `On`.

**required** : No

**default** : On

**values** : On | Off

### <a name="reportpagerequested"></a> `ReportPageRequest` ###

**description** : Enables the ablity to report page requests and blocking activities to PerimeterX.

**required** : No

**default** : On

**values** : On | Off

### <a name="apitimeout"></a> `APITimeoutMS` ###

**description** : Timeout, in *milliseconds*, for API  calls.

**required** : No

**default** : 1000

**values** : Integer

### <a name="apitimeout"></a> `APITimeout` ###
**description** : Timeout, in *seconds*, for API calls.

**required** : No

**default** : 1

**values** : Integer between 1 and 3

> Note: If APITimeout and APITimeoutMS are both set in the module configuration - the one that is set later in the file will be the one that will be used. Any other value set prior of it will be discarded.

### <a name="ipheader"></a> `IPHeader` ###

**description** : List of HTTP header names that contain the real client IP address. Use this feature when your server is behind a CDN.

**required** : No

**default** : NULL

**values** : List of strings

***Note***: 

* The order of headers in the configuration matters. The first header found with a value will be taken as the IP address.
* If no valid IP address is found in the IP header list, the module will use [`useragent_ip`](https://httpd.apache.org/docs/2.4/developer/new_api_2_4.html) as the request IP.


### <a name="blockpageurl"></a> `BlockPageURL`

The Apache module allows you to customize your blocking page.

Under this configuration, you need to specify the URL to a blocking page HTML file (relative to servers `DocumentRoot`).

This module will send a redirect response with the `Location` header in the following format: 

```
$host/$blockpageURL?url=${original_request_url}&uuid=${uuid}&vid=${vid}
```

The Visitor ID (vid) must be extracted from this URL for captcha JS snippet use (see below for explanation and example).

**required**: No. If not specified, the default block page will be used.

**default**: NULL

**value**: String

***Note***: When using a custom block page with captcha abilities implemented, the `Captcha` configuration option must be `On`.

#### Blocked user example: 

If I'm blocked when browsing to `http://www.mysite.com/coolpage`, and the server configuration is: 

```xml
BlockPageURL /block.html
```

Redirect URL will be: 

```
http://www.mysite.com/block.html&url=coolpage&uuid=uuid=e8e6efb0-8a59-11e6-815c-3bdad80c1d39&vid=08320300-6516-11e6-9308-b9c827550d47
```


When captcha is enabled, the block page **must** include the following:

###### Custom blockpage requirements:

* Inside `<head>` section:

```html
<script src="https://www.google.com/recaptcha/api.js"></script>
<script>
function handleCaptcha(response) {
    var vid = getQueryString("vid"); // getQueryString is implemented below
    var uuid = getQueryString("uuid");
    var name = '_pxCaptcha';
    var expiryUtc = new Date(Date.now() + 1000 * 10).toUTCString();
    var cookieParts = [name, '=', response + ':' + uuid + ':' + vid, '; expires=', expiryUtc, '; path=/'];
    document.cookie = cookieParts.join('');
    var originalURL = getQueryString("url");
    var originalHost = window.location.host;
    window.location.href = window.location.protocol + "//" +  originalHost + originalURL;
}

// http://stackoverflow.com/questions/901115/how-can-i-get-query-string-values-in-javascript
function getQueryString(name, url) {
    if (!url) url = window.location.href;
    name = name.replace(/[\[\]]/g, "\\$&");
    var regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)"),
            results = regex.exec(url);
    if (!results) return null;
    if (!results[2]) return '';
    return decodeURIComponent(results[2].replace(/\+/g, " "));
}
</script>
```
* Inside `<body>` section:

```
<div class="g-recaptcha" data-sitekey="6Lcj-R8TAAAAABs3FrRPuQhLMbp5QrHsHufzLf7b" data-callback="handleCaptcha" data-theme="dark"></div>
```

* [PerimeterX Javascript snippet](https://console.perimeterx.com/#/app/applicationsmgmt).

#### configuration example:
 
```xml
<IfModule mod_perimeterx.c>
	...
	BlockPageURL /blockpage.html
	...
</IfModule>
```

#### Block page implementation full example: 

```html
<html>
    <head>
        <script src="https://www.google.com/recaptcha/api.js"></script>
        <script>
        function handleCaptcha(response) {
            var vid = getQueryString("vid");
            var uuid = getQueryString("uuid");
            var name = '_pxCaptcha';
            var expiryUtc = new Date(Date.now() + 1000 * 10).toUTCString();
            var cookieParts = [name, '=', response + ':' + uuid + ':' + vid, '; expires=', expiryUtc, '; path=/'];
            document.cookie = cookieParts.join('');
            // after getting resopnse we want to reaload the original page requested
            var originalURL = getQueryString("url");
            var originalHost = window.location.host;
            window.location.href = window.location.protocol + "//" +  originalHost + originalURL;
        }
       
       // http://stackoverflow.com/questions/901115/how-can-i-get-query-string-values-in-javascript	
	function getQueryString(name, url) {
		if (!url) url = window.location.href;
		name = name.replace(/[\[\]]/g, "\\$&");
		var regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)"),
			results = regex.exec(url);
		if (!results) return null;
		if (!results[2]) return '';
		return decodeURIComponent(results[2].replace(/\+/g, " "));
	}
        </script>
    </head>
    <body>
        <h1>You are Blocked</h1>
        <p>Try and solve the captcha</p> 
        <div class="g-recaptcha" data-sitekey="6Lcj-R8TAAAAABs3FrRPuQhLMbp5QrHsHufzLf7b" data-callback="handleCaptcha" data-theme="dark"></div>
    </body>
<html>
```

### <a name="curlpoolsize"></a> `CurlPoolSize` ###
**description** : The number of active curl handles for each server

**required** : No

**default** : 40

**max**: 10000

**values** : Integer

> Note: For optimized performance, it is best to use the number of running worker threads in your Apache server as the CurlPoolSize.



### <a name="baseurl"></a> `BaseURL` ###
**description** : PerimeterX API server URL

**required** : No

**default** : https://collector.perimeterx.net

**values** : string

Determines PerimeterX server base URL.

### <a name="disablemodbyenvvar"></a> `DisableModByEnvvar` ###
**description** : Disables the PerimeterX module if environment variable `PX_SKIP_MODULE` is set on the request.

**required** : No

**default** : Off

**values** : On|Off

##### Examples

By using `mod_setenvif` you can configure a set of rules to set the `PX_SKIP_MODULE` variable on a request.

* Disable the PerimeterX module on either `gif` or `jpg` file extensions:
 
```
SetEnvIf Request_URI "\.gif$" PX_SKIP_MODULE true
SetEnvIf Request_URI "\.jpg$" PX_SKIP_MODULE true
```

* Disable the PerimeterX module according to the referer:

```
SetEnvIf Referer www\.mydomain\.example\.com PX_SKIP_MODULE true
```

* Disable the PerimeterX module on all `HEAD` requests:

```
SetEnvIf Request_Method HEAD PX_SKIP_MODULE true
```

* Disable the PerimeterX module based on the user-agent string:

```
SetEnvIf User-Agent good-bot PX_SKIP_MODULE true
```

Read more on `mod_setenvif` [here](https://httpd.apache.org/docs/current/mod/mod_setenvif.html).
 
**`mod_env` is not supported with this feature. Though the syntax is similiar to mod_setenvif, the module is different. Mod_env will only run after the PerimeterX module in the Apache fixups phase. You should NOT use the `SetEnv` directive to set the `PX_SKIP_MODULE` variable.**

### <a name="sensitiveroutes"></a> `SensitiveRoutes`

**descripotion** : List of routes the Perimeterx module will always do a server-to-server call for, even if the cookie score is low and valid. 

**required** : No

**default** : Empty list

**values** : A whitespace seperated list of strings.

**example** : `/api/checkout /users/login`

### <a name="sensitiveroutesprefix"></a>`SensitiveRoutesPrefix`

**descripotion** : List of routes prefix. The Perimeterx module will always match request uri by this prefix list and if match was found will create a server-to-server call for, even if the cookie score is low and valid. 

**required** : No

**default** : Empty list

**values** : A whitespace seperated list of strings.

**example** : `/api /users`


###<a name="whitelistroutes"></a> `PXWhitelistRoutes`

**descripotion** : A whitespace seperated list of paths that will not be examined by PX module. 

**required** : No

**default** : Empty list

**values** : A whitespace seperated list of strings.

**example** : `/server-status /staging`

### <a name="whitelistuseragent"></a> `PXWhitelistUserAgents`

**description** : A whitespace seperated list of User-Agents that will not be examined by PX module.

**required**: No

**default** : Empty list

**values** : A backspace delimited list of strings.

### <a name="extensionwhitelist"></a> `ExtensionWhitelist`

**description** : A whitespace seperated list of file extensions that will not be examined by PX module.

**required**: No

**default** : .css, .bmp, .tif, .ttf, .docx, .woff2, .js, .pict, .tiff, .eot, .xlsx, .jpg, .csv,
    .eps, .woff, .xls, .jpeg, .doc, .ejs, .otf, .pptx, .gif, .pdf, .swf, .svg, .ps,
    .ico, .pls, .midi, .svgz, .class, .png, .ppt, .mid, webp, .jar.
    
**Note**: When using this option, the default values are cleared and the supplied list will be used instead.

**values** : A whitespace delimited list of strings.

**example**: `.txt .css .jpeg`

### <a name="blockingbyhostname"></a>`EnableBlockingByHostname`

**description** : A whitespace seperated list of hostnames that PX module will enable block for.

**required**: No

**default** : Empty list
    
> **Note**: If this option is persent - only hostnames appear in this list will pass through mod_perimeterx.

**values** : A whitespace delimited list of strings.

**example**: `www.mysite.com www.mynewsite.com `

