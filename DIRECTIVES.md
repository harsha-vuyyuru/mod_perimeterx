Directives
===========================================

- [Basic](#basic)
- [Filters](#filters)
- [Customizing block page](#blockpage)
- [Background activities send](#backgroundactivitiessend)
- [PerimeterX Service monitor](#servicemonitor)


## <a name="#basic"></a>Basic 

|Directive Name| Description   | Default value   | Values  | Note
|---|---|---|---|---|
| PXEnabled   | Flag for enabling \ disabling Perimeterx protection, Off - disabled, On - enabled	 | Off  | On / Off |
| AppId  | PX custom application id in the format of PX______	  | NULL | String  |
| CookieKey  | Key used for cookie signing - Can be found \ generated in PX portal - Policy page. | NULL  |   |   |
| AuthToken | JWT token used for REST API - Can be found \ generated in PX portal - Application page.  | NULL  | String |
| BlockingScore | When requests with a score equal to or higher value they will be blocked.  | 70  | 0 - 100  |
| Captcha | Enable reCaptcha on the blocking page  | On  | On / Off  | When using a custom block page with captcha abilities implementation, this option must be `On`.
| ReportPageRequest | Boolean flag to enable or disable sending activities and metrics to PerimeterX on each page request. Enabling this feature will provide data that populates the PerimeterX portal with valuable information	  |  On | On / Off  |
| APITimeoutMS |  REST API timeout in milliseconds | 1000  | Integer  | In case APITimeoutMS and APITimeout (deprecated but supported for backward compatibility) are both set in the module configuration - the one that is set later in the file will be the one that will be used. Any other value set prior of it will be discarded.
| IPHeader | List of HTTP header names that contain the real client IP address. Use this feature when your server is behind a CDN. | NULL | List |  [IPHeader Importacne](#ipheader)
| CurlPoolSize | The number of active curl handles for each server  | 40  | Integer 1-1000  | For optimized performance, it is best to use the number of running worker threads in your Apache server as the CurlPoolSize.
| BaseURL |  Determines PerimeterX server base URL. | https://sapi-\<app_id\>.perimeterx.net  | String |

#### <a name="ipheader">IPHeader Importacne</a>: 

* The order of headers in the configuration matters. The first header found with a value will be taken as the IP address.
* If no valid IP address is found in the IP header list, the module will use [`useragent_ip`](https://httpd.apache.org/docs/2.4/developer/new_api_2_4.html) as the request IP.

## <a name="blockpage"></a>Customizing block page:
| Directive Name |                                                                  Description                                                                  | Default value | Values |                                 Note                                 |
|:--------------:|:---------------------------------------------------------------------------------------------------------------------------------------------:|:-------------:|:------:|:--------------------------------------------------------------------:|
|  BlockPageURL  |                                                     [Explanation & Examples](BLOCKPAGE.md)                                                    |      NULL     | String | The block page URL should be specified as relative to `DocumentRoot` |
|   CustomLogo   | The logo will be displayed at the top div of the the block page. The logo's max-height property would be 150px and width would be set to auto. |      NULL     | String |                                                                      |
|     CSSRef     |              The block page can be modified with a custom CSS by adding the CSSRef directive and providing a valid URL to the css             |      NULL     | String |                                                                      |
|      JSRef     |  The block page can be added with custom JS file by adding JSRef directive and providing the JS file that will be loaded with the block page. |      NULL     | String |                                                                      |



## <a name="#filters"></a>Filters 

|     Directive Name    |                                                                                                Description                                                                                               | Default value |  Values  |          Note           |
|:---------------------:|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:-------------:|:--------:|:-----------------------:|
|    SensitiveRoutes    | List of routes the Perimeterx module will always do a server-to-server call for, even if the cookie score is low and valid                                                                               | Empty list    | List     |  /login                       |
| SensitiveRoutesPrefix | List of routes prefix. The PerimeterX module will always match request URI by this prefix list and if match was found will create a server-to-server call for, even if the cookie score is low and valid | Empty list    | List     |                         |
|   DisableModByEnvvar  | Disables the PerimeterX module if environment variable `PX_SKIP_MODULE` is set on the request.                                                                                                           | Off           | On / Off | [Examples and Use cases](#disablemodenvvar)  |
|   PXWhitelistRoutes   | A whitespace separated list of paths that will not be examined by PX module.                                                                                                                             | Empy list     | List     | /server-status /staging |
| PXWhitelistUserAgents | A whitespace separated list of User-Agents that will not be examined by PX module.                                                                                                                       | Empty list    | List     |                         |
| ExtensionWhitelist    | A whitespace separated list of file extensions that will not be examined by PX module. | .css, .bmp, .tif, .ttf, .docx, .woff2, .js, .pict, .tiff, .eot, .xlsx, .jpg, .csv,,.eps, .woff, .xls, .jpeg, .doc, .ejs, .otf, .pptx, .gif, .pdf, .swf, .svg, .ps,,.ico, .pls, .midi, .svgz, .class, .png, .ppt, .mid, webp, .jar. | List | When using this option, the default values are cleared and the supplied list will be used |
| EnableBlockingByHostname |     A whitespace separated list of hostnames that PX module will enable block for.     |                                                                                                              Empy list                                                                                                             | List | If this option is present - only hostnames appear in this list will pass through mod_perimeterx. |


#### <a name="disablemodenvvar"></a>DisableModByEnvvar Examples and Use cases:

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
 
**`mod_env` is not supported with this feature. Though the syntax is similar to mod_setenvif, the module is different. Mod_env will only run after the PerimeterX module in the Apache fixups phase. You should NOT use the `SetEnv` directive to set the `PX_SKIP_MODULE`

## <a name="#backgroundactivitiessend"></a> Background activities send

When `BackgroundActivitySend` is set to `On` - `page_requested` and `block` activities will be pushed to queue, each worker from the `BackgroundActivityWorkers` will consume this queue for activity and send it.

|        Directive Name       |                                                                   Description                                                                   | Default value |  Values  |                                                           Note                                                           |
|:---------------------------:|:-----------------------------------------------------------------------------------------------------------------------------------------------:|:-------------:|:--------:|:------------------------------------------------------------------------------------------------------------------------:|
|    BackgroundActivitySend   |  Boolean flag to allow background activity (page_requested / activity) send without blocking the original request from continue with processing |      Off      | On / Off |                                                                                                                          |
|  BackgroundActivityWorkers  | Number of worker thread in the thread pool that will handle the background send (fetching from activities queue and send to PerimeterX servers) |       10      |  Integer |                                                                                                                          |
| BackgroundActivityQueueSize |                                Activities queue size from which the workers will fetch activities from and send.                                |      1000     |  Integer | When queue reaches it's full capacity - the push operation will block until queue size is less than the max size we set. |


## <a name="#filters"></a>PerimeterX Service monitor

When `PXServiceMonitor` is set to `On` - the module will count errors from PerimeterX service and if the number of errors on the specific apache instance will reach `MaxPXErrorsThreshold` in `PXErrorsCountInterval` seconds - fail open strategy will be activated and the requests will pass PerimeterX module without causing any delays.

In the background there will be periodic health check with PerimeterX service and once service is healthy - the module will start handling requests again.

|     Directive Name    |                                                                                                        Description                                                                                                       | Default value |  Values  | Note |
|:---------------------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:-------------:|:--------:|:----:|
|    PXServiceMonitor   |                                     Boolean flag to allow self disable PerimeterX module when PerimeterX service is unhealthy and periodic examine the service until it is healthy.                                      |      Off      | On / Off |      |
|  MaxPXErrorsThreshold |                                                        Number  of allowed PerimeterX service errors (during an interval) until we will block the PerimeterX module                                                       |       10      |  Integer |      |
| PXErrorsCountInterval | Time interval - In milliseconds -  in which we will count any kind of non successful call for PerimeterX service - when time is reached, without reaching the MaxPXErrorsThreshold, the counter will be set back to zero |    60000 |  Integer |      |



