Custom Block Page
===========================================
This section will discuss about implementing block page by the user. 

This is relevant only when `BlockPageURL` is set.

When BlockPageURL is set to some `$blockpageURL` - mod_perimeter will send a redirect response with the `Location` header in the following format: 

```
$host/$blockpageURL?url=${original_request_url}&uuid=${uuid}&vid=${vid}
```

The Visitor ID (vid) must be extracted from this URL for captcha JS snippet use (see below for explanation and example).

> Note: When using a custom block page with captcha abilities implemented, the `Captcha` configuration option must be `On`.

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

#### Configuration example:
 
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
	  <script type="text/javascript">
	    (function(){
	        window._pxAppId = $APP_ID;
	        // Custom parameters
	        // window._pxParam1 = "<param1>";
	        var p = document.getElementsByTagName('script')[0],
	            s = document.createElement('script');
	        s.async = 1;
	        s.src = '//client.perimeterx.net/$APP_ID/main.min.js';
	        p.parentNode.insertBefore(s,p);
	    }());
	 </script>
	 <noscript>
	    <div style="position:fixed; top:0; left:0; display:none" width="1" height="1">
	        <img src="//collector-$APP_ID.perimeterx.net/api/v1/collector/noScript.gif?appId=$APP_ID">
	    </div>
	</noscript>
    </body>
<html>
```