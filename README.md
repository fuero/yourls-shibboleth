Shibboleth authentication plugin
=============

This plugin will enable authentication with Shibboleth in [Yourls](http://yourls.org/).

Licensing
-------------
This plugin is licensed under the terms of the GNU General Public License, version 2 (GPLv2) or later.
License conditions are included in LICENSE or can be found at the [GNU website](http://www.gnu.org/licenses/gpl-2.0.html).

Prerequisites
-------------

If you have no idea what Shibboleth is, or what an IdP or an SP is,
familiarize yourself with the terms by reading [this](https://wiki.shibboleth.net/confluence/display/SHIB2/UnderstandingShibboleth).

 *   Shibboleth SP is installed and working properly
 *   IdP is releasing attributes used by plugin (by default: `cn`, `entitlement`)
 *   Verfied that this works with a short test page (see *Testing your shibboleth setup*)
 *   YOURLS >= 1.7

Installation
-------------

 *   Unzip this to YOURLS root folder
 *   Enable the plugin in yourls
 *   Configure httpd
        
    Your web server configuration need to be adjusted to accomodate Shibboleth.
    Here's a *sample* configuration you can use:

        # Protect admin area with Shibboleth
        <Location "/admin">
                AuthType shibboleth
                ShibRequestSetting requireSession 1
                require valid-user
                DirectoryIndex index.php
        </Location>
        # Protect stats too
        <LocationMatch "^/.*[+]$">
                AuthType shibboleth
                ShibRequestSetting requireSession 1
                require valid-user
        </LocationMatch>
        RewriteEngine on
        # Redirect 'http://yourls.local/' requests to admin area
        RewriteCond     %{REQUEST_URI}  ^/$
        RewriteRule     .*              /admin/                 [R,L]
        # Admin area or stats access is permitted over HTTPS only
        RewriteCond     %{REQUEST_URI}  ^/admin                 [OR]
        RewriteCond     %{REQUEST_URI}  ^/.*[+]$
        RewriteCond     %{HTTPS}        !=on
        RewriteRule     (.*)            https://yourls.local$1      [R,L]
        # Modified default rewrite rules for short urls.
        # Takes into account Shibboleth's service URLs, admin area, and
        # robots.txt.
        RewriteCond /path/to/yourls%{REQUEST_URI} !-f
        RewriteCond /path/to/yourls%{REQUEST_URI} !-d
        RewriteCond %{REQUEST_URI} !^/(?:shibboleth-sp|Shibboleth.sso)/
        RewriteRule ^(.*)$ /yourls-loader.php [L]

 *   Restart httpd for the changes to take effect.

Testing your shibboleth setup
-------------

Drop the following code in `admin/test-sp.php`:

    <html>
    <head><title>Shibboleth test</title></head>
    <body><pre><?php print_r($_SERVER); ?></pre>
    </body>
    </html>

Accessing this in your browser will yield something like this:

    Array
    (
        [SCRIPT_URL] => /admin/test-sp.php
        [SCRIPT_URI] => https://yourls.local/admin/test-sp.php
        [Shib-Application-ID] => default
        [Shib-Session-ID] => _d123456789eef1e35f96b29725731b2e6
        [Shib-Identity-Provider] => https://your-idp-host/idp/shibboleth
        [Shib-Authentication-Instant] => 2001-01-1T00:00:00.000Z
        [Shib-Authentication-Method] => urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
        [Shib-AuthnContext-Class] => urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
        [Shib-Session-Index] => _a4fa5ffe838191234567890c6ea23bd
        [cn] => your-user-id
        [entitlement] => urn:mace:dir:entitlement:yourls.local:admin
        [persistent-id] => some-persistent-id
        [HTTPS] => on
        [SSL_TLS_SNI] => yourls.local
        [HTTP_HOST] => yourls.local
        [HTTP_USER_AGENT] => Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:21.0) Gecko/20100101 Firefox/21.0
        [HTTP_ACCEPT] => text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
        [HTTP_ACCEPT_LANGUAGE] => en,en-us;q=0.7,de-at;q=0.3
        [HTTP_ACCEPT_ENCODING] => gzip, deflate
        [HTTP_COOKIE] => some-cookie-data 
        [HTTP_CONNECTION] => keep-alive
        [PATH] => /sbin:/usr/sbin:/bin:/usr/bin
        [SERVER_SIGNATURE] => Apache 
        [SERVER_SOFTWARE] => Apache
        [SERVER_NAME] => yourls.local
        [SERVER_ADDR] => 8.8.8.8
        [SERVER_PORT] => 443
        [REMOTE_ADDR] => 1.1.1.1
        [DOCUMENT_ROOT] => /path/to/yourls
        [SERVER_ADMIN] => root@localhost
        [SCRIPT_FILENAME] => /path/to/yourls/admin/test-sp.php
        [REMOTE_PORT] => 4711
        [REMOTE_USER] => some-persistent-id
        [AUTH_TYPE] => shibboleth
        [GATEWAY_INTERFACE] => CGI/1.1
        [SERVER_PROTOCOL] => HTTP/1.1
        [REQUEST_METHOD] => GET
        [QUERY_STRING] => 
        [REQUEST_URI] => /admin/test-sp.php
        [SCRIPT_NAME] => /admin/test-sp.php
        [PHP_SELF] => /admin/test-sp.php
        [PHP_AUTH_USER] => some-persistent-id
        [REQUEST_TIME] => 1366872110
    )

Verify that the attributes you want to specify for `SHIBBOLETH_ENTITLEMENT` and
`SHIBBOLETH_UID` are present and have reasonable values (example below):

    [cn] => your-user-id
    [entitlement] => urn:mace:dir:entitlement:yourls.local:admin

Configuration
-------------

Settings the plugin reads from `user/config.php` and their defaults:

    // Designates the attribute containing the username
    define('SHIBBOLETH_UID', 'cn');
    // The attribute controlling the user's roles for a SP, e.g. 'entitlement'. See attribute-map.xml
    define('SHIBBOLETH_ENTITLEMENT', 'entitlement');
    // A regular expression applied to SHIBBOLETH_ENTITLEMENT. Upon a match, the login page will be bypassed
    // and the user is granted access.
    define('SHIBBOLETH_ENTITLEMENT_REGEX', '/^.*urn:mace:dir:entitlement:yourls.local:.*$/');
    // Designates IP range(s) that will be assigned admin permissions
    $shibboleth_rbac_admin_ipranges = array(
            '127.0.0.0/8',
    );
    $shibboleth_rbac_role_assignment = array(
        "administrator" => "/^.*urn:mace:dir:entitlement:yourls.local:admin.*$/",
        "editor" => "/^.*urn:mace:dir:entitlement:yourls.local:editor.*$/",
        "contributor" => "/^.*urn:mace:dir:entitlement:yourls.local:contributor.*$/"
    );


Acknowledgements
-------------

`rbac.php` was almost entirely taken from nicwaller's Authorization Manager plugin for YOURLS
located [here](http://code.google.com/p/yourls-authmgr-plugin/)

Author
-------------
fuero <fuerob@gmail.com>

You wish to show me your appreciation? [Here](http://www.amazon.de/registry/wishlist/YCEEIYI1II4U/ref=cm_wl_act_vv?_encoding=UTF8&reveal=&visitor-view=1)'s my amazon wishlist.
