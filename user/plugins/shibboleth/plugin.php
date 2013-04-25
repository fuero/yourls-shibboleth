<?php
/*
Plugin Name: Shibboleth Auth
Plugin URI: https://github.com/fuero/yourls-shibboleth
Description: This plugin enables use of Shibboleth's service provider for authentication
Version: 1.0
Author: Robert Führicht
Author URI: https://github.com/fuero
*/

if (!defined('SHIBBOLETH_UID'))
        define('SHIBBOLETH_UID', 'cn');
if (!defined('SHIBBOLETH_ENTITLEMENT'))
        define('SHIBBOLETH_ENTITLEMENT', 'entitlement');
if (!defined('SHIBBOLETH_ENTITLEMENT_REGEX'))
        define('SHIBBOLETH_ENTITLEMENT_REGEX', '/^.*urn:mace:dir:entitlement:yourls.local:admin.*$/');

// Hook our custom function into the 'user_auth' filter
yourls_add_action( 'user_auth', 'shibboleth_user_auth' );

// Add a new link in the DB, either with custom keyword, or find one
function shibboleth_user_auth() {
        global $yourls_user_passwords;
        // Check for attributes set by mod_shib
        if (isset( $_SERVER[SHIBBOLETH_UID] ) && isset( $_SERVER[SHIBBOLETH_ENTITLEMENT] ) && 
                // Check if entitlement matches regex
                preg_match(SHIBBOLETH_ENTITLEMENT_REGEX, $_SERVER[SHIBBOLETH_ENTITLEMENT]))
        {
                // Notify various yourls stages
                yourls_do_action( 'pre_login' );
                yourls_do_action( 'pre_login_username_password' );
                yourls_do_action( 'login' );
                yourls_set_user( $_SERVER[SHIBBOLETH_UID] );
                if ( !yourls_is_API() ) {
                        // Satisfy yourls' cookie generation routine
                        $yourls_user_passwords[$_SERVER[SHIBBOLETH_UID]]=md5($_SERVER[SHIBBOLETH_UID]);
                        yourls_store_cookie( YOURLS_USER );
                }
                return true;
        }
}

