<?php
/*
Plugin Name: Shibboleth Auth
Plugin URI: https://github.com/fuero/yourls-shibboleth
Description: This plugin enables use of Shibboleth's service provider for authentication
Version: 1.1
Author: fuero
Author URI: https://github.com/fuero
*/

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

if (!defined('SHIBBOLETH_UID'))
        define('SHIBBOLETH_UID', 'cn');
if (!defined('SHIBBOLETH_ENTITLEMENT'))
        define('SHIBBOLETH_ENTITLEMENT', 'entitlement');
if (!defined('SHIBBOLETH_ENTITLEMENT_REGEX'))
        define('SHIBBOLETH_ENTITLEMENT_REGEX', '/^.*urn:mace:dir:entitlement:yourls.local:.*$/');
if (!defined('SHIBBOLETH_RBAC_ALLOW')) {
        // Define constants for critical filters
        define( 'SHIBBOLETH_RBAC_ALLOW', 'filter_shibboleth_rbac_allow' );
}
if (!defined('SHIBBOLETH_RBAC_HASROLE'))
        define( 'SHIBBOLETH_RBAC_HASROLE', 'filter_shibboleth_rbac_hasrole' );

include_once( "rbac.php" );

// Hook our custom function into the 'shunt_is_valid_user' filter
yourls_add_filter( 'shunt_is_valid_user', 'shibboleth_is_valid_user' );

function shibboleth_is_valid_user() {
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
                        $salt = rand( 10000, 99999 );
                        $yourls_user_passwords[$_SERVER[SHIBBOLETH_UID]]='md5:' . $salt . ':' . md5($salt . $_SERVER[SHIBBOLETH_UID]);
                        yourls_store_cookie( YOURLS_USER );
                }
                return true;
        }
        return null;
}

