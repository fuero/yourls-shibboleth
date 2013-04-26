<?php
/*
Taken from nicwaller's Authorization Manager plugin located here:
http://code.google.com/p/yourls-authmgr-plugin/
*/

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

/****************** SET UP CONSTANTS ******************/

// Define constants used for naming roles (but they don't work in config.php)
class ShibbolethRbacRoles {
        const Administrator = 'Administrator';
        const Editor = 'Editor';
        const Contributor = 'Contributor';
}

// Define constants used for naming capabilities
class ShibbolethRbacCapability {
        const ShowAdmin = 'ShowAdmin'; // only display admin panel
        const AddURL = 'AddURL';
        const DeleteURL = 'DeleteURL';
        const EditURL = 'EditURL';
        const ManagePlugins = 'ManagePlugins';
        const API = 'API';
        const ViewStats = 'ViewStats';
}

/********** Add hooks to intercept functionality in CORE ********/

yourls_add_action( 'load_template_infos', 'shibboleth_rbac_intercept_stats' );
function shibboleth_rbac_intercept_stats() { shibboleth_rbac_require_capability( ShibbolethRbacCapability::ViewStats ); }

yourls_add_action( 'api', 'shibboleth_rbac_intercept_api' );
function shibboleth_rbac_intercept_api() { shibboleth_rbac_require_capability( ShibbolethRbacCapability::API ); }

yourls_add_action( 'admin_init', 'shibboleth_rbac_intercept_admin' );
function shibboleth_rbac_intercept_admin() {
        shibboleth_rbac_require_capability( ShibbolethRbacCapability::ShowAdmin );

        // we use this GET param to send up a feedback notice to user
        if ( isset( $_GET['access'] ) && $_GET['access']=='denied' ) {
                yourls_add_notice('Access Denied');
        }

        $action_capability_map = array(
                'add' => ShibbolethRbacCapability::AddURL,
                'delete' => ShibbolethRbacCapability::DeleteURL,
                'edit_display' => ShibbolethRbacCapability::EditURL,
                'edit_save' => ShibbolethRbacCapability::EditURL,
                'activate' => ShibbolethRbacCapability::ManagePlugins,
                'deactivate' => ShibbolethRbacCapability::ManagePlugins,
        );

        // intercept requests for plugin management
        if ( isset( $_REQUEST['plugin'] ) ) {
                $action_keyword = $_REQUEST['action'];
                $cap_needed = $action_capability_map[$action_keyword];
                if ( $cap_needed !== NULL && shibboleth_rbac_have_capability( $cap_needed ) !== true) {
                        yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
                }
        }

        // also intercept AJAX requests
        if ( yourls_is_Ajax() ) {
                $action_keyword = $_REQUEST['action'];
                $cap_needed = $action_capability_map[$action_keyword];
                if ( shibboleth_rbac_have_capability( $cap_needed ) !== true) {
                        $err = array();
                        $err['status'] = 'fail';
                        $err['code'] = 'error:authorization';
                        $err['message'] = 'Access Denied';
                        $err['errorCode'] = '403';
                        echo json_encode( $err );
                        die();
                }
        }
}

yourls_add_filter( 'logout_link', 'shibboleth_rbac_html_append_roles' );
function shibboleth_rbac_html_append_roles( $original ) {
        $authenticated = yourls_is_valid_user();
        if ( $authenticated === true ) {
                $listcaps = implode(', ', shibboleth_rbac_enumerate_current_capabilities());
                return '<div title="'.$listcaps.'">'.$original.'</div>';
        } else {
                return $original;
        }
}

/**************** CAPABILITY TEST/ENUMERATION ****************/

/*
 * If capability is not permitted in current context, then abort.
 * This is the most basic way to intercept unauthorized usage.
 */
function shibboleth_rbac_require_capability( $capability ) {
        if ( !shibboleth_rbac_have_capability( $capability ) ) {
                // TODO: display a much nicer error page
                //die('Sorry, you are not authorized for the action: '.$capability);
                yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
                die();
        }
}

/*
 * Returns array of capabilities currently available.
 */
function shibboleth_rbac_enumerate_current_capabilities() {
        $current_capabilities = array();
        $all_capabilities = shibboleth_rbac_enumerate_all_capabilities();
        
        foreach ( $all_capabilities as $cap ) {
                if ( shibboleth_rbac_have_capability( $cap ) ) {
                        $current_capabilities[] = $cap;
                }
        }
        
        return $current_capabilities;
}

function shibboleth_rbac_enumerate_all_capabilities() {
        // TODO: generalize this, instead of just repeating the total declaration
        return array(
                ShibbolethRbacCapability::ShowAdmin,
                ShibbolethRbacCapability::AddURL,
                ShibbolethRbacCapability::DeleteURL,
                ShibbolethRbacCapability::EditURL,
                ShibbolethRbacCapability::ManagePlugins,
                ShibbolethRbacCapability::API,
                ShibbolethRbacCapability::ViewStats,
        );
}

/*
 * Is the requested capability permitted in this context?
 */
function shibboleth_rbac_have_capability( $capability ) {
        return yourls_apply_filter( SHIBBOLETH_RBAC_ALLOW, false, $capability);
}

/******************* FILTERS THAT GRANT CAPABILITIES *****************************/
/*  By filtering SHIBBOLETH_RBAC_ALLOW, you can grant capabilities without using roles.  */
/*********************************************************************************/

/*
 * What capabilities are always available, including anonymous users?
 */
yourls_add_filter( SHIBBOLETH_RBAC_ALLOW, 'shibboleth_rbac_check_anon_capability', 5 );
function shibboleth_rbac_check_anon_capability( $original, $capability ) {
        global $shibboleth_rbac_anon_capabilities;

        // Shortcut - trust approval given by earlier filters
        if ( $original === true ) return true;

        // Make sure the anon rights list has been setup
        shibboleth_rbac_environment_check();

        // Check list of capabilities that don't require authentication
        return in_array( $capability, $shibboleth_rbac_anon_capabilities );
}

/*
 * What capabilities are available through role assignments to the active user?
 */
yourls_add_filter( SHIBBOLETH_RBAC_ALLOW, 'shibboleth_rbac_check_user_capability', 10 );
function shibboleth_rbac_check_user_capability( $original, $capability ) {
        global $shibboleth_rbac_role_capabilities;

        // Shortcut - trust approval given by earlier filters
        if ( $original === true ) return true;

        // ensure $shibboleth_rbac_role_capabilities has been set up
        shibboleth_rbac_environment_check();

        // If the user is not authenticated, then give up because only users have roles.
        $authenticated = yourls_is_valid_user();
        if ( $authenticated !== true )
                return false;

        // Enumerate the capabilities available to this user through roles
        $user_caps = array();
        
        foreach ( $shibboleth_rbac_role_capabilities as $rolename => $rolecaps ) {
                        if ( shibboleth_rbac_user_has_role( YOURLS_USER, $rolename ) ) {
                                        $user_caps = array_merge( $user_caps, $rolecaps );
                        }
        }
        $user_caps = array_unique( $user_caps );

        // Is the desired capability in the enumerated list of capabilities?
        return in_array( $capability, $user_caps );
}

/*
 * If the user is connecting from an IP address designated for admins,
 * then all capabilities are automatically granted.
 * 
 * By default, only 127.0.0.0/8 (localhost) is an admin range.
 */
yourls_add_filter( SHIBBOLETH_RBAC_ALLOW, 'shibboleth_rbac_check_admin_ipranges', 15 );
function shibboleth_rbac_check_admin_ipranges( $original, $capability ) {
        global $shibboleth_rbac_admin_ipranges;

        // Shortcut - trust approval given by earlier filters
        if ( $original === true ) return true;

        // ensure $shibboleth_rbac_admin_ipranges is setup
        shibboleth_rbac_environment_check();

        foreach ($shibboleth_rbac_admin_ipranges as $range) {
                if ( shibboleth_rbac_cidr_match( $_SERVER['REMOTE_ADDR'], $range ) )
                        return true;
        }

        return $original; // effectively returns false
}

/*
 * What capabilities are available when making API requests without a username?
 */
yourls_add_filter( SHIBBOLETH_RBAC_ALLOW, 'shibboleth_rbac_check_apiuser_capability', 15 );
function shibboleth_rbac_check_apiuser_capability( $original, $capability ) {
        // Shortcut - trust approval given by earlier filters
        if ( $original === true ) return true;

        // In API mode and not using user/path authn? Let it go.
        if ( yourls_is_API() && !isset($_REQUEST['username']) )
                return true;
        // TODO: add controls for actions, like
        // shorturl, stats, db-stats, url-stats, expand

        return $original;
}

/******************** ROLE TEST AND ENUMERATION ***********************/

/*
 * Determine whether a specific user has a role.
 */
function shibboleth_rbac_user_has_role( $username, $rolename ) {
        return yourls_apply_filter( SHIBBOLETH_RBAC_HASROLE, false, $username, $rolename );
}

// ******************* FILTERS THAT GRANT ROLE MEMBERSHIP *********************
// By filtering SHIBBOLETH_RBAC_HASROLE, you can connect internal roles to something else.
// Any filter handlers should execute as quickly as possible.

/*
 * What role memberships are defined for the user in user/config.php?
 */
yourls_add_filter( SHIBBOLETH_RBAC_HASROLE, 'shibboleth_rbac_user_has_role_in_config');
function shibboleth_rbac_user_has_role_in_config( $original, $username, $rolename ) {
        global $shibboleth_rbac_role_assignment;

        // if no role assignments are created, grant everything
        // so the site still works even if stuff is configured wrong
        if ( empty( $shibboleth_rbac_role_assignment ) )
                return true;

        // do this the case-insensitive way
        // the entire array was made lowercase in environment check
        $username = strtolower($username);
        $rolename = strtolower($rolename);

        // if the role doesn't exist, give up now.
        if ( !in_array( $rolename, array_keys( $shibboleth_rbac_role_assignment ) ) )
                return false;
        return preg_match($shibboleth_rbac_role_assignment[$rolename], $_SERVER[SHIBBOLETH_ENTITLEMENT]);
}


/********************* VALIDATE CONFIGURATION ************************/

function shibboleth_rbac_environment_check() {
        global $shibboleth_rbac_anon_capabilities;
        global $shibboleth_rbac_role_capabilities;
        global $shibboleth_rbac_role_assignment;

        if ( !isset( $shibboleth_rbac_anon_capabilities) ) {
                $shibboleth_rbac_anon_capabilities = array(
                        ShibbolethRbacCapability::API,
                        ShibbolethRbacCapability::ShowAdmin,//TODO: hack! how to allow logon page?
                );
        }

        if ( !isset( $shibboleth_rbac_role_capabilities) ) {
                $shibboleth_rbac_role_capabilities = array(
                        ShibbolethRbacRoles::Administrator => array(
                                ShibbolethRbacCapability::ShowAdmin,
                                ShibbolethRbacCapability::AddURL,
                                ShibbolethRbacCapability::DeleteURL,
                                ShibbolethRbacCapability::EditURL,
                                ShibbolethRbacCapability::ManagePlugins,
                                ShibbolethRbacCapability::API,
                                ShibbolethRbacCapability::ViewStats,
                        ),
                        ShibbolethRbacRoles::Editor => array(
                                ShibbolethRbacCapability::ShowAdmin,
                                ShibbolethRbacCapability::AddURL,
                                ShibbolethRbacCapability::EditURL,
                                ShibbolethRbacCapability::DeleteURL,
                                ShibbolethRbacCapability::ViewStats,
                        ),
                        ShibbolethRbacRoles::Contributor => array(
                                ShibbolethRbacCapability::ShowAdmin,
                                ShibbolethRbacCapability::AddURL,
                                ShibbolethRbacCapability::ViewStats,
                        ),
                );
        }

        if ( !isset( $shibboleth_rbac_role_assignment ) ) {
                $shibboleth_rbac_role_assignment = array(
                        "administrator" => "/^.*urn:mace:dir:entitlement:yourls.local:admin.*$/",
                        "editor" => "/^.*urn:mace:dir:entitlement:yourls.local:editor.*$/",
                        "contributor" => "/^.*urn:mace:dir:entitlement:yourls.local:contributor.*$/"
                );
        }

        if ( !isset( $shibboleth_rbac_iprange_roles ) ) {
                $shibboleth_rbac_admin_ipranges = array(
                        '127.0.0.0/8',
                );
        }

        // convert role assignment table to lower case if it hasn't been done already
        // this makes searches much easier!
        // TODO: avoid doing this every time we validate
        $shibboleth_rbac_role_assignment = array_map('strtolower', $shibboleth_rbac_role_assignment);
        return true;
}

// ***************** GENERAL UTILITY FUNCTIONS ********************

/*
 * Borrowed from:
 * http://stackoverflow.com/questions/594112/matching-an-ip-to-a-cidr-mask-in-php5
 */
function shibboleth_rbac_cidr_match($ip, $range)
{
    list ($subnet, $bits) = split('/', $range);
    $ip = ip2long($ip);
    $subnet = ip2long($subnet);
    $mask = -1 << (32 - $bits);
    $subnet &= $mask; # nb: in case the supplied subnet wasn't correctly aligned
    return ($ip & $mask) == $subnet;
}
