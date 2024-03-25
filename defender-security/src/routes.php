<?php
if ( ! defined( 'ABSPATH' ) ) {
	die;
}

function defender_init_routes() {
	$routes = [
		'mask_login' => [
			'update_settings' => 'save_settings',
			'get_posts' => 'get_posts',
		],
		'security_headers' => [
			'update_settings' => 'save_settings',
		],
		'two_fa' => [
			'update_settings' => 'save_settings',
			'send_test_email' => 'send_test_email',
			'verify_otp_for_enabling' => 'verify_otp_for_enabling',
			'disable_totp' => 'disable_totp',
			'send_backup_code' => [ 'send_backup_code', true ],
			'generate_backup_codes' => 'generate_backup_codes',
		],
		'security_tweaks' => [
			'process' => 'process',
			'ignore' => 'ignore',
			'revert' => 'revert',
			'restore' => 'restore',
			'recheck' => 'recheck',
			'bulk_action' => 'bulk_action',
			'update_security_reminder' => 'update_security_reminder',
			'update_autogenerate_flag' => 'update_autogenerate_flag',
			'update_enabled_user_enums' => 'update_enabled_user_enums',
			'handle_notice' => 'handle_notice',
			'refuse_notice' => 'refuse_notice',
		],
		'ip_lockout' => [
			'update_settings' => 'save_settings',
			'download_geo_db' => 'download_geo_db',
			'import_ips' => 'import_ips',
			'query_locked_ips' => 'query_locked_ips',
			'ip_action' => 'ip_action',
			'export_ips' => 'export_ips',
			'empty_logs' => 'empty_logs',
			'dashboard_activation' => 'dashboard_activation',
			'import_ua' => 'import_ua',
			'export_ua' => 'export_ua',
			'empty_lockouts' => 'empty_lockouts',
			'verify_blocked_user' => [ 'verify_blocked_user', true ],
			'send_again' => [ 'send_again', true ],
		],
		'global_ip_lockout' => [
			'refresh_global_ip_list' => 'refresh_global_ip_list',
		],
		'scan' => [
			'start' => 'start',
			'cancel' => 'cancel',
			'process' => [ 'process', true ],
			'status' => 'status',
			'item_action' => 'item_action',
			'update_settings' => 'save_settings',
			'bulk_action' => 'bulk_action',
			'handle_notice' => 'handle_notice',
			'postpone_notice' => 'postpone_notice',
			'refuse_notice' => 'refuse_notice',
		],
		'audit' => [
			'update_settings' => 'save_settings',
			'pull_logs' => 'pull_logs',
			'summary' => 'summary',
			'export_as_csv' => 'export_as_csv',
		],
		'notification' => [
			'get_users' => 'get_users',
			'save_notification' => 'save_notification',
			'unscubscribe' => 'unsubscribe',
			'subscribe' => 'subscribe',
			'save_frequency' => 'save_frequency',
			'save_subscriber' => 'save_subscriber',
			'save_configs' => 'save_configs',
			'save_bulk_configs' => 'save_bulk_configs',
			'bulk_deactivate' => 'bulk_deactivate',
			'validate_email' => 'validate_email',
		],
		'dashboard' => [
			'hide_new_features' => 'hide_new_features',
			'activate_global_ip' => 'activate_global_ip',
			'remove_global_ip_notice_reminder' => 'remove_global_ip_notice_reminder',
		],
		'settings' => [
			'update_settings' => 'save_settings',
			'reset_settings' => 'reset_settings',
		],
		'waf' => [
			'recheck' => 'recheck',
		],
		'onboard' => [
			'activating' => 'activating',
			'skip' => 'skip',
		],
		'tutorial' => [
			'hide' => 'hide',
		],
		'blocklist_monitor' => [
			'blacklist_status' => 'blacklist_status',
			'toggle_blacklist_status' => 'toggle_blacklist_status',
		],
		'tracking' => [
			'close_track_modal' => 'close_track_modal',
			'save_track_modal' => 'save_track_modal',
		],
		'general_notice' => [
			'close_ip_detection_notice' => 'close_ip_detection_notice',
		],
	];

	if ( class_exists( 'WP_Defender\Controller\Quarantine' ) ) {
		$routes['quarantine'] = [
			'restore_file' => 'restore_file',
			'quarantine_collection' => 'quarantine_collection',
			'delete_file' => 'delete_file',
		];
	}

	foreach ( $routes as $module => $info ) {
		foreach ( $info as $name => $func ) {
			$nopriv = false;
			if ( is_array( $func ) ) {
				[ $func, $nopriv ] = $func;
			}
			\Calotes\Helper\Route::register_route(
				$name,
				$module,
				$name,
				[
					\Calotes\Helper\Array_Cache::get( $module ),
					$func,
				],
				$nopriv
			);
		}
	}
}

defender_init_routes();
