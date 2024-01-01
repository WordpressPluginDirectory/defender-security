<?php

namespace WP_Defender\Controller;

use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Component\Config\Config_Hub_Helper;
use WP_Defender\Component\Quarantine;
use WP_Defender\Component\IP\Global_IP;
use WP_Defender\Event;
use WP_Defender\Model\Lockout_Log;
use WP_Defender\Model\Notification\Audit_Report;
use WP_Defender\Model\Notification\Firewall_Notification;
use WP_Defender\Model\Notification\Firewall_Report;
use WP_Defender\Model\Notification\Malware_Notification;
use WP_Defender\Model\Notification\Malware_Report;
use WP_Defender\Model\Notification\Tweak_Reminder;
use WP_Defender\Model\Setting\Blacklist_Lockout;
use WP_Defender\Model\Setting\Global_Ip_Lockout;
use WP_Defender\Model\Setting\Login_Lockout;
use WP_Defender\Model\Setting\Notfound_Lockout;
use WP_Defender\Model\Setting\User_Agent_Lockout;
use WP_Defender\Model\Setting\Two_Fa;
use WP_Defender\Model\Setting\Audit_Logging as Model_Audit_Logging;
use WP_Defender\Traits\Formats;
use WP_Defender\Traits\IO;

/**
 * Class HUB
 * @package WP_Defender\Controller
 */
class HUB extends Event {
	use IO, Formats;

	private $view_onboard = false;

	public function __construct() {
		$this->attach_behavior( WPMUDEV::class, WPMUDEV::class );
		add_action( 'wdp_register_hub_action', [ &$this, 'add_hub_endpoint' ] );
		add_action( 'defender_hub_sync', [ &$this, 'hub_sync' ] );
	}

	public function add_hub_endpoint( $actions ) {
		$actions['defender_new_scan'] = [ &$this, 'new_scan' ];
		$actions['defender_schedule_scan'] = [ &$this, 'schedule_scan' ];
		$actions['defender_manage_audit_log'] = [ &$this, 'manage_audit_log' ];
		$actions['defender_manage_lockout'] = [ &$this, 'manage_lockout' ];
		$actions['defender_whitelist_ip'] = [ &$this, 'whitelist_ip' ];
		$actions['defender_blacklist_ip'] = [ &$this, 'blacklist_ip' ];
		$actions['defender_get_scan_progress'] = [ &$this, 'get_scan_progress' ];
		$actions['defender_manage_recaptcha'] = [ &$this, 'manage_recaptcha' ];
		$actions['defender_manage_2fa'] = [ &$this, 'manage_2fa' ];
		$actions['defender_manage_global_ip_list'] = [ &$this, 'manage_global_ip_list' ];
		$actions['defender_set_global_ip_list'] = [ &$this, 'set_global_ips' ];

		// Backup/restore settings.
		$actions['defender_export_settings'] = [ &$this, 'export_settings' ];
		$actions['defender_import_settings'] = [ &$this, 'import_settings' ];
		// Get stats, version#1.
		$actions['defender_get_stats'] = [ &$this, 'get_stats' ];
		// Version#2.
		$actions['defender_get_stats_v2'] = [ &$this, 'defender_get_stats_v2' ];

		$actions['defender_get_quarantined_files'] = [ &$this, 'get_quarantined_files' ];
		$actions['defender_restore_quarantined_file'] = [ &$this, 'restore_quarantined_file' ];

		return $actions;
	}

	/**
	 * Create new scan, triggered from HUB.
	 */
	public function new_scan() {
		$scan = \WP_Defender\Model\Scan::create();
		if ( is_wp_error( $scan ) ) {
			wp_send_json_error(
				[
					'message' => $scan->get_error_message(),
				]
			);
		}
		//Todo: need to save Malware_Report last_sent & est_timestamp?
		/**
		 * @var Scan
		 */
		$scan_controller = wd_di()->get( Scan::class );

		$scan_controller->scan_started_analytics(
			[
				'Triggered From' => 'Hub',
				'Scan Type' => 'Manual',
			]
		);

		$scan_controller->do_async_scan( 'hub' );

		wp_send_json_success();
	}

	/**
	 * Schedule a scan, from HUB.
	 *
	 * @param array $params
	 */
	public function schedule_scan( $params ) {
		$frequency = $params['frequency'];
		$day = $params['day'];
		$time = $params['time'];
		$allowed_freq = [ 1, 7, 30 ];
		if (
			! in_array( $frequency, $allowed_freq, true )
			|| ! in_array( $day, $this->get_days_of_week(), true )
			|| ! in_array( $time, $this->get_times(), true )
		) {
			wp_send_json_error();
		}
		$malware_report = new Malware_Report();
		$malware_report->frequency = $frequency;
		$malware_report->day = $day;
		$malware_report->time = $time;
		$malware_report->save();

		wp_send_json_success();
	}

	/**
	 * @param bool $is_active       New feature's state.
	 * @param string $feature_title Feature's title.
	 */
	protected function track_feature_from_hub( bool $is_active, string $feature_title ) {
		$event = $is_active ? 'def_feature_activated' : 'def_feature_deactivated';
		$data = [
			'Feature' => $feature_title,
			'Triggered From' => 'Hub',
		];

		$this->track_feature( $event, $data );
	}

	public function manage_audit_log() {
		$response = null;
		if ( class_exists( Model_Audit_Logging::class ) ) {
			$settings = new Model_Audit_Logging();
			$response = [];
			if ( true === $settings->enabled ) {
				$settings->enabled = false;
				$response['enabled'] = false;
			} else {
				$settings->enabled = true;
				$response['enabled'] = true;
			}
			$settings->save();
			// Track.
			if ( $this->is_tracking_active() ) {
				$this->track_feature_from_hub( ! $settings->enabled, 'Audit Logging' );
			}
		}

		wp_send_json_success( $response );
	}

	/**
	 * @param array  $params
	 * @param string $action
	 */
	public function manage_lockout( $params, $action ) {
		$type = $params['type'];
		$response = [];
		if ( 'login' === $type ) {
			$settings = new Login_Lockout();
			if ( $settings->enabled ) {
				$settings->enabled = false;
				$response[ $type ] = 'disabled';
			} else {
				$settings->enabled = true;
				$response[ $type ] = 'enabled';
			}
			$settings->save();
			$feature = 'Login Protection';
		} elseif ( '404' === $type ) {
			$settings = new Notfound_Lockout();
			if ( $settings->enabled ) {
				$settings->enabled = false;
				$response[ $type ] = 'disabled';
			} else {
				$settings->enabled = true;
				$response[ $type ] = 'enabled';
			}
			$settings->save();
			$feature = '404 Detection';
		} elseif ( 'ua-lockout' === $type ) {
			$settings = new User_Agent_Lockout();
			if ( $settings->enabled ) {
				$settings->enabled = false;
				$response[ $type ] = 'disabled';
			} else {
				$settings->enabled = true;
				$response[ $type ] = 'enabled';
			}
			$settings->save();
		} else {
			$response[ $type ] = 'invalid';
		}
		// Track. Only for Login & NF Lockouts.
		if ( $this->is_tracking_active() && in_array( $type, [ 'login', '404', true ] ) ) {
			$event = $settings->enabled ? 'def_feature_deactivated' : 'def_feature_activated';
			$data = [
				'Feature' => $feature,
				'Triggered From' => 'Hub',
			];

			$this->track_feature( $event, $data );
		}

		wp_send_json_success( $response );
	}

	/**
	 * @param array  $params
	 * @param string $action
	 */
	public function whitelist_ip( $params, $action ) {
		$settings = new Blacklist_Lockout();
		$ip = $params['ip'];
		if ( $ip && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			$settings->remove_from_list( $ip, 'blocklist' );
			$settings->add_to_list( $ip, 'allowlist' );
		} else {
			wp_send_json_error();
		}
		wp_send_json_success();
	}

	/**
	 * @param array  $params
	 * @param string $action
	 */
	public function blacklist_ip( $params, $action ) {
		$settings = new Blacklist_Lockout();
		$ip = $params['ip'];
		if ( $ip && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			$settings->remove_from_list( $ip, 'allowlist' );
			$settings->add_to_list( $ip, 'blocklist' );
		} else {
			wp_send_json_error();
		}
		wp_send_json_success();
	}

	/**
	 * Push data into HUB. It's without timezone.
	 *
	 * @param array  $params
	 * @param string $action
	 */
	public function get_stats( $params, $action ) {
		$data = $this->build_stats_to_hub();
		wp_send_json_success(
			[ 'stats' => $data ]
		);
	}

	/**
	 * Push scan data into HUB.
	 */
	public function get_scan_progress() {
		$model = \WP_Defender\Model\Scan::get_active();
		if ( ! is_object( $model ) ) {
			wp_send_json_success(
				[ 'progress' => - 1 ]
			);
		}
		$percent = $model->percent;
		if ( $percent > 100 ) {
			$percent = 100;
		}
		wp_send_json_success(
			[ 'progress' => $percent ]
		);
	}

	/**
	 * Export settings to HUB.
	 * Analog to export_strings but return not array. So separated method.
	 */
	public function export_settings() {
		$config_component = wd_di()->get( \WP_Defender\Component\Backup_Settings::class );
		$data = $config_component->parse_data_for_hub();
		// Replace all the new line in configs.
		$configs = $data['configs'];
		foreach ( $configs as $module => $mdata ) {
			foreach ( $mdata as $key => $value ) {
				if ( is_string( $value ) ) {
					$value = str_replace( [ "\r", "\n" ], '{nl}', $value );
					$mdata[ $key ] = $value;
				}
			}
			$configs[ $module ] = $mdata;
		}
		$data['configs'] = $configs;
		wp_send_json_success( $data );
	}

	/**
	 * Import settings from HUB.
	 * Analog to import_data but with object $params. So separated method.
	 */
	public function import_settings( $params ) {
		// Dirty but quick.
		if ( empty( $params->configs ) ) {
			wp_send_json_error(
				[ 'message' => __( 'Invalid config', 'defender-security' ) ]
			);
		}

		$configs = json_decode( json_encode( $params->configs ), true );
		if ( empty( $configs ) ) {
			wp_send_json_error(
				[ 'message' => __( 'Empty data', 'defender-security' ) ]
			);
		}

		$config_component = wd_di()->get( \WP_Defender\Component\Backup_Settings::class );
		$lockout_service = wd_di()->get( \WP_Defender\Component\Blacklist_Lockout::class );
		foreach ( $configs as $module => $mdata ) {
			foreach ( $mdata as $key => $value ) {
				// Todo: update logic to import/export whitelisted/blocklisted countries via maxmind_license_key.
				if ( in_array( $key, [ 'geoIP_db', 'geodb_path' ], true ) ) {
					if ( ! empty( $value ) ) {
						// Download it.
						$lockout_service->is_geodb_downloaded();
					} else {
						// Reset it.
						$mdata[ $key ] = '';
					}
				} elseif ( is_string( $value ) ) {
					$value = str_replace( '{nl}', PHP_EOL, $value );
					$mdata[ $key ] = $value;
				}
			}
			$configs[ $module ] = $mdata;
		}

		// If it's old config structure then we upgrade configs to new format.
		if ( ! empty( $configs ) && ! $config_component->check_for_new_structure( $configs ) ) {
			$adapter = wd_di()->get( \WP_Defender\Component\Config\Config_Adapter::class );
			$configs = $adapter->upgrade( $configs );
		}
		$restore_result = $config_component->restore_data( $configs, 'hub' );
		if ( is_string( $restore_result ) ) {
			wp_send_json_error(
				[ 'message' => $restore_result ]
			);
		}

		// Active config.
		Config_Hub_Helper::active_config_from_hub_id( (int) $params->hub_config_id );

		wp_send_json_success();
	}

	/**
	 * Build the json data for HUB 2.0.
	 */
	public function defender_get_stats_v2() {
		global $wp_version;

		$audit_log = wd_di()->get( Audit_Logging::class );
		$audit = $audit_log->summary_data( true );

		$scan = \WP_Defender\Model\Scan::get_last();
		$total = 0;
		if ( is_object( $scan ) ) {
			$total += count( $scan->get_issues() );
		}
		// Total number of Scan issues and Ignored items.
		$scan_total_issues = $total;

		$tweaks = wd_di()->get( Security_Tweaks::class )->data_frontend();
		$total += $tweaks['summary']['issues_count'];
		// Get statuses of login/404/ua-request if Firewall Notification is enabled.
		$firewall_notification = wd_di()->get( Firewall_Notification::class );

		if ( 'enabled' === $firewall_notification->status ) {
			$login_lockout = $firewall_notification->configs['login_lockout'];
			$nf_lockout = $firewall_notification->configs['nf_lockout'];
			// @since 3.3.0.
			$ua_lockout = $firewall_notification->configs['ua_lockout'] ?? false;
		} else {
			$login_lockout = $nf_lockout = $ua_lockout = false;// phpcs:ignore
		}

		$status_active = \WP_Defender\Model\Notification::STATUS_ACTIVE;
		$model_sec_headers = wd_di()->get( \WP_Defender\Model\Setting\Security_Headers::class );
		$scan_report = wd_di()->get( Malware_Report::class );
		$two_fa = wd_di()->get( Two_Fa::class );

		$quarantined_files = class_exists( 'WP_Defender\Component\Quarantine' ) ?
			wd_di()->get( Quarantine::class )->hub_list() : [];

		$ret = [
			'summary' => [
				'count' => $total,
				'next_scan' => $scan_report->get_next_run_for_hub(),
			],
			'report' => [
				'malware_scan' => $scan_report->get_next_run_as_string( true ),
				'firewall' => wd_di()->get( Firewall_Report::class )->get_next_run_as_string( true ),
				'audit_logging' => wd_di()->get( Audit_Report::class )->get_next_run_as_string( true ),
			],
			'security_tweaks' => [
				'issues' => $tweaks['summary']['issues_count'],
				'fixed' => $tweaks['summary']['fixed_count'],
				'notification' => wd_di()->get( Tweak_Reminder::class )->status === $status_active,
				'wp_version' => $wp_version,
				'php_version' => PHP_VERSION,
			],
			'malware_scan' => [
				'count' => $scan_total_issues,
				'notification' => wd_di()->get( Malware_Notification::class )->status === $status_active,
			],
			'firewall' => [
				'last_lockout' => Lockout_Log::get_last_lockout_date( true ),
				'24_hours' => [
					'login_lockout' => Lockout_Log::count(
						strtotime( '-24 hours' ),
						time(),
						[ Lockout_Log::AUTH_LOCK ]
					),
					'404_lockout' => Lockout_Log::count(
						strtotime( '-24 hours' ),
						time(),
						[ Lockout_Log::LOCKOUT_404 ]
					),
					'user_agent_lockout' => Lockout_Log::count(
						strtotime( '-24 hours' ),
						time(),
						[ Lockout_Log::LOCKOUT_UA ]
					),
				],
				'7_days' => [
					'login_lockout' => Lockout_Log::count_login_lockout_last_7_days(),
					'404_lockout' => Lockout_Log::count_404_lockout_last_7_days(),
					'user_agent_lockout' => Lockout_Log::count_ua_lockout_last_7_days(),
				],
				'30_days' => [
					'login_lockout' => Lockout_Log::count(
						strtotime( '-30 days' ),
						time(),
						[ Lockout_Log::AUTH_LOCK ]
					),
					'404_lockout' => Lockout_Log::count(
						strtotime( '-30 days' ),
						time(),
						[ Lockout_Log::LOCKOUT_404 ]
					),
					'user_agent_lockout' => Lockout_Log::count(
						strtotime( '-30 days' ),
						time(),
						[ Lockout_Log::LOCKOUT_UA ]
					),
				],
				'notification_status' => [
					'login_lockout' => $login_lockout,
					'404_lockout' => $nf_lockout,
					'ua_lockout' => $ua_lockout,
				],
				'login_lockout_enabled' => wd_di()->get( Login_Lockout::class )->enabled,
				'lockout_404_enabled' => wd_di()->get( Notfound_Lockout::class )->enabled,
				'user_agent_lockout_enabled' => wd_di()->get( User_Agent_Lockout::class )->enabled,
				'global_ip_list_enabled' => wd_di()->get( Global_Ip_Lockout::class )->enabled,
			],
			'audit' => [
				'last_event' => $audit['lastEvent'],
				'24_hours' => $audit['dayCount'],
				'7_days' => $audit['weekCount'],
				'30_days' => $audit['monthCount'],
				'enabled' => $audit_log->model->is_active(),
			],
			'advanced_tools' => [
				'security_headers' => [
					'sh_xframe' => $model_sec_headers->sh_xframe,
					'sh_xss_protection' => $model_sec_headers->sh_xss_protection,
					'sh_content_type_options' => $model_sec_headers->sh_content_type_options,
					'sh_strict_transport' => $model_sec_headers->sh_strict_transport,
					'sh_referrer_policy' => $model_sec_headers->sh_referrer_policy,
					'sh_feature_policy' => $model_sec_headers->sh_feature_policy,
				],
				'mask_login' => wd_di()->get( \WP_Defender\Model\Setting\Mask_Login::class )->is_active(),
				'google_recaptcha' => [
					'status' => wd_di()->get( \WP_Defender\Model\Setting\Recaptcha::class )->is_active(),
				],
				'password_protection' => [
					'status' => wd_di()->get( \WP_Defender\Model\Setting\Password_Protection::class )->is_active(),
				],
			],
			'two_fa' => [
				'status' => $two_fa->enabled,
				'lost_phone' => $two_fa->lost_phone,
			],
			'quarantined_files' => $quarantined_files,
		];

		wp_send_json_success(
			[ 'stats' => $ret ]
		);
	}

	public function hub_sync() {
		$data = $this->build_stats_to_hub();
		$this->make_wpmu_request(
			WPMUDEV::API_HUB_SYNC,
			$data,
			[ 'method' => 'POST' ]
		);
	}

	public function remove_settings() {}

	public function remove_data() {}

	public function data_frontend() {}

	public function to_array() {}

	public function import_data( $data ) {}

	/**
	 * @return array
	 */
	public function export_strings(): array {
		return [];
	}

	/**
	 * Display Onboard if the bool value 'true' and vice versa.
	 * @param bool $is_show
	 */
	public function set_onboarding_status( $is_show ) {
		$this->view_onboard = $is_show;
	}

	/**
	 * @return bool
	 */
	public function get_onboarding_status(): bool {
		return $this->view_onboard;
	}

	/**
	 * Activate/deactivate reCaptcha from HUB.
	 */
	public function manage_recaptcha() {
		$response = null;
		if ( class_exists( \WP_Defender\Model\Setting\Recaptcha::class ) ) {
			$settings = new \WP_Defender\Model\Setting\Recaptcha();
			$response = [];
			if ( true === $settings->enabled ) {
				$settings->enabled = false;
				$response['enabled'] = false;
			} else {
				$settings->enabled = true;
				$response['enabled'] = true;
			}
			$settings->save();
			// Track.
			if ( $this->is_tracking_active() ) {
				$this->track_feature_from_hub( ! $settings->enabled, 'Google reCAPTCHA' );
			}
		}
		wp_send_json_success( $response );
	}

	/**
	 * Activate/deactivate 2FA from HUB.
	 */
	public function manage_2fa() {
		$response = null;
		if ( class_exists( Two_Fa::class ) ) {
			$settings = wd_di()->get( Two_Fa::class );
			$response = [];
			if ( true === $settings->enabled ) {
				$settings->enabled = false;
				$response['enabled'] = false;
			} else {
				$settings->enabled = true;
				$response['enabled'] = true;
			}
			$settings->save();
			// Track.
			if ( $this->is_tracking_active() ) {
				$this->track_feature_from_hub( ! $settings->enabled, 'Two-Factor Authentication' );
			}
		}

		wp_send_json_success( $response );
	}

	/**
	 * Activate/deactivate Global IP list from HUB.
	 *
	 * @param object $params
	 *
	 * @since 3.4.0
	 * @return void
	 */
	public function manage_global_ip_list( object $params ): void {
		if ( ! isset( $params->enable ) ) {
			wp_send_json_error(
				[ 'message' => __( 'Missing parameter(s)', 'defender-security' ) ]
			);
		}

		$response = null;
		if ( class_exists( Global_Ip_Lockout::class ) ) {
			$settings = wd_di()->get( Global_Ip_Lockout::class );

			$response = [];
			if ( true === $params->enable ) {
				$settings->enabled = true;
				$response['enabled'] = true;
			} else {
				$settings->enabled = false;
				$response['enabled'] = false;
			}
			$settings->save();
		}
		wp_send_json_success( $response );
	}

	/**
	 * Set Global IP list.
	 *
	 * @param object $params
	 *
	 * @since 3.4.0
	 * @return void
	 */
	public function set_global_ips( object $params ): void {
		$global_ip_component = wd_di()->get( Global_IP::class );
		$result = $global_ip_component->set_global_ip_list( (array) $params );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error(
				[
					'message' => implode( ' ', $result->get_error_messages() ),
				]
			);
		}

		wp_send_json_success(
			[ 'enabled' => $global_ip_component->is_global_ip_enabled() ]
		);
	}

	/**
	 * Get recent quarantined files.
	 */
	public function get_quarantined_files(): void {
		if ( ! class_exists( 'WP_Defender\Component\Quarantine' ) ) {
			$result = [
				'message' => defender_quarantine_pro_only(),
				'success' => false,
			];

			wp_send_json_error( $result );
		}

		/**
		 * @var Quarantine
		 */
		$quarantine_obj = wd_di()->get( Quarantine::class );

		$quarantined_files = $quarantine_obj->hub_list();

		wp_send_json_success(
			[ 'quarantined_files' => $quarantined_files ]
		);
	}

	/**
	 * Hub action callback to handle quarantined file restoring process.
	 */
	public function restore_quarantined_file( object $params ): void {
		if ( ! class_exists( 'WP_Defender\Component\Quarantine' ) ) {
			$result = [
				'message' => defender_quarantine_pro_only(),
				'success' => false,
			];

			wp_send_json_error( $result );
		}

		if ( isset( $params->id ) ) {
			$id = (int) $params->id;

			/**
			 * @var Quarantine
			 */
			$quarantine_obj = wd_di()->get( Quarantine::class );

			$result = $quarantine_obj->restore_file( $id );

			if ( isset( $result['success'] ) && $result['success'] === false ) {
				wp_send_json_error( $result );
			}

			wp_send_json_success( $result );
		}

		wp_send_json_error(
			[
				'message' => __( 'Missing parameter: id.', 'defender-security' ),
			]
		);
	}

	/**
	 * Handle plugin deactivation.
	 *
	 * @param string $plugin Path to the plugin file relative to the plugins directory.
	 *
	 * @return void
	 */
	public function intercept_deactivate( $plugin ) {
		if ( ! $this->is_tracking_active() ) {
			return;
		}

		// Only if Defender.
		if ( DEFENDER_PLUGIN_BASENAME !== $plugin ) {
			return;
		}

		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';

		// Deactivated from WPMUDEV Dashboard.
		if ( 'wdp-project-deactivate' === $action ) {
			$triggered_from = 'Plugin deactivation - dashboard';
		} elseif ( 'deactivate' === $action ) {
			// Deactivated from WP plugins page.
			$triggered_from = 'Plugin deactivation - wpadmin';
		} elseif ( $this->is_hub_request() ) {
			$triggered_from = 'Plugin deactivation - hub';
		} else {
			$triggered_from = 'Unknown';
		}

		// Send plugin deactivation event.
		$this->track_opt_toggle( false, $triggered_from );
	}
}
