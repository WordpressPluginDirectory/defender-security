<?php
/**
 * Handle HUB based functionalities of WPMUDEV class.
 *
 * @package WP_Defender\Behavior
 */

namespace WP_Defender\Traits;

use Exception;
use WP_Defender\Component\Quarantine;
use WP_Defender\Controller\Firewall;
use WP_Defender\Controller\Security_Headers;
use WP_Defender\Controller\Security_Tweaks;
use WP_Defender\Model\Audit_Log;
use WP_Defender\Model\Notification;
use WP_Defender\Model\Notification\Audit_Report;
use WP_Defender\Model\Notification\Firewall_Report;
use WP_Defender\Model\Notification\Malware_Report;
use WP_Defender\Model\Notification\Firewall_Notification;
use WP_Defender\Model\Scan;
use WP_Defender\Model\Setting\Scan as Scan_Settings;
use WP_Defender\Model\Setting\Audit_Logging;
use WP_Defender\Model\Setting\Login_Lockout;
use WP_Defender\Model\Setting\Mask_Login;
use WP_Defender\Model\Setting\Notfound_Lockout;
use WP_Defender\Model\Setting\Two_Fa;
use WP_Defender\Model\Setting\User_Agent_Lockout;
use WP_Defender\Model\Setting\Global_Ip_Lockout;
use WP_Defender\Traits\IP;
use WP_Error;
use WPMUDEV_Dashboard;

/**
 * Traits to handle HUB based functionalities of WPMUDEV class.
 */
trait Defender_Hub_Client {
	use IP;

	/**
	 * Get API base URL.
	 *
	 * @since 3.4.0
	 * @return string
	 */
	public function get_api_base_url(): string {
		return defined( 'WPMUDEV_CUSTOM_API_SERVER' ) && WPMUDEV_CUSTOM_API_SERVER
			? WPMUDEV_CUSTOM_API_SERVER
			: 'https://wpmudev.com/';
	}

	/**
	 * @param $scenario
	 *
	 * @return string
	 */
	public function get_endpoint( $scenario ): string {
		$base = $this->get_api_base_url();
		switch ( $scenario ) {
			case self::API_SCAN_KNOWN_VULN:
				return "{$base}api/defender/v1/vulnerabilities";
			case self::API_SCAN_SIGNATURE:
				return "{$base}api/defender/v1/yara-signatures";
			case self::API_AUDIT:
				// This is from another endpoint.
				$base = defined( 'WPMUDEV_CUSTOM_AUDIT_SERVER' )
					? constant( 'WPMUDEV_CUSTOM_AUDIT_SERVER' )
					: 'https://audit.wpmudev.org/';

				return "{$base}logs";
			case self::API_AUDIT_ADD:
				$base = defined( 'WPMUDEV_CUSTOM_AUDIT_SERVER' )
					? constant( 'WPMUDEV_CUSTOM_AUDIT_SERVER' )
					: 'https://audit.wpmudev.org/';

				return "{$base}logs/add_multiple";
			case self::API_BLACKLIST:
				return "{$base}api/defender/v1/blacklist-monitoring?domain=" . network_site_url();
			case self::API_WAF:
				$site_id = $this->get_site_id();

				return "{$base}api/hub/v1/sites/$site_id/modules/hosting";
			case self::API_GLOBAL_IP_LIST:
				return "{$base}api/hub/v1/global-ip-list";
			case self::API_PACKAGE_CONFIGS:
				return "{$base}api/hub/v1/package-configs";
			case self::API_IP_BLOCKLIST_SUBMIT_LOGS:
				return "{$base}api/blocklist/v1/logs";
			case self::API_HUB_SYNC:
			default:
				return "{$base}api/defender/v1/scan-results";
		}
	}

	/**
	 * Get WPMUDEV site id.
	 *
	 * @return int|bool
	 */
	public function get_site_id() {
		if ( false !== $this->get_apikey() ) {
			return (int) WPMUDEV_Dashboard::$api->get_site_id();
		}

		return false;
	}

	/**
	 * HUB API remote request method.
	 *
	 * @param string $scenario
	 * @param array  $body
	 * @param array  $args
	 * @param bool   $recheck
	 *
	 * @return array|WP_Error
	 */
	private function hub_api_request( string $scenario, array $body = [], array $args = [], bool $recheck = false ) {
		$dash_api = WPMUDEV_Dashboard::$api;

		if ( ! $dash_api->has_key() ) {
			throw new Exception( __( 'Dash plugin authentication API key missing.', 'defender-security' ) );
		}

		$api_key = $dash_api->get_key();

		$body['domain'] ??= network_site_url();

		$headers = [
			'Authorization' => 'Basic ' . $api_key,
			'apikey' => $api_key,
		];

		$args = array_merge(
			$args,
			[
				'body' => $body,
				'headers' => $headers,
				'timeout' => '30',
				'sslverify' => apply_filters( 'https_ssl_verify', true ),
			]
		);

		$request = wp_remote_request( $this->get_endpoint( $scenario ), $args );

		if ( is_wp_error( $request ) ) {
			if ( ! $recheck ) {
				return $request;
			}
			// Sometimes a response comes with a curl error #52 so should delete Authorization header.
			$args['headers'] = [ 'apikey' => $api_key ];
			$request = wp_remote_request( $this->get_endpoint( $scenario ), $args );
			if ( is_wp_error( $request ) ) {
				return $request;
			}
		}

		$result = wp_remote_retrieve_body( $request );
		$result = json_decode( $result, true );

		if ( 200 !== wp_remote_retrieve_response_code( $request ) ) {
			return new WP_Error(
				wp_remote_retrieve_response_code( $request ),
				$result['message'] ?? wp_remote_retrieve_response_message( $request )
			);
		}

		return $result;
	}

	/**
	 * @param string $scenario
	 * @param array  $body
	 * @param array  $args
	 * @param bool   $recheck
	 *
	 * @return array|WP_Error
	 */
	public function make_wpmu_request( string $scenario, array $body = [], array $args = [], bool $recheck = false ) {
		$api_key = $this->get_apikey();

		if ( false === $api_key ) {
			$link_text = sprintf( '<a target="_blank" href="%s">%s</a>', 'https://wpmudev.com/project/wpmu-dev-dashboard/', __( 'here', 'defender-security' ) );
			return new WP_Error(
				'dashboard_required',
				sprintf(
					/* translators: %s - wpmudev link */
					esc_html__( 'WPMU DEV Dashboard will be required for this action. Please visit %s and install the WPMU DEV Dashboard.', 'defender-security' ),
					$link_text
				)
			);
		}

		return $this->hub_api_request( $scenario, $body, $args, $recheck );
	}

	/**
	 * Hub API wrapper for free and higher account holding users.
	 *
	 * @param string $scenario
	 * @param array  $body
	 * @param array  $args
	 * @param bool   $recheck
	 *
	 * @return array|WP_Error
	 */
	public function make_wpmu_free_request( string $scenario, array $body = [], array $args = [], bool $recheck = false ) {
		if ( $this->can_wpmu_free_request() === false ) {
			throw new Exception( __( 'Permission denied API call.', 'defender-security' ) );
		}

		$dash_api = WPMUDEV_Dashboard::$api;

		if ( ! $dash_api->has_key() ) {
			throw new Exception( __( 'Dash plugin authentication API key missing.', 'defender-security' ) );
		}

		return $this->hub_api_request( $scenario, $body, $args, $recheck );
	}

	/**
	 * Check can do free API request.
	 *
	 * @return bool True for allowed request, false for not allowed.
	 */
	public function can_wpmu_free_request() {
		if ( ! class_exists( 'WPMUDEV_Dashboard' ) ) {
			throw new Exception( __( 'WPMU DEV Dashboard plugin is missing.', 'defender-security' ) );
		}

		WPMUDEV_Dashboard::instance();

		$membership_status = WPMUDEV_Dashboard::$api->get_membership_status();

		if ( in_array( $membership_status, [ 'single', 'unit' ], true ) ) {
			return $this->is_member();
		}

		return in_array( $membership_status, [ 'free', 'full' ], true );
	}

	/**
	 * This will build data relate to scan module, so we can push to hub.
	 *
	 * @since 2.4.7 add 'plugin_integrity' args
	 *
	 * @return array
	 */
	protected function build_scan_hub_data(): array {
		$scan = Scan::get_last();
		$scan_result = [
			'core_integrity' => 0,
			'plugin_integrity' => 0,
			'vulnerability_db' => 0,
			'file_suspicious' => 0,
			'last_completed' => false,
			'scan_items' => [],
			'num_issues' => 0,
			'num_ignored_issues' => 0,
		];
		$total_issues = 0;
		if ( is_object( $scan ) ) {
			$data = $scan->prepare_issues(10, 1);

			$scan_result['core_integrity'] = $data['count_core'];
			$scan_result['plugin_integrity'] = $data['count_plugin'];
			$scan_result['vulnerability_db'] = $data['count_vuln'];
			$scan_result['file_suspicious'] = $data['count_malware'];
			$scan_result['last_completed'] = $scan->date_end;
			$scan_result['num_ignored_issues'] = $data['count_ignored'];

			if ( ! empty( $data['issues'] ) ) {
				$total_issues = $data['count_issues'];
				foreach ( $data['issues'] as $issue ) {
					$scan_result['scan_items'][] = [
						'file' => $issue['full_path'] ?? $issue['file_name'],
						'detail' => $issue['short_desc'],
					];
				}
			}
			$scan_result['num_issues'] = $total_issues + $data['count_ignored'];
		}

		$settings = new Scan_Settings();

		return [
			'timestamp' => is_object( $scan ) ? strtotime( $scan->date_start ) : '',
			'warning' => $total_issues,
			'scan_result' => $scan_result,
			'scan_schedule' => [
				// @since 2.7.0 change scheduled scan logic.
				'is_activated' => $settings->scheduled_scanning,
				// Example of frequency, day, time in build_notification_hub_data() method.
				'time' => $settings->time,
				'day' => $this->get_notification_day( $settings ),
				'frequency' => $this->backward_frequency_compatibility( $settings->frequency ),
			],
		];
	}

	/**
	 * @param string $frequency
	 *
	 * @return int
	 */
	public function backward_frequency_compatibility( string $frequency ): int {
		switch ( $frequency ) {
			case 'daily':
				return 1;
			case 'weekly':
				return 7;
			case 'monthly':
			default:
				return 30;
		}
	}

	/**
	 * Build data for security tweaks.
	 *
	 * @return array
	 */
	protected function build_security_tweaks_hub_data(): array {
		$arr = wd_di()->get( Security_Tweaks::class )->data_frontend();
		$data = [
			'cautions' => $arr['summary']['issues_count'],
			'issues' => [],
			'ignore' => [],
			'fixed' => [],
		];
		$types = [
			Security_Tweaks::STATUS_ISSUES,
			Security_Tweaks::STATUS_IGNORE,
			Security_Tweaks::STATUS_RESOLVE,
		];
		$view = '';
		foreach ( $types as $type ) {
			if ( 'ignore' === $type ) {
				$view = '&view=ignored';
			} elseif ( 'fixed' === $type ) {
				$view = '&view=resolved';
			}
			foreach ( wd_di()->get( Security_Tweaks::class )->init_tweaks( $type, 'array' ) as $tweak ) {
				$data[ $type ][] = [
					'label' => $tweak['title'],
					'url' => network_admin_url( 'admin.php?page=wdf-hardener' . $view . '#' . $tweak['slug'] ),
				];
			}
		}

		return $data;
	}

	/**
	 * @return array
	 */
	public function build_audit_hub_data(): array {
		$date_from = ( new \DateTime( gmdate( 'Y-m-d', strtotime( '-30 days' ) ) ) )->setTime(
			0,
			0,
			0
		)->getTimestamp();
		$date_to = ( new \DateTime( gmdate( 'Y-m-d' ) ) )->setTime( 23, 59, 59 )->getTimestamp();
		$month_count = Audit_Log::count( $date_from, $date_to );
		$last = Audit_Log::get_last();
		if ( is_object( $last ) ) {
			$last = gmdate( 'Y-m-d g:i a', $last->timestamp );
		} else {
			$last = 'n/a';
		}

		$settings = new Audit_Logging();

		return [
			'month' => $month_count,
			'last_event' => $last,
			'enabled' => $settings->is_active(),
		];
	}

	/**
	 * @return array
	 */
	public function build_lockout_hub_data(): array {
		$firewall = wd_di()->get( Firewall::class )->data_frontend();

		return [
			'last_lockout' => $firewall['last_lockout'],
			'lp' => wd_di()->get( Login_Lockout::class )->enabled,
			'lp_week' => $firewall['login']['week'],
			'nf' => wd_di()->get( Notfound_Lockout::class )->enabled,
			'nf_week' => $firewall['nf']['week'],
			'ua' => wd_di()->get( User_Agent_Lockout::class )->enabled,
			'ua_week' => $firewall['ua']['week'],
			'global_ip_list_enabled' => wd_di()->get( Global_Ip_Lockout::class )->enabled,
		];
	}

	/**
	 * @return array
	 */
	public function build_2fa_hub_data(): array {
		$settings = new Two_Fa();
		$service = wd_di()->get( \WP_Defender\Component\Two_Fa::class );
		$query = new \WP_User_Query(
			[
				// Look over the network.
				'blog_id' => 0,
				'meta_key' => $service::DEFAULT_PROVIDER_USER_KEY,
				'meta_value' => array_keys( $service->get_providers() ),
				'meta_compare' => 'IN',
			]
		);
		$active_users = [];
		if ( $query->get_total() > 0 ) {
			foreach ( $query->get_results() as $obj_user ) {
				$active_users[] = [
					'display_name' => $obj_user->data->display_name,
				];
			}
		}

		return [
			'active' => $settings->enabled && count( $settings->user_roles ),
			'enabled' => $settings->enabled,
			'active_users' => $active_users,
		];
	}

	/**
	 * @return array
	 */
	public function build_mask_login_hub_data(): array {
		$settings = new Mask_Login();

		return [
			'active' => $settings->is_active(),
			'masked_url' => $settings->mask_url,
		];
	}

	/**
	 * @return array
	 */
	public function build_recaptcha_hub_data(): array {
		$settings = new \WP_Defender\Model\Setting\Recaptcha();

		return [
			'active' => $settings->is_active(),
		];
	}

	/**
	 * @return array
	 */
	public function build_password_protection_hub_data(): array {
		$settings = new \WP_Defender\Model\Setting\Password_Protection();

		return [
			'active' => $settings->is_active(),
		];
	}

	/**
	 * @param object $module_report
	 *
	 * @return string
	 */
	private function get_notification_day( $module_report ): string {
		if ( ! is_object( $module_report ) ) {
			return '';
		}

		if ( 'daily' === $module_report->frequency ) {
			$day = '1';
		} elseif ( 'weekly' === $module_report->frequency ) {
			$day = $module_report->day;
		} else {
			// For 'monthly'.
			$day = $module_report->day_n;
		}

		return $day;
	}

	/**
	 * Frequency format:
	 * if frequency is day, e.g.: 'frequency' => 1, 'day' => '1', 'time' => '20:30'
	 * if frequency is week, e.g.: 'frequency' => 7, 'day' => 'wednesday', 'time' => '14:00'
	 * if frequency is month, e.g.: 'frequency' => 30, 'day' => '4', 'time' => '4:30'
	 *
	 * @return array
	 */
	public function build_notification_hub_data(): array {
		$audit_settings = new Audit_Logging();
		$audit_report = new Audit_Report();
		$firewall_report = new Firewall_Report();
		$malware_report = new Malware_Report();
		$scan_settings = new Scan_Settings();

		return [
			'file_scanning' => [
				'active' => true,
				// @since 2.7.0 move scheduled options to Scan settings, but we get status of Malware Scanning - Reporting here.
				'enabled' => Notification::STATUS_ACTIVE === $malware_report->status,
				// Report enabled bool value.
				'frequency' => [
					'frequency' => $this->backward_frequency_compatibility( $scan_settings->frequency ),
					'day' => $this->get_notification_day( $scan_settings ),
					'time' => $scan_settings->time,
				],
			],
			'audit_logging' => [
				'active' => $audit_settings->is_active(),
				'enabled' => Notification::STATUS_ACTIVE === $audit_report->status,
				'frequency' => [
					'frequency' => $this->backward_frequency_compatibility( $audit_report->frequency ),
					'day' => $this->get_notification_day( $audit_report ),
					'time' => $audit_report->time,
				],
			],
			'ip_lockouts' => [
				// Always true as we have blacklist listening.
				'active' => true,
				'enabled' => Notification::STATUS_ACTIVE === $firewall_report->status,
				// Report enabled bool value.
				'frequency' => [
					'frequency' => $this->backward_frequency_compatibility( $firewall_report->frequency ),
					'day' => $this->get_notification_day( $firewall_report ),
					'time' => $firewall_report->time,
				],
			],
		];
	}

	/**
	 * @return array
	 */
	public function build_firewall_notification_hub_data(): array {
		$firewall_notification = new Firewall_Notification();
		if ( 'enabled' === $firewall_notification->status ) {
			$login_lockout = $firewall_notification->configs['login_lockout'];
			$nf_lockout = $firewall_notification->configs['nf_lockout'];
			$ua_lockout = $firewall_notification->configs['ua_lockout'] ?? false;
		} else {
			$login_lockout = false;
			$nf_lockout = false;
			$ua_lockout = false;
		}

		return [
			'firewall' => [
				'login_lockout' => $login_lockout,
				'404_lockout' => $nf_lockout,
				'ua_lockout' => $ua_lockout,
			],
		];
	}

	/**
	 * @return array
	 */
	public function build_security_headers_hub_data(): array {
		$security_headers = wd_di()->get( Security_Headers::class )->get_type_headers();

		return [
			'active' => $security_headers['active'],
			'inactive' => $security_headers['inactive'],
		];
	}

	/**
	 * @return array
	 */
	public function build_stats_to_hub(): array {
		$scan_data = $this->build_scan_hub_data();
		$tweaks_data = $this->build_security_tweaks_hub_data();
		$audit_data = $this->build_audit_hub_data();
		$firewall_data = $this->build_lockout_hub_data();
		$two_fa = $this->build_2fa_hub_data();
		$mask_login = $this->build_mask_login_hub_data();
		$sec_headers = $this->build_security_headers_hub_data();
		$recaptcha = $this->build_recaptcha_hub_data();
		$pwned_password = $this->build_password_protection_hub_data();
		$quarantined_files = $this->build_quarantined_files_hub_data();

		return [
			// Domain name.
			'domain' => network_home_url(),
			// Last scan date.
			'timestamp' => $scan_data['timestamp'],
			// Scan issue count.
			'warnings' => $scan_data['warning'],
			// Security tweaks issue count.
			'cautions' => $tweaks_data['cautions'],
			'data_version' => gmdate( 'Ymd' ),
			'scan_data' => json_encode(
				[
					'scan_result' => $scan_data['scan_result'],
					'hardener_result' => [
						'issues' => $tweaks_data[ Security_Tweaks::STATUS_ISSUES ],
						'ignored' => $tweaks_data[ Security_Tweaks::STATUS_IGNORE ],
						'resolved' => $tweaks_data[ Security_Tweaks::STATUS_RESOLVE ],
					],
					'scan_schedule' => $scan_data['scan_schedule'],
					'audit_status' => [
						'events_in_month' => $audit_data['month'],
						'audit_enabled' => $audit_data['enabled'],
						'last_event_date' => $audit_data['last_event'],
					],
					'audit_page_url' => network_admin_url( 'admin.php?page=wdf-logging' ),
					'labels' => [
						// Todo: maybe should it remove because Scan Settings model has label() method for that?
						'parent_integrity' => esc_html__( 'File change detection', 'defender-security' ),
						'core_integrity' => esc_html__( 'Scan core files', 'defender-security' ),
						'plugin_integrity' => esc_html__( 'Scan plugin files', 'defender-security' ),
						'vulnerability_db' => esc_html__( 'Known vulnerabilities', 'defender-security' ),
						'file_suspicious' => esc_html__( 'Suspicious code', 'defender-security' ),
					],
					'scan_page_url' => network_admin_url( 'admin.php?page=wdf-scan' ),
					'hardener_page_url' => network_admin_url( 'admin.php?page=wdf-hardener' ),
					'new_scan_url' => network_admin_url( 'admin.php?page=wdf-scan&wdf-action=new_scan' ),
					'schedule_scans_url' => network_admin_url( 'admin.php?page=wdf-schedule-scan' ),
					'settings_page_url' => network_admin_url( 'admin.php?page=wdf-settings' ),
					'ip_lockout_page_url' => network_admin_url( 'admin.php?page=wdf-ip-lockout' ),
					'last_lockout' => $firewall_data['last_lockout'],
					'login_lockout_enabled' => $firewall_data['lp'],
					'login_lockout' => $firewall_data['lp_week'],
					'lockout_404_enabled' => $firewall_data['nf'],
					'lockout_404' => $firewall_data['nf_week'],
					'lockout_ua_enabled' => $firewall_data['ua'],
					'lockout_ua' => $firewall_data['ua_week'],
					'total_lockout' => (int) $firewall_data['lp_week'] + (int) $firewall_data['nf_week'] + (int) $firewall_data['ua_week'],
					'global_ip_list_enabled' => $firewall_data['global_ip_list_enabled'],
					'advanced' => [
						// This is moved but still keep here for backward compatibility.
						'multi_factors_auth' => [
							'active' => $two_fa['active'],
							'enabled' => $two_fa['enabled'],
							'active_users' => $two_fa['active_users'],
						],
						'mask_login' => [
							'activate' => $mask_login['active'],
							'masked_url' => $mask_login['masked_url'],
						],
						'security_headers' => [
							'active' => $sec_headers['active'],
							'inactive' => $sec_headers['inactive'],
						],
						'google_recaptcha' => [
							'active' => $recaptcha['active'],
						],
						'password_protection' => [
							'active' => $pwned_password['active'],
						],
					],
					'reports' => $this->build_notification_hub_data(),
					'notifications' => $this->build_firewall_notification_hub_data(),
					'quarantined_files' => $quarantined_files,
				]
			),
		];
	}

	/**
	 * Checks whether we're on WPMU DEV Hosting.
	 *
	 * @return bool
	 */
	public function is_wpmu_hosting(): bool {
		return isset( $_SERVER['WPMUDEV_HOSTED'] ) && ! empty( $_SERVER['WPMUDEV_HOSTED'] );
	}

	/**
	 * @return bool
	 */
	protected function is_tfh_account(): bool {
		return class_exists( 'WPMUDEV_Dashboard' ) &&
			is_object( WPMUDEV_Dashboard::$api ) &&
			method_exists( WPMUDEV_Dashboard::$api, 'get_membership_status' ) &&
			'free' === WPMUDEV_Dashboard::$api->get_membership_status();
	}

	/**
	 * Check if WPMUDEV Hosted site is connected to The Free HUB.
	 *
	 * @since 3.3.0
	 * @return bool
	 */
	public function is_hosted_site_connected_to_tfh(): bool {
		return $this->is_tfh_account() && $this->is_wpmu_hosting();
	}

	/**
	 * Check if a site from 3rd party hosting is connected to The Free HUB.
	 *
	 * @since 3.6.0
	 * @return bool
	 */
	public function is_another_hosted_site_connected_to_tfh(): bool {
		return $this->is_tfh_account() && ! $this->is_wpmu_hosting();
	}

	/**
	 * @return array
	 */
	protected function build_quarantined_files_hub_data(): array {
		if ( ! class_exists( 'WP_Defender\Component\Quarantine' ) ) {
			return [];
		}

		return wd_di()->get( Quarantine::class )->hub_list();
	}

	/**
	 * Schedule Hub Synchronization event.
	 */
	public function schedule_hub_sync(): void {
		if ( ! wp_next_scheduled( 'defender_hub_sync' ) ) {
			wp_schedule_single_event( time(), 'defender_hub_sync' );
		}
	}
}
