<?php

namespace WP_Defender\Component;

use WP_Defender\Component;
use WP_Defender\Component\Trusted_Proxy_Preset\Trusted_Proxy_Preset;
use WP_Defender\Model\Lockout_Ip;
use WP_Defender\Model\Setting\Firewall as Model_Firewall;
use WP_Defender\Behavior\WPMUDEV;

class Firewall extends Component {
	/**
	 * The notice slug if there is switching IP Detection option to Cloudflare (CF).
	 */
	public const IP_DETECTION_CF_SHOW_SLUG = 'wd_show_ip_detection_cf_notice';

	/**
	 * The notice slug if CF IP Detection notice is rejected.
	 */
	public const IP_DETECTION_CF_DISMISS_SLUG = 'wd_dismiss_ip_detection_cf_notice';

	/**
	 * The notice slug if there is switching IP Detection option to X-Forwarded-For (XFF).
	 */
	public const IP_DETECTION_XFF_SHOW_SLUG = 'wd_show_ip_detection_xff_notice';

	/**
	 * The notice slug if CF IP Detection notice is rejected.
	 */
	public const IP_DETECTION_XFF_DISMISS_SLUG = 'wd_dismiss_ip_detection_xff_notice';

	/**
	 * Check if the first commencing request is proper staff remote access.
	 *
	 * @param $access
	 *
	 * @return bool
	 */
	private function is_commencing_staff_access( $access ): bool {
		return wp_doing_ajax() &&
			isset( $_GET['action'], $_POST['wdpunkey'] ) &&
			'wdpunauth' === sanitize_text_field( $_GET['action'] ) &&
			hash_equals( sanitize_text_field( $_POST['wdpunkey'] ), $access['key'] );
	}

	/**
	 * Check is the access from authenticated staff.
	 *
	 * @return bool
	 */
	private function is_authenticated_staff_access(): bool {
		return isset( $_COOKIE['wpmudev_is_staff'] ) && '1' === $_COOKIE['wpmudev_is_staff'];
	}

	/**
	 * Check if the access is from our staff access.
	 *
	 * @return bool
	 */
	private function is_a_staff_access(): bool {
		if ( defined( 'WPMUDEV_DISABLE_REMOTE_ACCESS' ) && true === constant( 'WPMUDEV_DISABLE_REMOTE_ACCESS' ) ) {
			return false;
		}

		$wpmu_dev = new WPMUDEV();
		$is_remote_access = $wpmu_dev->get_apikey() &&
			true === \WPMUDEV_Dashboard::$api->remote_access_details( 'enabled' );

		if ( $is_remote_access ) {
			$access = $wpmu_dev->get_remote_access();
			if ( $this->is_authenticated_staff_access() || $this->is_commencing_staff_access( $access ) ) {
				$this->log( var_export( $access, true ), \WP_Defender\Controller\Firewall::FIREWALL_LOG );

				return true;
			}
		}

		return false;
	}

	/**
	 * Cron for delete old log.
	 */
	public function firewall_clean_up_logs() {
		$settings = new Model_Firewall();
		/**
		 * Filter count days for IP logs to be saved to DB.
		 *
		 * @since 2.3
		 *
		 * @param string
		 */
		$storage_days = apply_filters( 'ip_lockout_logs_store_backward', $settings->storage_days );
		if ( ! is_numeric( $storage_days ) ) {
			return;
		}
		$time_string = '-' . $storage_days . ' days';
		$timestamp = $this->local_to_utc( $time_string );
		\WP_Defender\Model\Lockout_Log::remove_logs( $timestamp, 50 );
	}

	/**
	 * Cron for clean up temporary IP block list.
	 */
	public function firewall_clean_up_temporary_ip_blocklist() {
		$models = Lockout_Ip::get_bulk( Lockout_Ip::STATUS_BLOCKED );
		foreach( $models as $model )  {
			$model->status = Lockout_Ip::STATUS_NORMAL;
			$model->save();
		}
	}

	/**
	 * Update temporary IP blocklist of Firewall, clear cron job.
	 * The interval settings value is updated once.
	 *
	 * @param string $new_interval
	 */
	public function update_cron_schedule_interval( $new_interval ) {
		$settings = new Model_Firewall();
		// If a new interval is different from the saved value, we need to clear the cron job.
		if ( $new_interval !== $settings->ip_blocklist_cleanup_interval ) {
			update_site_option( 'wpdef_clear_schedule_firewall_cleanup_temp_blocklist_ips', true );
		}
	}

	/**
	 * @param string $ip
	 *
	 * @return bool
	 */
	public function skip_priority_lockout_checks( string $ip ): bool {
		/**
		 * @var IP\Global_IP
		 */
		$global_ip = wd_di()->get( IP\Global_IP::class );

		if(
			$global_ip->is_global_ip_enabled() &&
			$global_ip->is_ip_allowed( $ip )
		) {
			return true;
		}

		/**
		 * @var Blacklist_Lockout
		 */
		$service = wd_di()->get( Blacklist_Lockout::class );

		$model = Lockout_Ip::get( $ip );
		$is_lockout_ip = is_object( $model ) && $model->is_locked();

		$is_country_whitelisted = ! $service->is_blacklist( $ip ) &&
			$service->is_country_whitelist( $ip ) && ! $is_lockout_ip;

		// If this IP is whitelisted, so we don't need to blacklist this.
		if ( $service->is_ip_whitelisted( $ip ) || $is_country_whitelisted ) {
			return true;
		}
		// Green light if access staff is enabled.
		if ( $this->is_a_staff_access() ) {
			return true;
		}

		return false;
	}

	/**
	 * @param string $ip
	 *
	 * @return array
	 */
	public function is_blocklisted_ip( string $ip ): array {
		$array = [
			'reason' => '',
			'result' => false,
		];
		/**
		 * @var Blacklist_Lockout
		 */
		$service = wd_di()->get( Blacklist_Lockout::class );

		if ( $service->is_blacklist( $ip ) ) {
			return [
				'reason' => 'local_ip',
				'result' => true,
			];
		}

		if ( $service->is_country_blacklist( $ip ) ) {
			return [
				'reason' => 'country',
				'result' => true,
			];
		}

		/**
		 * @var IP\Global_IP
		 */
		$global_ip = wd_di()->get( IP\Global_IP::class );

		if(
			$global_ip->is_global_ip_enabled() &&
			$global_ip->is_ip_blocked( $ip )
		) {
			return [
				'reason' => 'global_ip',
				'result' => true,
			];
		}

		return $array;
	}

	/**
	 * @return int
	 * @since 3.7.0 Get the limit of Lockout records.
	 */
	public function get_lockout_record_limit() {
		return (int) apply_filters( 'wd_lockout_record_limit', 10000 );
	}

	/**
	 * Cron for deleting unwanted lockout records.
	 *
	 * @since 3.8.0
	 * @return void
	 */
	public function firewall_clean_up_lockout(): void {
		global $wpdb;

		$table = $wpdb->base_prefix . ( new Lockout_Ip() )->get_table();
		$current_timestamp = time();
		$limit = $this->get_lockout_record_limit();

		do {
			$affected_rows = $wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$table}
					 WHERE (release_time = 0 OR release_time < %d) AND meta IN (%s, %s, %s, %s, %s)
					 ORDER BY id
					 LIMIT %d",
					$current_timestamp,
					'[]',
					'{"nf":[]}',
					'{"login":[]}',
					'{"nf":[],"login":[]}',
					'{"login":[],"nf":[]}',
					$limit
				)
			);

		} while ( $affected_rows === $limit );
	}

	/**
	 * Gather IP(s) from headers.
	 *
	 * @since 4.4.2
	 *
	 * @return array
	 */
	public function gather_ips(): array {
		$ip_headers = [
			'HTTP_CLIENT_IP',
			'HTTP_X_REAL_IP',
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_FORWARDED',
			'HTTP_X_CLUSTER_CLIENT_IP',
			'HTTP_FORWARDED_FOR',
			'HTTP_FORWARDED',
			'HTTP_CF_CONNECTING_IP',
			'REMOTE_ADDR',
		];

		$gathered_ips = [];
		foreach ( $ip_headers as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				// Handle multiple IP addresses
				$ips = array_map( 'trim', explode( ',', $_SERVER[ $header ] ) );

				foreach( $ips as $ip ) {
					if ( $this->validate_ip( $ip ) ) {
						$gathered_ips[] = $ip;
					}
				}
			}
		}

		/**
		 * Filter the gathered IPs before checking the lockout records.
		 *
		 * @param array $gathered_ips IPs gathered from request headers.
		 * @since 4.5.1
		 */
		$gathered_ips = (array) apply_filters( 'wpdef_firewall_gathered_ips', array_unique( $gathered_ips ) );

		return $this->filter_user_ips( $gathered_ips );
	}

	/**
	 * Check if the current request is recognized as coming from Cloudflare.
	 *
	 * @return bool
	 */
	public function is_cloudflare_request(): bool {
		$is_cloudflare = true;

		if( ! (
			isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ||
			isset( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ||
			isset( $_SERVER['HTTP_CF_RAY'] ) ||
			isset( $_SERVER['HTTP_CF_VISITOR'] )
		) ) {
			$is_cloudflare = false;
		}

		return $is_cloudflare;
	}

	/**
	 * Auto-detect proxy server and switch to appropriate IP Detection option.
	 *
	 * @return void
	 */
	public function auto_switch_ip_detection_option(): void {
		$model = wd_di()->get( Model_Firewall::class );

		if ( $this->is_cloudflare_request() ) {
			if (
				'HTTP_CF_CONNECTING_IP' !== $model->http_ip_header &&
				! self::is_switched_ip_detection_notice( self::IP_DETECTION_CF_SHOW_SLUG )
			) {
				$model->http_ip_header = 'HTTP_CF_CONNECTING_IP';
				update_site_option( self::IP_DETECTION_CF_SHOW_SLUG, true );
			}

			$model->trusted_proxy_preset = 'cloudflare';
			$model->save();

			// Fetch trusted proxy ips
			$this->update_trusted_proxy_preset_ips();
		}
	}

	/**
	 * Update trusted proxy preset IPs.
	 *
	 * @return void
	 */
	public function update_trusted_proxy_preset_ips(): void {
		$model = wd_di()->get( Model_Firewall::class );
		if ( ! empty( $model->trusted_proxy_preset ) ) {
			/**
			 * @var Trusted_Proxy_Preset $trusted_proxy_preset ;
			 */
			$trusted_proxy_preset = wd_di()->get( Trusted_Proxy_Preset::class );
			$trusted_proxy_preset->set_proxy_preset( $model->trusted_proxy_preset );
			$trusted_proxy_preset->update_ips();
		}
	}

	/**
	 * Show a notice if wrong IP Detection option is configured for the site.
	 *
	 * @return void
	 */
	public function maybe_show_misconfigured_ip_detection_option_notice(): void {
		$model = wd_di()->get( Model_Firewall::class );

		if (
			'HTTP_X_FORWARDED_FOR' !== $model->http_ip_header &&
			isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) &&
			! $this->is_cloudflare_request() &&
			! self::is_xff_notice_ready()
		) {
			update_site_option( self::IP_DETECTION_XFF_SHOW_SLUG, true );
		}
	}

	/**
	 * @param string $key
	 *
	 * @return bool
	 */
	public static function is_switched_ip_detection_notice( string $key ): bool {
		return (bool) get_site_option( $key );
	}

	/**
	 * @return bool
	 */
	public static function is_xff_notice_ready(): bool {
		return self::is_switched_ip_detection_notice( self::IP_DETECTION_XFF_SHOW_SLUG )
			&& ! self::is_switched_ip_detection_notice( self::IP_DETECTION_XFF_DISMISS_SLUG );
	}

	/**
	 * @return bool
	 */
	public static function is_cf_notice_ready(): bool {
		return self::is_switched_ip_detection_notice( self::IP_DETECTION_CF_SHOW_SLUG )
			&& ! self::is_switched_ip_detection_notice( self::IP_DETECTION_CF_DISMISS_SLUG );
	}

	/**
	 * @return void
	 */
	public static function delete_slugs(): void {
		delete_site_option( self::IP_DETECTION_CF_SHOW_SLUG );
		delete_site_option( self::IP_DETECTION_CF_DISMISS_SLUG );
		delete_site_option( self::IP_DETECTION_XFF_SHOW_SLUG );
		delete_site_option( self::IP_DETECTION_XFF_DISMISS_SLUG );
	}

	/**
	 * Get the first blocked IP.
	 *
	 * @param array $ips
	 *
	 * @return string
	 */
	public function get_blocked_ip( $ips ): string {
		$blocked_ip = '';
		foreach ( $ips as $ip ) {
			$is_blocklisted = $this->is_blocklisted_ip( $ip );
			if ( $is_blocklisted['result'] ) {
				$blocked_ip = $ip;
				break;
			}
		}
		// Do not continue if there is not a single blocked IP.
		if ( '' === $blocked_ip ) {
			// Maybe IP(-s) in Active lockouts?
			if ( count( $ips ) > 1 ) {
				$models = Lockout_Ip::get_bulk( Lockout_Ip::STATUS_BLOCKED, $ips );
				foreach ( $models as $model ) {
					$blocked_ip = $model->ip;
					break;
				}
			} else {
				if ( null !== Lockout_Ip::is_blocklisted_ip( $ips[0] ) ) {
					$blocked_ip = $ips[0];
				}
			}
		}

		return $blocked_ip;
	}
}
