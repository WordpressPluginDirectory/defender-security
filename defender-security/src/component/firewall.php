<?php

namespace WP_Defender\Component;

use WP_Defender\Component;
use WP_Defender\Model\Lockout_Ip;
use WP_Defender\Model\Setting\Firewall as Model_Firewall;
use WP_Defender\Behavior\WPMUDEV;

class Firewall extends Component {

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
	 */
	public function is_blocklisted_ip( string $ip ) {
		/**
		 * @var Blacklist_Lockout
		 */
		$service = wd_di()->get( Blacklist_Lockout::class );

		if ( $service->is_blacklist( $ip ) ) {
			return true;
		}

		if ( $service->is_country_blacklist( $ip ) ) {
			return true;
		}

		/**
		 * @var IP\Global_IP
		 */
		$global_ip = wd_di()->get( IP\Global_IP::class );

		if(
			$global_ip->is_global_ip_enabled() &&
			$global_ip->is_ip_blocked( $ip )
		) {
			return true;
		}
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

		$client_ips = [];
		foreach ( $ip_headers as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				// Handle multiple IP addresses
				$ips = array_map( 'trim', explode( ',', $_SERVER[ $header ] ) );

				foreach( $ips as $ip ) {
					if ( $this->validate_ip( $ip ) ) {
						$client_ips[] = $ip;
					}
				}
			}
		}
		$client_ips = array_unique( $client_ips );

		return $this->filter_user_ips( $client_ips );
	}
}
