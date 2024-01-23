<?php

namespace WP_Defender\Component;

use Calotes\Helper\Array_Cache;
use WP_Defender\Component;
use WP_Defender\Integrations\MaxMind_Geolocation;
use WP_Defender\Model\Lockout_Log;
use WP_Defender\Model\Setting\Blacklist_Lockout as Model_Blacklist_Lockout;

class Blacklist_Lockout extends Component {
	use \WP_Defender\Traits\Country;
	use \WP_Defender\Traits\IP;

	/**
	 * @param string $ip
	 *
	 * @return bool
	 */
	public function is_country_whitelist( $ip ): bool {
		// Check Firewall > IP Banning > Locations section is activated or not.
		$country = $this->get_current_country( $ip );
		if ( false === $country ) {
			return false;
		}
		$model = new Model_Blacklist_Lockout();
		$whitelist = $model->get_country_whitelist();
		if ( empty( $whitelist ) ) {
			return false;
		}
		if ( ! empty( $country['iso'] ) && in_array( strtoupper( $country['iso'] ), $whitelist, true ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Return the default ips need to whitelisted, e.g. HUB ips.
	 *
	 * @return array
	 */
	private function get_default_ip_whitelisted(): array {
		$ips = [
			'18.204.159.253',
			'54.227.51.40',
			'3.93.131.0',
			'18.219.56.14',
			'45.55.78.242',
			'35.171.56.101',
			'192.241.140.159',
			'104.236.132.222',
			'192.241.148.185',
			'34.196.51.17',
			'35.157.144.199',
			'159.89.254.12',
			'18.219.161.157',
			'165.227.251.117',
			'165.227.251.120',
			'140.82.60.49',
			'45.63.10.140',
			...$this->get_blc_ip_whitelisted(),
			'127.0.0.1',
			array_key_exists( 'SERVER_ADDR', $_SERVER )
				? $_SERVER['SERVER_ADDR']
				: ( $_SERVER['LOCAL_ADDR'] ?? null ),
		];

		return (array) apply_filters( 'ip_lockout_default_whitelist_ip', $ips );
	}

	/**
	 * Is IP on Whitelist?
	 *
	 * @param string $ip
	 *
	 * @return bool
	 */
	public function is_ip_whitelisted( $ip ): bool {
		if ( in_array( $ip, $this->get_default_ip_whitelisted(), true ) ) {
			return true;
		}

		$blacklist_settings = new Model_Blacklist_Lockout();

		return $this->is_ip_in_format( $ip, $blacklist_settings->get_list( 'allowlist' ) );
	}

	/**
	 * Is IP on Blocklist?
	 *
	 * @param string $ip
	 *
	 * @return bool
	 */
	public function is_blacklist( $ip ) {
		$blacklist_settings = new Model_Blacklist_Lockout();

		return $this->is_ip_in_format( $ip, $blacklist_settings->get_list( 'blocklist' ) );
	}

	/**
	 * Is country on Blacklist?
	 *
	 * @param string $ip
	 *
	 * @return bool
	 */
	public function is_country_blacklist( $ip ): bool {
		// Check Firewall > IP Banning > Locations section is activated or not.
		$country = $this->get_current_country( $ip );
		if ( false === $country ) {
			return false;
		}
		$blacklist_settings = new Model_Blacklist_Lockout();
		$blacklisted        = $blacklist_settings->get_country_blacklist();
		if ( empty( $blacklisted ) ) {
			return false;
		}
		if ( in_array( 'all', $blacklisted, true ) ) {
			return true;
		}
		if ( ! empty( $country['iso'] ) && in_array( strtoupper( $country['iso'] ), $blacklisted, true ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Validate import file is in right format and usable for IP Lockout.
	 *
	 * @param $file
	 *
	 * @return array|bool
	 */
	public function verify_import_file( $file ) {
		$fp = fopen( $file, 'r' );
		$data = [];
		while ( ( $line = fgetcsv( $fp ) ) !== false ) { //phpcs:ignore
			if ( 2 !== count( $line ) ) {
				return false;
			}

			if ( ! in_array( $line[1], [ 'allowlist', 'blocklist' ], true ) ) {
				return false;
			}

			if ( false === $this->validate_ip( $line[0] ) ) {
				continue;
			}

			$data[] = $line;
		}
		fclose( $fp );

		return $data;
	}

	/**
	 * @param Model_Blacklist_Lockout $model
	 * @param string                  $country_iso
	 *
	 * @return object
	 * @since 2.8.0
	*/
	public function add_default_whitelisted_country( Model_Blacklist_Lockout $model, $country_iso ) {
		if ( empty( $model->country_whitelist ) ) {
			$model->country_whitelist[] = $country_iso;
		} elseif ( ! in_array( $country_iso, $model->country_whitelist, true ) ) {
			$model->country_whitelist[] = $country_iso;
		}

		return $model;
	}

	/**
	 * Check downloaded GeoDB.
	 *
	 * @return bool
	 */
	public function is_geodb_downloaded(): bool {
		$model = new Model_Blacklist_Lockout();
		// Likely the case after the config import with existed MaxMind license key.
		if (
			! empty( $model->maxmind_license_key )
			&& ( is_null( $model->geodb_path ) || ! is_file( $model->geodb_path ) )
		) {
			$service_geo = wd_di()->get( MaxMind_Geolocation::class );
			$tmp         = $service_geo->get_downloaded_url( $model->maxmind_license_key );
			if ( ! is_wp_error( $tmp ) ) {
				$phar = new \PharData( $tmp );
				$path = $service_geo->get_db_base_path();
				if ( ! is_dir( $path ) ) {
					wp_mkdir_p( $path );
				}
				$phar->extractTo( $path, null, true );
				$model->geodb_path = $path . DIRECTORY_SEPARATOR . $phar->current()->getFileName() . DIRECTORY_SEPARATOR . $service_geo->get_db_full_name();
				// Save because we'll check for a saved path.
				$model->save();

				if ( file_exists( $tmp ) ) {
					unlink( $tmp );
				}

				if ( empty( $model->country_whitelist ) ) {
					$is_country = false;
					foreach ( $this->get_user_ip() as $ip ) {
						$country = $this->get_current_country( $ip );

						if ( ! empty( $country['iso'] ) ) {
							$model = $this->add_default_whitelisted_country( $model, $country['iso'] );
							$is_country = true;
						}
					}

					if ( false === $is_country ) {
						return false;
					}
				}
				$model->save();
			}
		}

		// Check again.
		if ( is_null( $model->geodb_path ) || ! is_file( $model->geodb_path ) ) {
			return false;
		}

		// Check if the file exists on the site. The file can exist on the same server but for different sites.
		// For example, after config importing.
		$path_parts = pathinfo( $model->geodb_path );
		if ( preg_match( '/(\/wp-content\/.+)/', $path_parts['dirname'], $matches ) ) {
			$rel_path = $matches[1];
			$rel_path = ltrim( $rel_path, '/' );
			$abs_path = ABSPATH . $rel_path;
			if ( ! is_dir( $abs_path ) ) {
				wp_mkdir_p( $abs_path );
			}

			$rel_path = $abs_path . DIRECTORY_SEPARATOR . $path_parts['basename'];
			if ( file_exists( $rel_path ) ) {
				return true;
			} elseif ( ! empty( $model->geodb_path ) && file_exists( $model->geodb_path ) ) {
				// The case if ABSPATH was changed e.g. in wp-config.php.
				return true;
			}

			if ( move_uploaded_file( $model->geodb_path, $rel_path ) ) {
				$model->geodb_path = $rel_path;
				$model->save();
			} else {
				return false;
			}
		}

		return true;
	}

	/**
	 * For Country widget.
	 *
	 * @param int $limit
	 * @param int $max_age_days
	 *
	 * @return array
	 */
	public function get_top_countries_blocked( $limit = 10, $max_age_days = 7 ) {
		$result = Array_Cache::get( 'countries', 'ip_lockout', [] );
		if ( empty( $result ) ) {
			global $wpdb;
			$table = $wpdb->base_prefix . ( new Lockout_Log() )->get_table();
			$sql = $wpdb->prepare(
				"SELECT country_iso_code, COUNT(ip) AS ip_count FROM {$table}" .
				" WHERE (type = %s OR type = %s OR type = %s) AND date >= %d AND country_iso_code IS NOT NULL" .
				" GROUP BY country_iso_code" .
				" ORDER BY ip_count DESC LIMIT %d",
				Lockout_Log::LOCKOUT_404,
				Lockout_Log::AUTH_LOCK,
				Lockout_Log::LOCKOUT_UA,
				strtotime( '-' . $max_age_days . ' days', current_time( 'timestamp' ) ),
				$limit
			);

			$result = $wpdb->get_results( $sql, ARRAY_A );
			// Get data from cache.
			Array_Cache::set( 'countries', $result, 'ip_lockout' );
		}

		return ! empty( $result ) ? $result : [];
	}

	/**
	 * https://wpmudev.com/docs/wpmu-dev-plugins/broken-link-checker/#broken-link-checker-ip
	 * @since 4.2.0
	 *
	 * @return array
	 */
	private function get_blc_ip_whitelisted(): array {
		return [
			'165.227.127.103',
			'64.176.196.23',
			'144.202.86.106',
		];
	}

	/**
	 * Is IP on BLC Whitelist?
	 * @since 4.2.0
	 *
	 * @return bool
	 */
	public function is_blc_ip_whitelisted(): bool {
		$ips = $this->get_user_ip();
		$blc_ips = $this->get_blc_ip_whitelisted();
		$diff = array_diff( $ips, $blc_ips );
		return empty( $diff );
	}

	/**
	 * Are IPs Whitelisted?
	 *
	 * @param array $ips
	 *
	 * @since 4.4.2
	 * @return bool
	 */
	public function are_ips_whitelisted( array $ips ): bool {
		foreach ( $ips as $ip ) {
			if ( ! $this->is_ip_whitelisted( $ip ) ) {
				return false;
			}
		}

		return true;
	}
}
