<?php

namespace WP_Defender\Component\Http\Remote_Address;

use WP_Defender\Traits\IP;
use WP_Defender\Extra\IP_Helper;

/**
 * Class Classic_Remote_Address.
 *
 * Older way of getting the client/Remote IP address on HTTP request.
 *
 * @package WP_Defender\Component\Http\Remote_Address
 */
class Classic_Remote_Address {
	use IP;

	/**
	 * @var array
	 */
	private $accepted_header = [
		'HTTP_CLIENT_IP',
		'HTTP_X_REAL_IP',
		'HTTP_X_FORWARDED_FOR',
		'HTTP_X_FORWARDED',
		'HTTP_X_CLUSTER_CLIENT_IP',
		'HTTP_FORWARDED_FOR',
		'HTTP_FORWARDED',
		'REMOTE_ADDR',
	];

	/**
	 * Check if there are any cloudflare headers in the request.
	 *
	 * @return bool
	 */
	private function is_cloudflare_request(): bool {
		if ( isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			return true;
		}
		if ( isset( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) {
			return true;
		}
		if ( isset( $_SERVER['HTTP_CF_RAY'] ) ) {
			return true;
		}
		if ( isset( $_SERVER['HTTP_CF_VISITOR'] ) ) {
			return true;
		}

		return false;
	}

	/**
	 * We fetch the ip range here.
	 * https://www.cloudflare.com/ips/
	 *
	 * @since 2.5.0 Update the ip range.
	 *
	 * @return array
	 */
	private function cloudflare_ip_ranges(): array {
		return [
			[
				'173.245.48.0/20',
				'103.21.244.0/22',
				'103.22.200.0/22',
				'103.31.4.0/22',
				'141.101.64.0/18',
				'108.162.192.0/18',
				'190.93.240.0/20',
				'188.114.96.0/20',
				'197.234.240.0/22',
				'198.41.128.0/17',
				'162.158.0.0/15',
				'172.64.0.0/13',
				'131.0.72.0/22',
				'104.16.0.0/13',
				'104.24.0.0/14',
			],
			[
				'2400:cb00::/32',
				'2606:4700::/32',
				'2803:f800::/32',
				'2405:b500::/32',
				'2405:8100::/32',
				'2a06:98c0::/29',
				'2c0f:f248::/32',
			],
		];
	}

	/**
	 * Check if the request is from cloudflare. If it is, we get the IP.
	 *
	 * @return mixed
	 */
	private function cloudflare_ip() {
		if ( $this->is_cloudflare_request() ) {
			// This looks like it come from cloudflare, so this should contain the actual IP,
			// and REMOTE_ADDR contains cloudflare IP.
			[$cloudflare_ipv4_range, $cloudflare_ipv6_range] = $this->cloudflare_ip_ranges();
			$ip_helper = new IP_Helper();
			$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ?
				filter_var( $_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP ) :
				false;
			$cf_con_ip = isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ?
				filter_var( $_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP ) :
				false;

			if ( $remote_addr === $cf_con_ip ) {
				return $cf_con_ip;
			} elseif ( false === $remote_addr || false === $cf_con_ip ) {
				return false;
			}

			$is_cloudflare_proxy_ip = false;
			if ( $this->is_v4( $remote_addr ) ) {
				foreach ( $cloudflare_ipv4_range as $cf_ip ) {
					if ( $ip_helper->ipv4_in_range( $remote_addr, $cf_ip ) ) {
						$is_cloudflare_proxy_ip = true;
						break;
					}
				}
			} elseif ( $this->is_v6( $remote_addr ) ) {
				foreach ( $cloudflare_ipv6_range as $cf_ip ) {
					if ( $ip_helper->ipv6_in_range( $remote_addr, $cf_ip ) ) {
						$is_cloudflare_proxy_ip = true;
						break;
					}
				}
			}

			if ( true === $is_cloudflare_proxy_ip ) {
				return $cf_con_ip;
			}
		}

		return false;
	}

	/**
	 * Returns client IP address.
	 *
	 * @return string IP address.
	 */
	public function get_ip_address(): string {
		// Check if it's any cloudflare IP.
		$cf_ip = $this->cloudflare_ip();
		if ( ! empty( $cf_ip ) && filter_var( $cf_ip, FILTER_VALIDATE_IP ) ) {
			return apply_filters( 'defender_user_ip', $cf_ip );
		}

		$ip = '';
		foreach ( $this->accepted_header as $key ) {
			if ( array_key_exists( $key, $_SERVER ) && ! empty( $_SERVER[ $key ] ) ) {
				$ip_array = explode( ',', $_SERVER[ $key ] );
				$tmp_ip = array_shift( $ip_array );
				$tmp_ip = trim( $tmp_ip );
				if ( $this->check_validate_ip( $tmp_ip ) ) {
					$ip = $tmp_ip;
					break;
				}
			}
		}

		return apply_filters( 'defender_user_ip', $ip );
	}

	/**
	 * Return the first find header.
	 *
	 * @return string Header key/name.
	 */
	public function get_ip_header(): string {
		$cf_ip = $this->cloudflare_ip();
		if ( ! empty( $cf_ip ) && filter_var( $cf_ip, FILTER_VALIDATE_IP ) ) {
			return 'HTTP_CF_CONNECTING_IP';
		}

		foreach ( $this->accepted_header as $key ) {
			if ( array_key_exists( $key, $_SERVER ) && ! empty( $_SERVER[ $key ] ) ) {
				$ip_array = explode( ',', $_SERVER[ $key ] );
				$tmp_ip = array_shift( $ip_array );
				$tmp_ip = trim( $tmp_ip );
				if ( $this->check_validate_ip( $tmp_ip ) ) {
					return $key;
				}
			}
		}

		return '';
	}

}
