<?php

namespace WP_Defender\Component\Http\Remote_Address;

use WP_Defender\Traits\IP;

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
		'HTTP_CF_CONNECTING_IP',
		'REMOTE_ADDR',
	];

	/**
	 * Returns client IP addresses.
	 *
	 * @return array IP addresses
	 */
	public function get_ip_address(): array {
		$ip_list = [];
		foreach ( $this->accepted_header as $key ) {
			if ( array_key_exists( $key, $_SERVER ) && ! empty( $_SERVER[ $key ] ) ) {
				$ip_array = explode( ',', $_SERVER[ $key ] );
				foreach ( $ip_array as $ip ) {
					$ip = trim( $ip );
					if ( $this->check_validate_ip( $ip ) ) {
						$ip_list[] = $ip;
					}
				}
			}
		}

		return $ip_list;
	}

	/**
	 * Return all the headers found.
	 *
	 * @return array Header(s) key/name.
	 */
	public function get_ip_header(): array {
		$header_array = [];
		foreach ( $this->accepted_header as $key ) {
			if ( array_key_exists( $key, $_SERVER ) && ! empty( $_SERVER[ $key ] ) ) {
				$ip_array = explode( ',', $_SERVER[ $key ] );
				foreach ( $ip_array as $ip ) {
					$ip = trim( $ip );
					if ( $this->check_validate_ip( $ip ) ) {
						$header_array[] = $key;
						break;
					}
				}
			}
		}

		return $header_array;
	}

}
