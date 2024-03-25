<?php

namespace WP_Defender\Component\Http;

use WP_Defender\Model\Setting\Firewall;
use WP_Defender\Component\Http\Remote_Address\Remote_Address as Modern_Remote_Address;
use WP_Defender\Component\Http\Remote_Address\Classic_Remote_Address;

/**
 * Class Remote_Addr.
 *
 * Service layer decides/stragize which instance of remote address class to use.
 *
 * @package WP_Defender\Component\Http\Remote_Address
 */
class Remote_Address {

	/**
	 * @var Firewall
	 */
	private $firewall;

	/**
	 * @var string HTTP IP header name.
	 */
	private $http_ip_header = '';

	public function __construct() {
		$this->firewall = wd_di()->get( Firewall::class );
		$this->http_ip_header = esc_html( $this->firewall->http_ip_header );
	}

	/**
	 * Sets the HTTP IP header key.
	 *
	 * @param string $http_header HTTP header key/name.
	 */
	public function set_http_ip_header( $http_header ): void {
		$this->http_ip_header = $http_header;
	}

	private function instance() {
		/**
		 * Filter the HTTP IP header.
		 *
		 * @param string $http_ip_header HTTP header for identifying client's IP.
		 * @since 4.5.1
		 */
		$http_ip_header = (string) apply_filters( 'wpdef_firewall_ip_detection', $this->http_ip_header );
		switch ( $http_ip_header ) {
			case 'HTTP_X_FORWARDED_FOR':
			case 'HTTP_X_REAL_IP':
			case 'HTTP_CF_CONNECTING_IP':
				$remote_address = wd_di()->get( Modern_Remote_Address::class );
				$remote_address
					->set_use_proxy()
					->set_proxy_header( $http_ip_header )
					->set_trusted_proxies( $this->firewall->get_trusted_proxies_ip() )
					->set_trusted_proxy_preset( $this->firewall->get_trusted_proxy_preset() );

				return $remote_address;

			case 'REMOTE_ADDR':
				$remote_address = wd_di()->get( Modern_Remote_Address::class );
				$remote_address->set_use_proxy( false );

				return $remote_address;

			default:
				return wd_di()->get( Classic_Remote_Address::class );
		}
	}

	public function get_ip_address() {
		return $this->instance()->get_ip_address();
	}

	/**
	 * Return HTTP IP header(s) value if it presents else failed message.
	 *
	 * @param string $http_ip_header_key HTTP header key/name.
	 *
	 * @return string Header(s) value or failure message.
	 */
	public function get_http_ip_header_value( string $http_ip_header_key ): string {
		$ip_array = [];
		if ( empty( $http_ip_header_key ) ) {
			$ip_array = wd_di()->get( Classic_Remote_Address::class )->get_ip_header();
		} else if ( isset( $_SERVER[ $http_ip_header_key ] ) ) {
			$ip_array[] = $_SERVER[ $http_ip_header_key ];
		}

		return ! empty( $ip_array ) ?
			implode( ', ', $ip_array ) :
			sprintf( /* translators: %s - HTTP IP header */
				__( '%s header missing in $_SERVER global variable.', 'defender-security' ),
				$http_ip_header_key
			);
	}

}
