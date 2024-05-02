<?php

namespace WP_Defender\Integrations;

if ( ! defined( 'ABSPATH' ) ) {
	die;
}

use WP_Defender\Behavior\WPMUDEV;
use WP_Error;

/**
 * A client class for interacting with Blocklist API service.
 *
 * @since 4.7.1
 * @package WP_Defender\Integrations
 */
class Blocklist_Client {
	/**
	 * The base URL of the Blocklist API service.
	 *
	 * @var string
	 */
	// TODO: Change this to the production API URL.
	private $base_url = 'https://staging-api.blocklist-service.com';

	/**
	 * @var WPMUDEV
	 */
	private $wpmudev;

	public function __construct( WPMUDEV $wpmudev ) {
		$this->wpmudev = $wpmudev;
	}

	/**
	 * Get the base URL of the Blocklist API service.
	 *
	 * @return string
	 */
	private function get_base_url(): string {
		$base_url = defined( 'BLOCKLIST_CUSTOM_API_SERVER' ) && BLOCKLIST_CUSTOM_API_SERVER
			? BLOCKLIST_CUSTOM_API_SERVER
			: $this->base_url;

		return $base_url . '/api';
	}

	/**
	 * Send firewall logs to blocklist API.
	 *
	 * @param array $data The firewall logs.
	 *
	 * @return array|WP_Error
	 */
	public function send_reports( $data ) {
		return $this->make_request( 'POST', '/report', $data );
	}

	/**
	 * Make a request to the Blocklist API service.
	 *
	 * @param string $method   The HTTP method to use.
	 * @param string $endpoint The API endpoint to request.
	 * @param array  $data     The data to send with the request.
	 *
	 * @return array|WP_Error
	 */
	private function make_request( $method, $endpoint, $data = [] ) {
		$apikey = $this->wpmudev->get_apikey();

		if ( ! $apikey ) {
			return new WP_Error( 'no_api_key', 'No API key provided' );
		}

		$response = wp_remote_request(
			$this->get_base_url() . $endpoint,
			[
				'method'  => $method,
				'headers' => [
					'x-blocklist-auth' => $apikey,
					'Content-Type'     => 'application/json',
				],
				'body'    => json_encode( $data ),
			]
		);

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		return json_decode( wp_remote_retrieve_body( $response ), true );
	}
}
