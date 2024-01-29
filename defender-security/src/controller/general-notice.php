<?php

namespace WP_Defender\Controller;

use Calotes\Component\Response;

/**
 * This class displays common data on different plugin pages, e.g. a notice about extended IP detection logic.
 *
 * Class General_Notice
 * @package WP_Defender\Controller
 * @since 4.4.2
 */
class General_Notice extends \WP_Defender\Controller {

	public const IP_DETECTION_SLUG = 'wd_show_ip_detection_notice';

	public function __construct() {
		$this->register_routes();
	}

	/**
	 * @return array
	 */
	public function get_notice_data(): array {
		$result = $this->dump_routes_and_nonces();

		return [
			'routes' => $result['routes'],
			'nonces' => $result['nonces'],
		];
	}

	/**
	 * @return Response
	 * @defender_route
	 */
	public function close_ip_detection_notice(): Response {
		self::delete_slugs();

		return new Response( true, [] );
	}

	public static function delete_slugs(): void {
		delete_site_option( self::IP_DETECTION_SLUG );
	}

	/**
	 * @return bool
	 */
	public function show_notice(): bool {
		return (bool) get_site_option( self::IP_DETECTION_SLUG );
	}

	public function remove_data() {}

	/**
	 * @return array
	 */
	public function export_strings(): array {
		return [];
	}

	/**
	 * @return array
	 */
	public function to_array(): array {
		return [];
	}

	/**
	 * @param array $data
	 *
	 * @return void
	 */
	public function import_data( $data ): void {}

	/**
	 * @return void
	 */
	public function remove_settings(): void {}

	/**
	 * @return array
	 */
	public function data_frontend(): array {
		return [];
	}
}
