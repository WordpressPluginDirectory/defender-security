<?php

namespace WP_Defender\Controller;

use WP_Defender\Event;
use WP_Defender\Integrations\MaxMind_Geolocation;

/**
 * Since advanced tools will have many submodules, this just using for render.
 *
 * Class Advanced_Tools
 * @package WP_Defender\Controller
 */
class Advanced_Tools extends Event {
	public $slug = 'wdf-advanced-tools';

	public function __construct() {
		$this->register_page( esc_html__( 'Tools', 'defender-security' ), $this->slug, [
			&$this,
			'main_view'
		], $this->parent_slug );
		$this->register_routes();
		add_action( 'defender_enqueue_assets', [ &$this, 'enqueue_assets' ] );
	}

	public function enqueue_assets() {
		if ( ! $this->is_page_active() ) {
			return;
		}

		$data = $this->dump_routes_and_nonces();
		wp_enqueue_script( 'clipboard' );
		$data = (array) apply_filters( 'wp_defender_advanced_tools_data', $data );
		wp_localize_script( 'def-advancedtools', 'advanced_tools', $data );
		wp_enqueue_script( 'def-advancedtools' );
		$this->enqueue_main_assets();
	}

	/**
	 * Render the root element for frontend.
	 */
	public function main_view() {
		$this->render( 'main' );
	}

	/**
	 * Remove settings of submodules.
	 */
	public function remove_settings() {
		( new \WP_Defender\Model\Setting\Mask_Login() )->delete();
		( new \WP_Defender\Model\Setting\Security_Headers() )->delete();
		( new \WP_Defender\Model\Setting\Password_Protection() )->delete();
		( new \WP_Defender\Model\Setting\Password_Reset() )->delete();
		( new \WP_Defender\Model\Setting\Recaptcha() )->delete();
	}

	/**
	 * Drop Defender's directories and files in /uploads/.
	 *
	 * @since 2.4.6
	 */
	public function remove_data() {
		( new \WP_Defender\Controller\Password_Reset() )->remove_data();
		global $wp_filesystem;
		if ( is_null( $wp_filesystem ) ) {
			WP_Filesystem();
		}

		$service_geo = wd_di()->get( MaxMind_Geolocation::class );
		$maxmind_dir = $service_geo->get_db_base_path();
		$wp_filesystem->delete( $maxmind_dir, true );
		$arr_deleted_files = array(
			// Files without '.log'. We can delete it when we switch to the <category>.log format completely.
			'audit',
			'internal',
			'malware_scan',
			'notification-audit',
			'scan',
			'password',
			// Files with '.log'.
			'defender.log',
			'audit.log',
			'firewall.log',
			'internal.log',
			'malware_scan.log',
			'notification-audit.log',
			'scan.log',
			'password.log',
			// Old category titles.
			'backlog',
			'mask',
			'notification',
		);

		foreach ( $arr_deleted_files as $deleted_file ) {
			$wp_filesystem->delete( $deleted_file );
		}
	}

	/**
	 * @return array
	 */
	public function data_frontend(): array {
		return [
			'mask_login' => wd_di()->get( Mask_Login::class )->data_frontend(),
			'security_headers' => wd_di()->get( Security_Headers::class )->data_frontend(),
			'pwned_passwords' => wd_di()->get( Password_Protection::class )->data_frontend(),
			'recaptcha' => wd_di()->get( Recaptcha::class )->data_frontend(),
		];
	}

	public function to_array() {}

	public function import_data( $data ) {}

	/**
	 * @return array
	 */
	public function export_strings() {
		return [];
	}
}
