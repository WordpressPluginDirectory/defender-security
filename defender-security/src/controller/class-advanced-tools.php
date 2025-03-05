<?php
/**
 * The advanced tools class.
 *
 * @package WP_Defender\Controller
 */

namespace WP_Defender\Controller;

use WP_Defender\Event;
use WP_Defender\Integrations\MaxMind_Geolocation;
use WP_Filesystem_Base;

/**
 * Since advanced tools will have many submodules, this just using for render.
 *
 * Class Advanced_Tools
 */
class Advanced_Tools extends Event {
	/**
	 * Menu slug name.
	 *
	 * @var string
	 */
	public $slug = 'wdf-advanced-tools';

	/**
	 * Constructor method
	 */
	public function __construct() {
		$this->register_page(
			$this->get_title(),
			$this->slug,
			array( $this, 'main_view' ),
			$this->parent_slug
		);
		$this->register_routes();
		add_action( 'defender_enqueue_assets', array( $this, 'enqueue_assets' ) );
		add_action( 'admin_init', array( $this, 'mark_page_visited' ) );
	}

	/**
	 * Enqueue assets.
	 */
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
	 * Render the main view for this page.
	 */
	public function main_view() {
		$this->render( 'main' );
	}

	/**
	 * Remove settings for all submodules.
	 */
	public function remove_settings() {
		( new \WP_Defender\Model\Setting\Mask_Login() )->delete();
		( new \WP_Defender\Model\Setting\Security_Headers() )->delete();
		( new \WP_Defender\Model\Setting\Password_Protection() )->delete();
		( new \WP_Defender\Model\Setting\Password_Reset() )->delete();
		( new \WP_Defender\Model\Setting\Recaptcha() )->delete();
		( new \WP_Defender\Model\Setting\Strong_Password() )->delete();
	}

	/**
	 * Delete all the data & the cache.
	 *
	 * @since 2.4.6
	 */
	public function remove_data() {
		wd_di()->get( \WP_Defender\Controller\Mask_Login::class )->remove_data();
		// Remove data of all Password features.
		wd_di()->get( \WP_Defender\Controller\Password_Protection::class )->remove_data();
		wd_di()->get( \WP_Defender\Controller\Password_Reset::class )->remove_data();
		wd_di()->get( \WP_Defender\Controller\Strong_Password::class )->remove_data();
		// End.
		wd_di()->get( \WP_Defender\Controller\Recaptcha::class )->remove_data();

		global $wp_filesystem;
		// Initialize the WP filesystem, no more using 'file-put-contents' function.
		if ( empty( $wp_filesystem ) ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';
			WP_Filesystem();
		}

		$service_geo = wd_di()->get( MaxMind_Geolocation::class );
		$maxmind_dir = $service_geo->get_db_base_path();
		$wp_filesystem->delete( $maxmind_dir, true );
		$arr_deleted_files = array(
			'audit',
			'internal',
			'malware_scan',
			'notification-audit',
			'scan',
			'password',
			'defender.log',
			'audit.log',
			'firewall.log',
			'internal.log',
			'malware_scan.log',
			'notification-audit.log',
			'scan.log',
			'password.log',
			'backlog',
			'mask',
			'notification',
		);

		foreach ( $arr_deleted_files as $deleted_file ) {
			$wp_filesystem->delete( $deleted_file );
		}

		$this->handle_log_file_deletion();
	}

	/**
	 * Handle log file deletion.
	 *
	 * @since 4.7.2
	 * @return void
	 */
	public function handle_log_file_deletion(): void {
		if ( is_multisite() ) {
			global $wpdb;

			$offset = 0;
			$limit  = 100;
			$blogs  = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				$wpdb->prepare(
					"SELECT blog_id FROM {$wpdb->blogs} LIMIT %d, %d",
					$offset,
					$limit
				),
				ARRAY_A
			);
			while ( ! empty( $blogs ) && is_array( $blogs ) ) {
				foreach ( $blogs as $blog ) {
					switch_to_blog( $blog['blog_id'] );

					$this->delete_log_files();

					restore_current_blog();
				}
				$offset += $limit;
				$blogs   = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
					$wpdb->prepare(
						"SELECT blog_id FROM {$wpdb->blogs} LIMIT %d, %d",
						$offset,
						$limit
					),
					ARRAY_A
				);
			}
		} else {
			$this->delete_log_files();
		}
	}

	/**
	 * Delete log files.
	 *
	 * @since 4.7.2
	 * @return void
	 */
	private function delete_log_files(): void {
		global $wp_filesystem;

		// Initialize the WP filesystem, no more using 'file-put-contents' function.
		if ( empty( $wp_filesystem ) ) {
			require_once ABSPATH . '/wp-admin/includes/file.php';
			WP_Filesystem();
		}

		$upload_dir  = wp_upload_dir();
		$upload_path = $upload_dir['basedir'] . DIRECTORY_SEPARATOR . 'wp-defender';

		if ( is_dir( $upload_path ) ) {
			$files = glob( $upload_path . '/*.log' );

			foreach ( $files as $file ) {
				if ( $wp_filesystem->is_file( $file ) ) {
					$wp_filesystem->delete( $file );
				}
			}
		}
	}

	/**
	 * Get data for frontend
	 *
	 * @return array
	 */
	public function data_frontend(): array {
		return array(
			'mask_login'       => wd_di()->get( Mask_Login::class )->data_frontend(),
			'security_headers' => wd_di()->get( Security_Headers::class )->data_frontend(),
			'pwned_passwords'  => wd_di()->get( Password_Protection::class )->data_frontend(),
			'recaptcha'        => wd_di()->get( Recaptcha::class )->data_frontend(),
			'strong_password'  => wd_di()->get( Strong_Password::class )->data_frontend(),
		);
	}

	/**
	 * Export to array
	 */
	public function to_array() {}

	/**
	 * Import data
	 *
	 * @param array $data The data to import.
	 */
	public function import_data( $data ) {}

	/**
	 * Export strings
	 *
	 * @return array
	 */
	public function export_strings() {
		return array();
	}

	/**
	 * Returns the title of the page.
	 *
	 * @return string The title of the page.
	 */
	public function get_title(): string {
		// Check if the user has already visited the Password Rules page.
		$default = esc_html__( 'Tools', 'defender-security' );
		if ( get_user_meta( get_current_user_id(), 'wd_password_rules_visited', true ) ) {
			return $default;
		}

		return $default . '<span class=wd-new-feature-dot></span>';
	}

	/**
	 * Marks the password rules page as visited.
	 *
	 * @return void
	 */
	public function mark_page_visited(): void {
		if ( 'wdf-advanced-tools' !== defender_get_current_page() || 'password-rules' !== defender_get_data_from_request( 'view', 'g' ) ) {
			return;
		}
		update_user_meta( get_current_user_id(), 'wd_password_rules_visited', 1 );
	}
}
