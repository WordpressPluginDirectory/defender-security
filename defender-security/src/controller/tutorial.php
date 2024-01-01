<?php

namespace WP_Defender\Controller;

use Calotes\Component\Response;
use Calotes\Helper\Route;
use WP_Defender\Controller;

/**
 * Class Tutorial
 * @package WP_Defender\Controller
 */
class Tutorial extends Controller {
	public $slug = 'wdf-tutorial';

	public function __construct() {
		// Check if tutorials should be hidden.
		$hide = apply_filters( 'wpmudev_branding_hide_doc_link', false );
		if ( ! $hide ) {
			$this->register_page(
				esc_html__( 'Tutorials', 'defender-security' ),
				$this->slug,
				[ &$this, 'main_view' ],
				$this->parent_slug
			);
			add_action( 'defender_enqueue_assets', [ &$this, 'enqueue_assets' ] );
			$this->register_routes();
		}
	}

	/**
	 * Enqueue assets & output data.
	 */
	public function enqueue_assets(): void {
		if ( $this->is_page_active() ) {
			wp_localize_script( 'def-tutorial', 'tutorial', $this->data_frontend() );
			wp_enqueue_script( 'def-tutorial' );
			$this->enqueue_main_assets();
		}
	}

	public function main_view() {
		$this->render( 'main' );
	}

	/**
	 * @return bool
	 */
	public function is_show(): bool {
		return ! get_site_option( 'wp_defender_hide_tutorials' ) && ! apply_filters( 'wpmudev_branding_hide_doc_link', false );
	}

	/**
	 * @return array
	 */
	public function to_array(): array {
		[ $routes, $nonces ] = Route::export_routes( 'tutorial' );

		return [
			'show' => $this->is_show(),
			'endpoints' => $routes,
			'nonces' => $nonces,
		];
	}

	/**
	 * Hide tutorials.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function hide(): Response {
		update_site_option( 'wp_defender_hide_tutorials', true );

		return new Response(
			true,
			[
				'message' => sprintf(
				/* translators: %s: Tutorial link. */
					__(
						'The widget has been removed. You can check all defender tutorials at the <a href="%s">tutorials\' tab</a> at any time.',
						'defender-security'
					),
					network_admin_url( 'admin.php?page=wdf-tutorial' )
				),
			]
		);
	}

	public function remove_settings() {
		delete_site_option( 'wp_defender_hide_tutorials' );
	}

	public function remove_data() {
		delete_site_option( 'wp_defender_hide_tutorials' );
	}

	/**
	 * All the variables that we will show on frontend, both in the main page, or dashboard widget.
	 *
	 * @return array
	 */
	public function data_frontend(): array {
		return array_merge(
			[ 'show' => $this->is_show() ],
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * @param array $data
	 *
	 * @return void
	 */
	public function import_data( $data ): void {}

	/**
	 * @return array
	 */
	public function export_strings(): array {
		return [];
	}
}
