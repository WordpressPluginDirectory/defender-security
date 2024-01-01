<?php

namespace WP_Defender\Controller;

use Calotes\Helper\Route;
use Calotes\Helper\HTTP;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Event;
use WP_Defender\Model\Setting\Login_Lockout;
use WP_Defender\Model\Setting\Notfound_Lockout;
use WP_Defender\Model\Setting\User_Agent_Lockout;
use WP_Defender\Model\Setting\Main_Setting as Model_Main_Setting;

/**
 * This class is only used once, after the activation on a fresh install.
 * We will use this for activating & presets other module settings.
 *
 * Class Onboard
 * @package WP_Defender\Controller
 */
class Onboard extends Event {
	public $slug = 'wp-defender';

	public function __construct() {
		$this->attach_behavior( WPMUDEV::class, WPMUDEV::class );
		$this->add_main_page();
		add_action( 'defender_enqueue_assets', [ &$this, 'enqueue_assets' ] );
	}

	protected function add_main_page() {
		$this->register_page(
			$this->get_menu_title(),
			$this->parent_slug,
			[
				&$this,
				'main_view',
			],
			null,
			$this->get_menu_icon()
		);
	}

	public function main_view() {
		$class = wd_di()->get( Security_Tweaks::class );
		$class->refresh_tweaks_status();
		$this->render( 'main' );
	}

	/**
	 * @defender_route
	 */
	public function activating() {
		if ( ! $this->check_permission() || ! $this->verify_nonce( 'activating' . 'onboard' ) ) {
			wp_send_json_error( [ 'message' => __( 'Invalid', 'defender-security' ) ] );
		}

		$this->attach_behavior( WPMUDEV::class, WPMUDEV::class );

		update_site_option( 'wp_defender_shown_activator', true );
		delete_site_option( 'wp_defender_is_free_activated' );
		if ( $this->is_pro() ) {
			$this->preset_audit();
			$this->preset_blacklist_monitor();
		}
		$this->preset_firewall();
		$this->resolve_security_tweaks();
		$this->preset_scanning();

		$this->maybe_tracking( 'Activate & Configure' );
		// @since 4.2.0 No display the Data Tracking after the Onboarding.
		\WP_Defender\Controller\Data_Tracking::delete_modal_key();

		wp_send_json_success();
	}

	/**
	 * Enable blacklist status.
	 */
	private function preset_blacklist_monitor() {
		$this->make_wpmu_request( WPMUDEV::API_BLACKLIST, [], [
			'method' => 'POST'
		] );
	}

	private function preset_audit() {
		$audit = new \WP_Defender\Model\Setting\Audit_Logging();
		$audit->enabled = true;
		$audit->save();
	}

	private function preset_scanning() {
		$model = new \WP_Defender\Model\Setting\Scan();
		$model->save();
		// Create new scan.
		$ret = \WP_Defender\Model\Scan::create();
		if ( ! is_wp_error( $ret ) ) {
			/**
			 * @var Scan
			 */
			$scan_controller = wd_di()->get( Scan::class );

			$scan_controller->scan_started_analytics(
				[
					'Triggered From' => 'Plugin',
					'Scan Type' => 'Install',
				]
			);

			$scan_controller->do_async_scan( 'install' );
		}
	}

	private function preset_firewall() {
		$lockout = new Login_Lockout();
		$lockout->enabled = true;
		$lockout->save();
		$nf = new Notfound_Lockout();
		$nf->enabled = true;
		$nf->save();
		$ua = new User_Agent_Lockout();
		$ua->enabled = true;
		$ua->save();
	}

	/**
	 * Resolve all tweaks that we can.
	 * @since 2.4.6 Remove tweaks that can be added to wp-config.php manually: 'hide-error', 'disable-file-editor'.
	 */
	private function resolve_security_tweaks() {
		$slugs = [
			'disable-xml-rpc',
			'login-duration',
			'disable-trackback',
			'prevent-enum-users',
		];
		$class = wd_di()->get( Security_Tweaks::class );
		$class->refresh_tweaks_status();
		$class->security_tweaks_auto_action( $slugs, 'resolve' );
	}

	/**
	 * @return array
	 */
	private function get_modules(): array {
		$modules = [
			'Firewall',
			'Recommendations',
		];
		if ( $this->is_pro() ) {
			$modules[] = 'Malware Scanning';
			$modules[] = 'Audit Logging';
			$modules[] = 'Blocklist Monitor';
		} else {
			$modules[] = 'WP file scanning';
		}

		return $modules;
	}

	/**
	 * @param string $action
	 */
	private function maybe_tracking( string $action ) {
		$usage_data_state = HTTP::post( 'usage_tracking', '' );
		// Track it, the default option value is changed to True.
		if ( 'true' === $usage_data_state ) {
			wd_di()->get( Model_Main_Setting::class )->toggle_tracking( true );
			$this->track_opt_toggle( true, 'Wizard' );
			$this->track_feature( 'def_quick_setup', [ 'module' => $this->get_modules(), 'action' => $action ] );
		}
	}

	/**
	 * @defender_route
	 */
	public function skip() {
		if ( ! $this->check_permission() || ! $this->verify_nonce( 'skip' . 'onboard' ) ) {
			wp_send_json_error( [ 'message' => __( 'Invalid', 'defender-security' ) ] );
		}

		update_site_option( 'wp_defender_shown_activator', true );
		delete_site_option( 'wp_defender_is_free_activated' );
		// @since 4.2.0 No display the Data Tracking after the Onboarding.
		\WP_Defender\Controller\Data_Tracking::delete_modal_key();

		$this->maybe_tracking( 'Start from scratch' );
		wp_send_json_success();
	}

	public function enqueue_assets() {
		if ( ! $this->is_page_active() ) {
			return;
		}

		wp_localize_script( 'def-onboard', 'onboard', $this->data_frontend() );
		wp_enqueue_script( 'def-onboard' );
		$this->enqueue_main_assets();
		add_filter( 'admin_body_class', [ $this, 'admin_body_class' ] );
	}

	/**
	 * @param string $classes
	 *
	 * @return string
	 */
	public function admin_body_class( $classes ) {
		$classes .= ' wdf-full-screen ';

		return $classes;
	}

	public function remove_settings() {}

	public function remove_data() {}

	public function export_strings() {}

	public function to_array() {}

	public function import_data( $data ) {}

	/**
	 * @return array
	 */
	public function data_frontend(): array {
		[ $endpoints, $nonces ] = Route::export_routes( 'onboard' );

		return [
			'endpoints' => $endpoints,
			'nonces' => $nonces,
			'misc' => [
				'state_usage_tracking' => wd_di()->get( Model_Main_Setting::class )->usage_tracking,
				'privacy_link' => Model_Main_Setting::PRIVACY_LINK,
			],
		];
	}
}
