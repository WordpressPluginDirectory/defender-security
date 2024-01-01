<?php

namespace WP_Defender\Controller;

use Calotes\Component\Response;
use WP_Defender\Event;
use WP_Defender\Model\Setting\Main_Setting;
use WP_Defender\Component\Config\Config_Hub_Helper;

/**
 * Class Data_Tracking
 * @package WP_Defender\Controller
 * @since 4.2.0
 */
class Data_Tracking extends Event {

	public const TRACKING_SLUG = 'wd_show_usage_data';

	public function __construct() {
		$this->register_routes();
	}

	/**
	 * Get the Tracking modal that is displayed on all plugin pages.
	 *
	 * @return array
	 */
	public function get_tracking_modal(): array {
		$title = __( 'Help Us Enhance Your Site\'s Security', 'defender-security' );

		$current_user = wp_get_current_user();

		$desc = sprintf(
			/* translators: %s: user display name */
			__( 'Hey there! %s, Defender is dedicated to protecting your WordPress website from hackers and malware. However, our mission is more effective with your collaboration. By opting in to share anonymous usage data, you help us refine and enhance our plugin for everyone\'s benefit.', 'defender-security' ),
			'<strong>' . esc_html( $current_user->display_name ) . '</strong>'
		);
		$desc .= '<br/><br/>';
		$desc .= sprintf(
			/* translators: %s: Link. */
			__( 'Your privacy is important to us. We guarantee that your data stays anonymous and your identity stays secure. Learn more about our usage tracking <a href="%s" target="_blank">here<a>.', 'defender-security' ),
			Main_Setting::PRIVACY_LINK
		);
		$result = $this->dump_routes_and_nonces();

		return [
			'title' => $title,
			'desc' => $desc,
			'banner_1x' => defender_asset_url( '/assets/img/modal/tracking-modal.png' ),
			'banner_2x' => defender_asset_url( '/assets/img/modal/tracking-modal@2x.png' ),
			'banner_alt' => __( 'Help us improve Defender', 'defender-security' ),
			'optin_button_title' => __( 'OPT IN', 'defender-security' ),
			'skip_button_title' => __( 'Skip for now', 'defender-security' ),
			'state_usage_tracking' => wd_di()->get( Main_Setting::class )->usage_tracking,
			'routes' => $result['routes'],
			'nonces' => $result['nonces'],
		];
	}

	/**
	 * @return Response
	 * @defender_route
	 */
	public function close_track_modal(): Response {
		//Track.
		$this->track_feature( 'def_tracking_modal', [ 'Modal Action' => 'closed' ] );
		self::delete_modal_key();

		return new Response( true, [] );
	}

	/**
	 * Save Enabled tracking state.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function save_track_modal(): Response {
		$model_settings = wd_di()->get( Main_Setting::class );
		// Update the value if it's changed.
		if ( $model_settings->usage_tracking !== true ) {
			$model_settings->toggle_tracking( true );
			// Changes for Hub.
			Config_Hub_Helper::set_clear_active_flag();
			//Track#1.
			$this->track_opt_toggle( true, 'Tracking modal' );
			//Track#2.
			$this->track_feature( 'def_tracking_modal', [ 'Modal Action' => 'cta_clicked' ] );
		}
		// Hide the modal.
		self::delete_modal_key();

		return new Response( true, [] );
	}

	public static function delete_modal_key(): void {
		delete_site_option( self::TRACKING_SLUG );
	}

	/**
	 * Conditions of the Tracking modal:
	 * 1)show on all Defender pages.
	 * 2)show to users upgrading from older versions.
	 * 3)should have higher priority than a Welcome modal on the Defender > Dashboard page.
	 * 4)if user closes or clicks on the Save button on one plugin page, we don't itl on another plugin page.
	 * 5)no display after the updated Onboarding with Opt-in.
	 * 6)no display when Whitelabel > Documentation, Tutorials and What’s New Modal is set to “Hide”
	 *
	 * @return bool
	 */
	public function show_tracking_modal() {
		$info = defender_white_label_status();

		$white_label_is_hide = isset( $info['hide_doc_link'] ) && $info['hide_doc_link'];

		return (bool) get_site_option( self::TRACKING_SLUG ) && ! $white_label_is_hide;
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
