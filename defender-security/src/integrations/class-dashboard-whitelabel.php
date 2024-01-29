<?php

namespace WP_Defender\Integrations;

if ( ! defined( 'ABSPATH' ) ) {
	die;
}

/**
 * Class Dashboard_Whitelabel
 *
 * @since 3.2.0
 * @package WP_Defender\Integrations
 */
class Dashboard_Whitelabel {

	/**
	 * @var array Holds dashboard plugin white-label filter values.
	 */
	private $wpmudev_branding;

	public function __construct() {
		$this->wpmudev_branding = apply_filters( 'wpmudev_branding', [] );
	}

	/**
	 * Hide or show branding.
	 *
	 * @return bool True to hide and false for show.
	 */
	public function is_hide_branding(): bool {
		return isset( $this->wpmudev_branding['hide_branding'] ) && $this->wpmudev_branding['hide_branding'];
	}

	/**
	 * Get branding logo.
	 *
	 * @return string URL of whitelabeled logo or default logo.
	 */
	public function get_branding_logo(): string {
		if ( $this->is_hide_branding() && ! empty( trim( $this->wpmudev_branding['hero_image'] ) ) ) {
			return $this->wpmudev_branding['hero_image'];
		}

		return defender_asset_url( '/assets/email-images/logo.png' );
	}

	/**
	 * Boolean to check before change footer text.
	 *
	 * @return bool True to change and false for use default.
	 */
	public function is_change_footer(): bool {
		return isset( $this->wpmudev_branding['change_footer'] ) && $this->wpmudev_branding['change_footer'];
	}

	/**
	 * Footer text either custom text or default text.
	 *
	 * @return string Text to show in email content footer.
	 */
	public function get_footer_text(): string {
		if ( $this->is_change_footer() && $this->is_set_footer_text() ) {
			return $this->wpmudev_branding['footer_text'];
		}

		return esc_html__( 'The WPMU DEV Team.', 'defender-security' );
	}

	/**
	 * Check if whitelabel feature is allowed for the membership.
	 *
	 * @since 4.5.0
	 * @return bool
	 */
	public function can_whitelabel(): bool {
		if (
			class_exists( '\WPMUDEV_Dashboard' ) &&
			is_object( \WPMUDEV_Dashboard::$whitelabel ) &&
			method_exists( \WPMUDEV_Dashboard::$whitelabel, 'can_whitelabel' ) &&
			\WPMUDEV_Dashboard::$whitelabel->can_whitelabel()
		) {
			return true;
		}

		return false;
	}

	/**
	 * Check if whitelabel footer text is set.
	 *
	 * @since 4.5.0
	 * @return bool
	 */
	public function is_set_footer_text(): bool {
		$text = $this->wpmudev_branding['footer_text'] ?? '';

		return trim( $text ) !== '';
	}

	/**
	 * Whether to custom plugin labels or not.
	 *
	 * @param int $plugin_id Plugin id.
	 *
	 * @since 4.5.0
	 * @return bool
	 */
	private function plugin_enabled( $plugin_id ) {
		if (
			! class_exists( '\WPMUDEV_Dashboard' ) ||
			empty( \WPMUDEV_Dashboard::$whitelabel ) ||
			! method_exists( \WPMUDEV_Dashboard::$whitelabel, 'get_settings' )
		) {
			return false;
		}
		$whitelabel_settings = \WPMUDEV_Dashboard::$whitelabel->get_settings();

		return ! empty( $whitelabel_settings['labels_enabled'] )
			&& ! empty( $whitelabel_settings['labels_config'][ $plugin_id ] );
	}

	/**
	 * Get custom plugin label.
	 *
	 * @param int $plugin_id Plugin id.
	 *
	 * @since 4.5.0
	 * @return bool|string
	 */
	public function get_plugin_name( $plugin_id ) {
		if ( ! $this->plugin_enabled( $plugin_id ) ) {
			return false;
		}
		$whitelabel_settings = \WPMUDEV_Dashboard::$whitelabel->get_settings();
		if ( empty( $whitelabel_settings['labels_config'][ $plugin_id ]['name'] ) ) {
			return false;
		}

		return $whitelabel_settings['labels_config'][ $plugin_id ]['name'];
	}
}
