<?php

namespace WP_Defender\Component;

use WP_Defender\Component;

/**
 * Class Mail.
 *
 * @since 4.5.0
 * @package WP_Defender\Component
 */
class Mail extends Component {

	/**
	 * Get sender name.
	 *
	 * @param string $notification_slug
	 *
	 * @return string
	 */
	public function get_sender_name( $notification_slug ): string {
		$whitelabel = new \WP_Defender\Integrations\Dashboard_Whitelabel;
		if ( $whitelabel->can_whitelabel() ) {
			$plugin_label = $whitelabel->get_plugin_name( \WP_Defender\Component\Config\Config_Hub_Helper::WDP_ID );
			if ( empty( $plugin_label ) ) {
				$plugin_label = $this->find_feature_name_by_slug( $notification_slug );
			}
		} else {
			$plugin_label = __( 'Defender', 'defender-security' );
		}

		return $plugin_label;
	}

	/**
	 * @param string $slug
	 *
	 * @return string
	 */
	protected function find_feature_name_by_slug( $slug ) {
		switch ( $slug ) {
			case \WP_Defender\Model\Notification\Tweak_Reminder::SLUG:
				return __( 'Recommendations', 'defender-security' );
			case \WP_Defender\Model\Notification\Malware_Notification::SLUG:
			case \WP_Defender\Model\Notification\Malware_Report::SLUG:
				return __( 'Malware Scanning', 'defender-security' );
			case \WP_Defender\Model\Notification\Firewall_Notification::SLUG:
			case \WP_Defender\Model\Notification\Firewall_Report::SLUG:
				return __( 'Firewall', 'defender-security' );
			case \WP_Defender\Model\Notification\Audit_Report::SLUG:
				return __( 'Audit Logging', 'defender-security' );
			case 'subscription':
				return __( 'Subscription', 'defender-security' );
			case 'subscribe_confimed':
				return __( 'Subscription Confirmed', 'defender-security' );
			case 'unsubscription':
				return __( 'Unsubscription', 'defender-security' );
			case 'totp':
				return __( 'Two-Factor Authentication', 'defender-security' );
			case \WP_Defender\Component\Unlock_Me::SLUG_UNLOCK:
				return \WP_Defender\Component\Unlock_Me::get_feature_title();
			default:
				return '';
		}
	}

	/**
	 * Noreply email header.
	 * Generate noreply email header with HTML UTF-8 support.
	 *
	 * @param string $from_email
	 * @param string $notification_slug
	 *
	 * @return array Returns the email headers.
	 */
	public function get_headers( $from_email, $notification_slug = '' ): array {
		$from_label = $this->get_sender_name( $notification_slug );
		$headers = [
			'From: '. $from_label .' <' . $from_email . '>',
			'Content-Type: text/html; charset=UTF-8',
		];

		return $headers;
	}

	//Todo: move defender_noreply_email() from functions.php
}
