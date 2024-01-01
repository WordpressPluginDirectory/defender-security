<?php

namespace WP_Defender\Component\Security_Tweaks;

use Calotes\Component\Response;
use WP_Error;
use Calotes\Helper\HTTP;
use Calotes\Base\Component;

/**
 * Class Change_Admin
 * @package WP_Defender\Component\Security_Tweaks
 */
class Change_Admin extends Component {
	public $slug = 'replace-admin-username';

	/**
	 * Check whether the issue has been resolved or not.
	 *
	 * @return bool
	 */
	public function check(): bool {
		return $this->is_resolved();
	}

	/**
	 * Here is the code for processing, if the return is true, we add it to resolve list, WP_Error if any error.
	 *
	 * @return bool|\WP_Error
	 */
	public function process() {
		$username = HTTP::post( 'username' );
		$is_valid = $this->validate( $username );

		if ( is_wp_error( $is_valid ) ) {
			return $is_valid;
		}

		return $this->update_username( $username );
	}

	/**
	 * This is for un-do stuff that has be done in @process.
	 *
	 * @return bool
	 */
	public function revert(): bool {
		return true;
	}

	/**
	 * Shield up.
	 *
	 * @return bool
	 */
	public function shield_up(): bool {
		return true;
	}

	/**
	 * Check whether the issue is resolved or not.
	 *
	 * @return bool
	 */
	private function is_resolved() {
		return ! $this->get_user_with_admin_username();
	}

	/**
	 * Get user with admin username.
	 *
	 * @return \WP_User|false on failure
	 */
	private function get_user_with_admin_username() {
		return get_user_by( 'login', 'admin' );
	}

	/**
	 * Validate username.
	 *
	 * @param string $username
	 *
	 * @return bool|WP_Error on failure
	 */
	private function validate( $username ) {
		if ( empty( $username ) ) {
			return new WP_Error( 'defender_invalid_username', __( 'The username can\'t be empty!', 'defender-security' ) );
		}

		if ( 'admin' === strtolower( $username ) ) {
			return new WP_Error(
				'defender_invalid_username',
				__( 'You can\'t use admin as a username again!', 'defender-security' )
			);
		}

		if ( ! validate_username( $username ) ) {
			return new WP_Error( 'defender_invalid_username', __( 'The username is invalid!', 'defender-security' ) );
		}

		if ( username_exists( $username ) ) {
			return new WP_Error( 'defender_invalid_username', __( 'The username already exists!', 'defender-security' ) );
		}

		return true;
	}

	/**
	 * @param string $username
	 *
	 * @return bool|WP_Error|Response
	 */
	private function update_username( $username ) {
		global $wpdb;
		$user = $this->get_user_with_admin_username();

		$ret = $wpdb->update(
			$wpdb->users,
			[ 'user_login' => trim( $username ) ],
			[ 'ID' => $user->ID ]
		);
		if ( ! $ret ) {
			return new WP_Error( 'update_error', $wpdb->last_error );
		}

		if ( is_multisite() ) {
			$site_admins = get_site_option( 'site_admins' );

			if ( is_array( $site_admins ) ) {
				$pos = array_search( 'admin', array_map( 'strtolower', $site_admins ), true );

				if ( false !== $pos ) {
					$site_admins[ $pos ] = $username;
					update_site_option( 'site_admins', $site_admins );
				}
			}
		}
		clean_user_cache( $user );
		// Log the user out only if it's the user with 'admin' username.
		if ( $user->ID !== get_current_user_id() ) {
			return true;
		}
		if ( defined( 'WP_DEFENDER_TESTING' ) && true === constant( 'WP_DEFENDER_TESTING' ) ) {
			// Testing.
			return true;
		}
		$interval = 5;
		$redirect = $this->get_login_url();

		return new Response(
			true,
			[
				'message' => sprintf(
				/* translators: 1. Redirect link. 2. Redirect text. 2. Interval. */
					__(
						'Your admin name has changed. You will need to <a href="%1$s"><strong>%2$s</strong></a>.<br/>This will auto reload after %3$s seconds.',
						'defender-security'
					),
					$redirect,
					're-login',
					'<span class="hardener-timer">' . $interval . '</span>'
				),
				'redirect' => $redirect,
				'interval' => $interval,
			]
		);
	}

	/**
	 * Get the login url.
	 *
	 * @return string
	 */
	private function get_login_url(): string {
		return wp_login_url( network_admin_url( 'admin.php?page=wdf-hardener' ) );
	}

	/**
	 * Return a summary data of this tweak.
	 *
	 * @return array
	 */
	public function to_array(): array {
		return [
			'slug' => $this->slug,
			'title' => __( 'Change default admin user account', 'defender-security' ),
			'errorReason' => __( 'You have a user account with the admin username.', 'defender-security' ),
			'successReason' => __( 'You don\'t have a user account with the default admin username, great!', 'defender-security' ),
			'misc' => [ 'host' => defender_get_hostname() ],
			'bulk_description' => __(
				'Using the default admin username is widely considered bad practice and opens you up to the easitest form of entry to your website. We will create new admin username for you.',
				'defender-security'
			),
			'bulk_title' => __( 'Admin User', 'defender-security' ),
		];
	}
}
