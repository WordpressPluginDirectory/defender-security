<?php

namespace WP_Defender\Component;

use Calotes\Helper\HTTP;
use WP_Defender\Model\Lockout_Ip;
use WP_Defender\Model\Unlockout;
use WP_Defender\Controller\Firewall;

/**
 * Class Unlock_Me.
 *
 * @since 4.6.0
 * @package WP_Defender\Component
 */
class Unlock_Me extends \WP_Defender\Component {
	/**
	 * @var int
	 */
	public const EXPIRED_COUNTER_TIME = 5 * MINUTE_IN_SECONDS;

	/**
	 * @var string
	 */
	public const SLUG_UNLOCK = 'defender_unlock_me';

	/**
	 * @return string
	 */
	public static function get_expired_time(): string {
		return (string) apply_filters( 'wpdef_firewall_unlockout_expired_time', '-30 minutes' );
	}

	/**
	 * This is a receiver to unlock IP(-s) using email.
	 * It makes no difference whether the user is logged in or not.
	 *
	 * @return bool|void
	 */
	public function maybe_unlock() {
		// Hash values contains an user email, IP.
		$hash = HTTP::get( 'hash', '' );
		$login = HTTP::get( 'login', '' );
		//Get Unlock ID(-s).
		$string_uid = HTTP::get( 'uid', '' );
		if ( empty( $hash ) || empty( $login ) || empty( $string_uid ) ) {
			return false;
		}

		$user = get_user_by( 'login', $login );
		if ( ! $user ) {
			$this->log( 'Unlock Me. Incorrect result. Not found user for UID(-s) ' . $string_uid, Firewall::FIREWALL_LOG );

			return false;
		}

		$user_email = $user->user_email;
		if ( ! hash_equals( $hash, hash( 'sha256', $user_email . AUTH_SALT ) ) ) {
			$this->log( 'Unlock Me. Incorrect result. Invalid hash.', Firewall::FIREWALL_LOG );

			return false;
		}

		$ips = [];
		// Get the line of ID or several IDs for multiple lockouts, and change status(-es) in Unlockout table.
		$limit_time = strtotime( self::get_expired_time() );
		if ( false !== strpos( $string_uid, '-' ) ) {
			// There are some ID's.
			$arr_uids = explode( '-', $string_uid );
			if ( ! is_array( $arr_uids ) ) {
				$this->log( 'Unlock Me. Incorrect result. Wrong UID(-s).', Firewall::FIREWALL_LOG );

				return false;
			}
			foreach ( $arr_uids as $arr_uid ) {
				$resolved_ip = Unlockout::get_resolved_ip_by( (int) $arr_uid, $user_email, $limit_time );
				if ( 'expired' === $resolved_ip ) {
					return false;
				} elseif ( '' !== $resolved_ip ) {
					// This is not expired result and no empty one.
					$ips[] = $resolved_ip;
				}
			}
		} else {
			// Only one ID.
			$resolved_ip = Unlockout::get_resolved_ip_by( (int) $string_uid, $user_email, $limit_time );
			if ( 'expired' === $resolved_ip ) {
				return false;
			} elseif ( '' !== $resolved_ip ) {
				// This is not expired result and no empty one.
				$ips[] = $resolved_ip;
			}
		}
		// All is good. IP's were unblocked.
		if ( empty( $ips ) ) {
			return true;
		}
		// Work with IP's.
		$ips = array_unique( $ips );
		$first_ip = $ips[0];
		// Remove the user IP's from Blocklist.
		$bl = wd_di()->get( \WP_Defender\Model\Setting\Blacklist_Lockout::class );
		foreach ( $ips as $ip ) {
			$bl->remove_from_list( $ip, 'blocklist' );
			$this->log( 'Unlock Me. Success. IP ' . $ip . ' have been unblocked.', Firewall::FIREWALL_LOG );
		}
		// Maybe IP(-s) in Active lockouts? Then unlock it or them.
		if ( count( $ips ) > 1 ) {
			$models = Lockout_Ip::get_bulk( Lockout_Ip::STATUS_BLOCKED, $ips );
			foreach ( $models as $model ) {
				$model->status = Lockout_Ip::STATUS_NORMAL;
				$model->save();
				$this->log( 'Unlock Me. Success. IP ' . $ip . ' have been unblocked.', Firewall::FIREWALL_LOG );
			}
		} else {
			$ip = Lockout_Ip::get_unlocked_ip_by( $first_ip );
			if ( ! empty( $ip ) ) {
				$this->log( 'Unlock Me. Success. IP ' . $ip . ' have been unblocked.', Firewall::FIREWALL_LOG );
			}
		}
		// Remove the old counter.
		delete_transient( $this->check_ip_by_remote_addr( $first_ip ) );
		// Redirect.
		wp_safe_redirect( \WP_Defender\Component\Mask_Login::maybe_masked_login_url() );
		exit;
	}

	/**
	 * Display the section if:
	 * 1) no empty IP(-s),
	 * 2) depending on the lockout reason.
	 *
	 * @param string $reason
	 * @param array $ips
	 *
	 * @return bool
	 */
	public static function is_displayed( string $reason, array $ips ): bool {
		$excluded_reasons = (array) apply_filters( 'wpdef_firewall_unlockout_excluded_reasons',
			[
				'country',
				'demo',
			]
		);
		$is_displayed = ! in_array( $reason, $excluded_reasons ) && ! empty( $ips );

		return (bool) apply_filters( 'wpdef_firewall_unlockout_is_displayed', $is_displayed );
	}

	/**
	 * Get the limit of failed attempts.
	 *
	 * @return int
	 */
	public static function get_attempt_limit(): int {
		return (int) apply_filters( 'wpdef_firewall_unlockout_attempt_limit', 5 );
	}

	/**
	 * @param string $email
	 * @param string $user_login
	 * @param array  $arr_uids
	 *
	 * @return string
	 */
	public static function create_url( $email, $user_login, $arr_uids ): string {
		$string_uids = implode('-', $arr_uids);

		return add_query_arg(
			[
				'action' => self::SLUG_UNLOCK,
				// No need IP.
				'hash' => hash( 'sha256', $email . AUTH_SALT ),
				'login' => $user_login,
				'uid' => $string_uids,
			],
			network_site_url()
		);
	}

	/**
	 * @return string
	 */
	public static function get_feature_title(): string {
		return __( 'Unlock Me', 'defender-security' );
	}
}
