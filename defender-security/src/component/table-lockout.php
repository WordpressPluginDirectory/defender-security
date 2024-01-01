<?php

namespace WP_Defender\Component;

use WP_Defender\Component;
use WP_Defender\Model\Lockout_Ip;
use WP_Defender\Model\Lockout_Log;
use WP_Defender\Traits\Formats;

class Table_Lockout extends Component {
	use Formats;

	public const STATUS_BAN = 'ban', STATUS_NOT_BAN = 'not_ban', STATUS_ALLOWLIST = 'allowlist';
	public const SORT_DESC  = 'latest', SORT_ASC = 'oldest', SORT_BY_IP = 'ip', SORT_BY_UA = 'user_agent';
	public const LIMIT_20   = '20', LIMIT_50 = '50', LIMIT_100 = '100', LIMIT_ALL = '-1';

	/**
	 * Get IP status.
	 *
	 * @param string $ip
	 *
	 * @return string
	 */
	public function get_ip_status_text( $ip ): string {
		$bl_component = new \WP_Defender\Component\Blacklist_Lockout();
		if ( $bl_component->is_ip_whitelisted( $ip ) ) {
			return __( 'Is allowlisted', 'defender-security' );
		}
		if ( $bl_component->is_blacklist( $ip ) ) {
			return __( 'Is blocklisted', 'defender-security' );
		}

		$model = Lockout_Ip::get( $ip );
		if ( ! is_object( $model ) ) {
			return __( 'Not banned', 'defender-security' );
		}

		if ( Lockout_Ip::STATUS_BLOCKED === $model->status ) {
			return __( 'Banned', 'defender-security' );
		} elseif ( Lockout_Ip::STATUS_NORMAL === $model->status ) {
			return __( 'Not banned', 'defender-security' );
		}

		return '';
	}

	/**
	 * Get types.
	 *
	 * @return array
	 */
	private function get_types(): array {
		return [
			'all' => __( 'All', 'defender-security' ),
			Lockout_Log::AUTH_FAIL => __( 'Failed login attempts', 'defender-security' ),
			Lockout_Log::AUTH_LOCK => __( 'Login lockout', 'defender-security' ),
			Lockout_Log::ERROR_404 => __( '404 error', 'defender-security' ),
			Lockout_Log::LOCKOUT_404 => __( '404 lockout', 'defender-security' ),
			Lockout_Log::LOCKOUT_UA => __( 'User Agent Lockout', 'defender-security' ),
		];
	}

	/**
	 * Get ban statuses.
	 *
	 * @return array
	 */
	private function ban_status(): array {
		return [
			'all' => __( 'All', 'defender-security' ),
			self::STATUS_NOT_BAN => __( 'Not Banned', 'defender-security' ),
			self::STATUS_BAN => __( 'Banned', 'defender-security' ),
			self::STATUS_ALLOWLIST => __( 'Allowlisted', 'defender-security' ),
		];
	}

	/**
	 * Get type.
	 *
	 * @param string $type
	 *
	 * @return string
	 */
	public function get_type( $type ): string {
		$types = [
			Lockout_Log::AUTH_FAIL => __( 'Failed login attempts', 'defender-security' ),
			Lockout_Log::AUTH_LOCK => __( 'Login lockout', 'defender-security' ),
			Lockout_Log::ERROR_404 => __( '404 error', 'defender-security' ),
			Lockout_Log::ERROR_404_IGNORE => __( '404 error', 'defender-security' ),
			Lockout_Log::LOCKOUT_404 => __( '404 lockout', 'defender-security' ),
			Lockout_Log::LOCKOUT_UA => __( 'User Agent Lockout', 'defender-security' ),
		];

		return $types[ $type ] ?? '';
	}

	/**
	 * @return array
	 */
	private function sort_values(): array {
		return [
			self::SORT_DESC => __( 'Latest', 'defender-security' ),
			self::SORT_ASC => __( 'Oldest', 'defender-security' ),
			self::SORT_BY_IP => __( 'IP Address', 'defender-security' ),
			self::SORT_BY_UA => __( 'User agent', 'defender-security' ),
		];
	}

	/**
	 * @return array
	 */
	private function limit_per_page(): array {
		return [
			self::LIMIT_20 => '20',
			self::LIMIT_50 => '50',
			self::LIMIT_100 => '100',
			self::LIMIT_ALL => __( 'All', 'defender-security' ),
		];
	}

	/**
	 * @return array
	 */
	public function get_filters(): array {
		return [
			'lockout_types' => $this->get_types(),
			'ban_status' => $this->ban_status(),
			'sort_values' => $this->sort_values(),
			'limit_logs' => $this->limit_per_page(),
		];
	}
}
