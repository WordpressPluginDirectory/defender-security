<?php

namespace WP_Defender\Model\Setting;

class Login_Lockout extends \Calotes\Model\Setting {
	protected $table = 'wd_login_lockout_settings';

	/**
	 * @var bool
	 * @defender_property
	 */
	public $enabled = false;
	/**
	 * Maximum attempt before get locked.
	 *
	 * @var int
	 * @defender_property
	 * @rule required|integer
	 */
	public $attempt = 5;
	/**
	 * The timeframe we record the attempt.
	 *
	 * @var int
	 * @defender_property
	 * @rule required|integer
	 */
	public $timeframe = 300;
	/**
	 * How current lockout last.
	 *
	 * @var int
	 * @defender_property
	 * @rule required|integer
	 */
	public $duration = 300;
	/**
	 * Duration unit.
	 *
	 * @var string
	 * @defender_property
	 * @rule in[seconds,minutes,hours]
	 */
	public $duration_unit = 'seconds';
	/**
	 * How the lock is going to be, if we choose permanent, then their IP will be blacklisted.
	 *
	 * @var string
	 * @defender_property
	 * @rule in[timeframe,permanent]
	 */
	public $lockout_type = 'timeframe';

	/**
	 * The message to output on the lockout screen.
	 *
	 * @var string
	 * @defender_property
	 * @rule required
	 * @sanitize sanitize_textarea_field
	 */
	public $lockout_message = '';

	/**
	 * The blacklist username, if fail will be banned.
	 *
	 * @var string
	 * @defender_property
	 * @rule required
	 * @sanitize sanitize_textarea_field
	 */
	public $username_blacklist = '';

	/**
	 * Validation rules.
	 *
	 * @var array
	 */
	protected $rules = [
		[ [ 'enabled' ], 'boolean' ],
		[ [ 'attempt', 'timeframe', 'duration' ], 'integer' ],
		[ [ 'lockout_type' ], 'in', [ 'timeframe', 'permanent' ] ],
		[ [ 'duration_unit' ], 'in', [ 'seconds', 'minutes', 'hours' ] ],
	];

	/**
	 * @return array
	 */
	public function get_default_values(): array {
		return [
			'message' => __( 'You have been locked out due to too many invalid login attempts.', 'defender-security' ),
		];
	}

	protected function before_load(): void {
		$default_values = $this->get_default_values();
		$this->lockout_message = $default_values['message'];
	}

	/**
	 *  Return the blacklisted username as array.
	 *
	 * @return array
	 */
	public function get_blacklisted_username(): array {
		// @since 2.4.7.
		$usernames = apply_filters( 'wp_defender_banned_usernames', $this->username_blacklist );
		if ( empty( $usernames ) ) {
			return [];
		}
		$usernames = str_replace( [ "\r\n", "\r", "\n" ], ' ', $this->username_blacklist );
		$usernames = explode( ' ', $usernames );

		return array_map( 'trim', $usernames );
	}

	/**
	 * Define settings labels.
	 *
	 * @return array
	 */
	public function labels(): array {
		return [
			// New key: enabled.
			'login_protection' => self::get_module_name(),
			// New key: attempt.
			'login_protection_login_attempt' => __( 'Login Protection - Threshold', 'defender-security' ),
			// New key: timeframe.
			'login_protection_lockout_timeframe' => __( 'Login Protection - Timeframe', 'defender-security' ),
			// New key: lockout_type.
			'login_protection_lockout_ban' => __( 'Login Protection - Duration Type', 'defender-security' ),
			// New key: duration.
			'login_protection_lockout_duration' => __( 'Login Protection - Duration', 'defender-security' ),
			// New key: duration_unit.
			'login_protection_lockout_duration_unit' => __( 'Login Protection - Duration units', 'defender-security' ),
			// New key: lockout_message.
			'login_protection_lockout_message' => __( 'Login Protection - Lockout Message', 'defender-security' ),
			'username_blacklist' => __( 'Login Protection - Banned Usernames', 'defender-security' ),
		];
	}

	/**
	 * @return string
	 */
	public static function get_module_name(): string {
		return __( 'Login Protection', 'defender-security' );
	}

	/**
	 * @param bool $flag
	 *
	 * @return string
	 */
	public static function get_module_state( $flag ): string {
		return $flag ? __( 'active', 'defender-security' ) : __( 'inactive', 'defender-security' );
	}
}
