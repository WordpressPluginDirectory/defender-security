<?php

namespace WP_Defender\Model\Setting;

use Calotes\Model\Setting;

class Password_Reset extends Setting {
	/**
	 * @var string
	 */
	protected $table = 'wd_password_reset_settings';

	/**
	 * @var array
	 * @defender_property
	 */
	public $user_roles = [];

	/**
	 * @var string
	 * @defender_property
	 * @sanitize sanitize_textarea_field
	 */
	public $message = '';

	/**
	 * @var bool
	 * @defender_property
	 */
	public $expire_force = false;

	/**
	 * @var int
	 * @defender_property
	 */
	public $force_time;

	/**
	 * @return array
	 */
	public function get_default_values(): array {
		return [
			'message' => __( 'You are required to change your password to a new one to use this site.', 'defender-security' ),
		];
	}

	protected function before_load(): void {
		$default_values = $this->get_default_values();
		// Default we will load all rules.
		if ( function_exists( 'get_editable_roles' ) ) {
			// We only need this inside admin, no need to load the user.php everywhere.
			$this->user_roles = array_keys( get_editable_roles() );
		} else {
			// Define defaults user roles.
			$this->user_roles = [ 'administrator' ];
		}
		$this->message = $default_values['message'];
	}

	/**
	 * Define settings labels.
	 *
	 * @return array
	 */
	public function labels(): array {
		return [
			'user_roles' => __( 'User Roles', 'defender-security' ),
			'message' => __( 'Message', 'defender-security' ),
		];
	}

	/**
	 * Checks for active feature: 'expire_force', one role at least and there is a reset time.
	 *
	 * @return bool
	 */
	public function is_active(): bool {
		return (bool) apply_filters(
			'wd_password_reset_active',
			$this->expire_force && count( $this->user_roles ) > 0 && $this->force_time
		);
	}

	/**
	 * @return string
	 */
	public static function get_module_name(): string {
		return __( 'Password Reset', 'defender-security' );
	}
}
