<?php

namespace WP_Defender\Model\Setting;

use Calotes\Model\Setting;

class Password_Protection extends Setting {
	/**
	 * @var string
	 */
	protected $table = 'wd_password_protection_settings';

	/**
	 * Feature status
	 *
	 * @defender_property
	 * @var bool
	 */
	public $enabled = false;

	/**
	 * @defender_property
	 * @var array
	 */
	public $user_roles = [];

	/**
	 * @defender_property
	 * @var array
	 */
	public $pwned_actions = [];

	/**
	 * @return array
	 */
	public function get_default_values(): array {
		return [
			'message' => __( 'You are required to change your password because the password you are using exists on database breach records.', 'defender-security' ),
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
		$this->pwned_actions = [
			'force_change_message' => $default_values['message'],
		];
	}

	/**
	 * Define settings labels.
	 *
	 * @return array
	 */
	public function labels(): array {
		return [
			'enabled' => self::get_module_name(),
			'pwned_actions' => __( 'Force password change', 'defender-security' ),
			'user_roles' => __( 'User Roles', 'defender-security' ),
		];
	}

	/**
	 * Check if the model is activated.
	 *
	 * @return bool
	 */
	public function is_active(): bool {
		return (bool) apply_filters(
			'wd_password_protection_enable',
			$this->enabled && count( $this->user_roles ) > 0
		);
	}

	/**
	 * @return string
	 */
	public static function get_module_name(): string {
		return __( 'Pwned Passwords', 'defender-security' );
	}
}
