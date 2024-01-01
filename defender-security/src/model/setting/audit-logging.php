<?php

namespace WP_Defender\Model\Setting;

use Calotes\Model\Setting;

class Audit_Logging extends Setting {
	/**
	 * Option name.
	 * @var string
	 */
	protected $table = 'wd_audit_settings';
	/**
	 * @defender_property
	 * @var bool
	 */
	public $enabled = false;
	/**
	 * @defender_property
	 * @var string
	 */
	public $storage_days = '6 months';

	/**
	 * Define settings labels.
	 *
	 * @return array
	 */
	public function labels(): array {
		return [
			'enabled' => self::get_module_name(),
			'storage_days' => __( 'Storage for', 'defender-security' ),
		];
	}

	/**
	 * @since 2.6.5
	 * @return bool
	 */
	public function is_active(): bool {
		return (bool) apply_filters( 'wd_audit_enable', $this->enabled );
	}

	/**
	 * @return string
	 */
	public static function get_module_name(): string {
		return __( 'Audit Logging', 'defender-security' );
	}
}
