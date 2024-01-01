<?php

namespace WP_Defender\Model\Setting;

use Calotes\Model\Setting;

class Scan extends Setting {
	/**
	 * @var string
	 */
	protected $table = 'wd_scan_settings';

	/**
	 * Enable core/plugin integrity check while perform a scan.
	 *
	 * @defender_property
	 * @var bool
	 */
	public $integrity_check = true;

	/**
	 * Enable Scan WP core files.
	 *
	 * @defender_property
	 * @var bool
	 */
	public $check_core = true;

	/**
	 * Enable Scan plugin files.
	 *
	 * @defender_property
	 * @var bool
	 */
	public $check_plugins = false;

	/**
	 * Check the files inside wp-content by our malware signatures.
	 *
	 * @defender_property
	 * @var bool
	 */
	public $scan_malware = false;

	/**
	 * Check if any plugins or themes have a known vulnerability.
	 *
	 * @defender_property
	 * @var bool
	 */
	public $check_known_vuln = true;

	/**
	 * If a file is smaller than this, we wil include it to the test.
	 *
	 * @defender_property
	 * @var int
	 */
	public $filesize = 10;

	/**
	 * @defender_property
	 * @var bool
	 */
	public $scheduled_scanning = false;

	/**
	 * The frequency of scheduled scan.
	 *
	 * @var string
	 * @defender_property
	 * @rule in[daily,weekly,monthly]
	 */
	public $frequency;

	/**
	 * The day of scheduled scan.
	 *
	 * @var string
	 * @defender_property
	 * @sanitize_text_field
	 */
	public $day;

	/**
	 * This is for when user select scheduled scan as monthly, we will have the day number, instead of text.
	 *
	 * @var int
	 * @sanitize_text_field
	 * @defender_property
	 */
	public $day_n;

	/**
	 * Same as $day.
	 *
	 * @var string
	 * @defender_property
	 * @sanitize_text_field
	 */
	public $time;

	/**
	 * Quarantine file deletion/expiration cron schedule.
	 *
	 * @var string
	 * @defender_property
	 * @sanitize_text_field
	 */
	public $quarantine_expire_schedule = 'thirty_days';

	/**
	 * Define settings labels.
	 *
	 * @return array
	 */
	public function labels(): array {
		return [
			'integrity_check' => __( 'File change detection', 'defender-security' ),
			'check_core' => __( 'Scan core files', 'defender-security' ),
			'check_plugins' => __( 'Scan plugin files', 'defender-security' ),
			'check_known_vuln' => __( 'Known vulnerabilities', 'defender-security' ),
			'scan_malware' => __( 'Suspicious Code', 'defender-security' ),
			'filesize' => __( 'Max included file size', 'defender-security' ),
			'scheduled_scanning' => __( 'Scheduled Scanning', 'defender-security' ),
			'frequency' => __( 'Frequency', 'defender-security' ),
			'day' => __( 'Day of the week', 'defender-security' ),
			'day_n' => __( 'Day of the month', 'defender-security' ),
			'time' => __( 'Time of day', 'defender-security' ),
		];
	}

	/**
	 * Check different cases for 'File change detection' option.
	 *
	 * @return bool
	 */
	public function is_checked_any_file_change_types(): bool {
		if ( ! $this->integrity_check ) {
			// Check the parent type.
			return false;
		} elseif ( $this->integrity_check && ! $this->check_core && ! $this->check_plugins ) {
			// Check the parent and child types.
			return false;
		}

		return true;
	}

	protected function after_validate(): void {
		// Case#1: all child types of File change detection are unchecked BUT parent type is checked.
		if ( $this->integrity_check && ! $this->check_core && ! $this->check_plugins ) {
			$this->errors[] = __( 'You have not selected a scan type for the <strong>File change detection</strong>. Please choose at least one and save the settings again.', 'defender-security' );
			// Case#2: all scan types are unchecked and Scheduled Scanning is checked.
		} elseif ( ! $this->integrity_check && ! $this->check_known_vuln && ! $this->scan_malware
			&& $this->scheduled_scanning
		) {
			$this->errors[] = __( 'You have not selected a scan type. Please enable at least one scan type and save the settings again.', 'defender-security' );
		}
	}

	protected function before_load(): void {
		$this->frequency = 'weekly';
		$this->day = 'sunday';
		$this->day_n = '1';
		$this->time = '4:00';
	}
}
