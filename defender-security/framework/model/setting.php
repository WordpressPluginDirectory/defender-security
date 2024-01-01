<?php

namespace Calotes\Model;

use Calotes\Base\Model;

class Setting extends Model {
	protected $exclude = [ 'table' ];

	protected $old_settings = [];

	public function __construct() {
		// We parse the annotations here, and only one.
		$this->parse_annotations();
		$this->before_load();
		$this->load();
		$this->after_load();
		$this->sanitize();
	}

	public function save() {
		$prepared_data = $this->prepare_data();
		$data = json_encode( $prepared_data );
		$ret = update_site_option( $this->table, $data );
		if ( false === $ret ) {
			$this->internal_logging[] = sprintf(
				'Saving fail on %s with data %s.',
				$this->table,
				json_encode( $data )
			);
		} else {
			/**
			 * Handle settings update. No from WP CLI commands.
			 *
			 * @param array $this->old_settings The old option values.
			 * @param array $prepared_data      The new option values.
			 *
			 * @since 4.2.0
			 */
			do_action( 'wd_settings_update', $this->old_settings, $prepared_data );
		}
	}

	/**
	 * Load data.
	 *
	 * @throws \ReflectionException
	 */
	public function load() {
		$time = microtime( true );
		if ( empty( $this->table ) ) {
			throw new \Exception( 'Table must be defined before using.' );
		}

		$data = get_site_option( $this->table );
		if ( false === $data ) {
			return;
		}

		if ( ! is_array( $data ) ) {
			$data = json_decode( $data, true );
		}

		if ( ! is_array( $data ) ) {
			return;
		}

		$data = $this->prepare_data( $data );
		$this->old_settings = $data;
		$this->import( $data );
		$this->log( sprintf( 'loaded %s - %s', $this->table, microtime( true ) - $time ) );
	}

	public function delete() {
		delete_site_option( $this->table );
	}

	protected function after_load(): void {
	}

	protected function before_load(): void {
	}

	/**
	 * Get table name.
	 *
	 * @return string
	 */
	public function get_table(): string {
		return $this->table;
	}
}
