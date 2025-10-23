<?php
/**
 * Network Cron Manager for WP Defender.
 *
 * This file contains the Network_Cron_Manager class which manages
 * centralized cron jobs across a multisite network with locking.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use WP_Defender\Component;

/**
 * Network Cron Manager class.
 *
 * Provides centralized cron management with locking and multisite execution control.
 */
class Network_Cron_Manager extends Component {
	/**
	 * Log file name constant.
	 *
	 * @var string
	 */
	public const LOG_FILE_NAME = 'network-cron-manager';

	/**
	 * Array of registered callbacks.
	 *
	 * @var array
	 */
	private $callbacks = array();

	/**
	 * Prefix for lock keys.
	 *
	 * @var string
	 */
	private $lock_prefix = 'wpdef_cron_manager_lock_';

	/**
	 * Prefix for last run timestamp keys.
	 *
	 * @var string
	 */
	private $lastrun_prefix = 'wpdef_cron_manager_lastrun_';

	/**
	 * Option name for storing callbacks.
	 *
	 * @var string
	 */
	private $callbacks_option = 'wpdef_cron_manager_callbacks';

	/**
	 * Constructor.
	 *
	 * Initializes the cron manager and hooks into WordPress.
	 */
	public function __construct() {
		add_action( 'shutdown', array( $this, 'check_and_execute_callbacks' ), PHP_INT_MAX );
	}

	/**
	 * Load callbacks from network options.
	 */
	private function load_callbacks() {
		$this->callbacks = get_network_option( get_main_network_id(), $this->callbacks_option, array() );
	}

	/**
	 * Save callbacks to network options.
	 */
	private function save_callbacks() {
		update_network_option( get_main_network_id(), $this->callbacks_option, $this->callbacks );
	}

	/**
	 * Register a callback for cron execution.
	 *
	 * Automatically handles both multisite and single-site setups:
	 * - For multisite: Uses Network Cron Manager execution with start_time support
	 * - For single-site: Uses WordPress native cron with proper scheduling
	 *
	 * @param string          $hook_name The hook name.
	 * @param callable        $callback The callback function.
	 * @param int             $interval_seconds The interval in seconds.
	 * @param int|string|null $start_time When to start: timestamp, 'next Thursday', etc. Defaults to defender_get_current_time().
	 * @param array           $args Arguments for the callback.
	 *
	 * @return bool|void False on validation failure, void on success.
	 */
	public function register_callback( string $hook_name, callable $callback, int $interval_seconds, $start_time = null, array $args = array() ) {
		$hook_name = sanitize_key( $hook_name );
		if ( empty( $hook_name ) || ! is_string( $hook_name ) ) {
			$this->log( 'Task registration failed: Invalid task name provided', self::LOG_FILE_NAME );
			return false;
		}
		if ( ! is_callable( $callback ) ) {
			$this->log( "Task registration failed: Task '{$hook_name}' function cannot be called", self::LOG_FILE_NAME );
			return false;
		}
		if ( ! is_numeric( $interval_seconds ) || $interval_seconds < 1 ) {
			$this->log( "Task registration failed: Task '{$hook_name}' has invalid run interval ({$interval_seconds} seconds)", self::LOG_FILE_NAME );
			return false;
		}

		if ( is_multisite() ) {
			if ( wp_next_scheduled( $hook_name ) ) {
				wp_clear_scheduled_hook( $hook_name );
				$this->log( "Cleared existing WordPress cron event for '{$hook_name}' to prevent conflicts", self::LOG_FILE_NAME );
			}

			$this->callbacks[ $hook_name ] = array(
				'callback'   => $callback,
				'interval'   => $interval_seconds,
				'start_time' => $start_time,
				'args'       => $args,
			);
			$this->save_callbacks();
		} else {
			if ( ! wp_next_scheduled( $hook_name ) ) {
				$start_timestamp = $this->calculate_start_time( $start_time );
				$schedule        = $this->get_schedule_name( $interval_seconds );
				wp_schedule_event( $start_timestamp, $schedule, $hook_name );
			}
			add_action( $hook_name, $callback );
		}
	}

	/**
	 * Calculate the start time for a cron event.
	 *
	 * @param int|string|null $start_time The start time specification.
	 *
	 * @return int The timestamp when the cron should first run.
	 */
	private function calculate_start_time( $start_time = null ) {
		if ( null === $start_time ) {
			return defender_get_current_time();
		}

		if ( is_numeric( $start_time ) ) {
			return (int) $start_time;
		}

		if ( is_string( $start_time ) ) {
			$timestamp = strtotime( $start_time );

			return false !== $timestamp ? $timestamp : defender_get_current_time();
		}

		return defender_get_current_time();
	}

	/**
	 * Get WordPress cron schedule name from interval seconds.
	 *
	 * @param int $interval_seconds The interval in seconds.
	 *
	 * @return string The schedule name.
	 */
	private function get_schedule_name( $interval_seconds ) {
		$schedules = wp_get_schedules();

		foreach ( $schedules as $schedule_name => $schedule_data ) {
			if ( isset( $schedule_data['interval'] ) && $schedule_data['interval'] === $interval_seconds ) {
				return $schedule_name;
			}
		}

		switch ( $interval_seconds ) {
			case 12 * HOUR_IN_SECONDS:
				return 'twicedaily';
			case DAY_IN_SECONDS:
				return 'daily';
			case WEEK_IN_SECONDS:
				return 'weekly';
			case HOUR_IN_SECONDS:
			default:
				return 'hourly';
		}
	}

	/**
	 * Check and execute registered callbacks.
	 */
	public function check_and_execute_callbacks() {
		$this->load_callbacks();
		if ( empty( $this->callbacks ) ) {
			return;
		}
		foreach ( $this->callbacks as $hook_name => $config ) {
			$this->execute_callback( $hook_name, $config );
		}
	}

	/**
	 * Execute a specific callback.
	 *
	 * @param string $hook_name The hook name.
	 * @param array  $config    The callback configuration.
	 */
	private function execute_callback( $hook_name, $config ) {
		if ( ! $this->should_execute( $hook_name, $config ) ) {
			return;
		}
		if ( ! $this->acquire_lock( $hook_name ) ) {
			return;
		}
		$start_time = defender_get_current_time();
		try {
			if ( is_callable( $config['callback'] ) ) {
				call_user_func_array( $config['callback'], $config['args'] );
				$this->update_last_run( $hook_name );
			}
		} catch ( \Exception $exception ) {
			$this->log( "Task '{$hook_name}' failed to run: " . $exception->getMessage(), self::LOG_FILE_NAME );
		} finally {
			$this->release_lock( $hook_name );
		}
	}

	/**
	 * Check if a callback should be executed based on interval and start_time.
	 *
	 * @param string $hook_name The hook name.
	 * @param array  $config The callback configuration.
	 *
	 * @return bool Whether the callback should execute.
	 */
	private function should_execute( $hook_name, $config ) {
		$interval = $config['interval'];

		/**
		 * Filter to modify execution intervals for network cron jobs.
		 *
		 * @param int    $interval  The interval in seconds.
		 * @param string $hook_name The hook name being executed.
		 */
		$interval     = (int) apply_filters( 'wpdef_network_cron_interval', $interval, $hook_name );
		$last_run     = $this->get_last_run( $hook_name );
		$current_time = defender_get_current_time();

		if ( ! $last_run && isset( $config['start_time'] ) && null !== $config['start_time'] ) {
			$start_timestamp = $this->calculate_start_time( $config['start_time'] );
			if ( $current_time < $start_timestamp ) {
				return false;
			}
		}

		if ( $last_run ) {
			$time_diff = $current_time - $last_run;
			if ( $time_diff < $interval ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Acquire a lock for a specific hook.
	 *
	 * @param string $hook_name The hook name.
	 * @return bool Whether the lock was acquired.
	 */
	private function acquire_lock( $hook_name ) {
		/**
		 * Filter to modify lock timeout for network cron jobs.
		 *
		 * @param int    $timeout   The timeout in seconds.
		 * @param string $hook_name The hook name being locked.
		 */
		$lock_timeout  = (int) apply_filters( 'wpdef_network_cron_lock_timeout', 300, $hook_name );
		$lock_key      = $this->lock_prefix . $hook_name;
		$existing_lock = get_network_option( get_main_network_id(), $lock_key );
		if ( $existing_lock && ( defender_get_current_time() - $existing_lock ) < $lock_timeout ) {
			return false;
		}
		$lock_value = defender_get_current_time();
		return update_network_option( get_main_network_id(), $lock_key, $lock_value );
	}

	/**
	 * Release a lock for a specific hook.
	 *
	 * @param string $hook_name The hook name.
	 */
	private function release_lock( $hook_name ) {
		$lock_key = $this->lock_prefix . $hook_name;
		delete_network_option( get_main_network_id(), $lock_key );
	}

	/**
	 * Get the last run timestamp for a hook.
	 *
	 * @param string $hook_name The hook name.
	 * @return int The last run timestamp.
	 */
	private function get_last_run( $hook_name ) {
		$lastrun_key = $this->lastrun_prefix . $hook_name;
		return get_network_option( get_main_network_id(), $lastrun_key, 0 );
	}

	/**
	 * Update the last run timestamp for a hook.
	 *
	 * @param string $hook_name The hook name.
	 */
	private function update_last_run( $hook_name ) {
		$lastrun_key = $this->lastrun_prefix . $hook_name;
		$timestamp   = defender_get_current_time();
		update_network_option( get_main_network_id(), $lastrun_key, $timestamp );
	}

	/**
	 * Get all registered callbacks.
	 *
	 * @return array The registered callbacks.
	 */
	public function get_callbacks() {
		return $this->callbacks;
	}

	/**
	 * Remove all Network Cron Manager data during uninstallation.
	 */
	public function remove_data() {
		if ( ! is_multisite() ) {
			return;
		}

		$network_id = get_main_network_id();

		delete_network_option( $network_id, $this->callbacks_option );

		global $wpdb;
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->prepare(
				"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s OR meta_key LIKE %s",
				$this->lock_prefix . '%',
				$this->lastrun_prefix . '%'
			)
		);
	}
}
