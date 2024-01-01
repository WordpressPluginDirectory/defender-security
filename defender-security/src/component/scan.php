<?php

namespace WP_Defender\Component;

use WP_Defender\Behavior\Scan\Core_Integrity;
use WP_Defender\Behavior\Scan\Gather_Fact;
use WP_Defender\Behavior\Scan\Known_Vulnerability;
use WP_Defender\Behavior\Scan\Malware_Scan;
use WP_Defender\Behavior\Scan\Malware_Quick_Scan;
use WP_Defender\Behavior\Scan\Malware_Deep_Scan;
use WP_Defender\Behavior\Scan\Plugin_Integrity;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Component;
use WP_Defender\Model\Scan_Item;
use WP_Defender\Model\Scan as Model_Scan;
use WP_Defender\Helper\Analytics\Scan as Scan_Analytics;

class Scan extends Component {

	/**
	 * Cache the current scan.
	 *
	 * @var \WP_Defender\Model\Scan
	 */
	public $scan;

	/**
	 * @var \WP_Defender\Model\Setting\Scan
	 */
	public $settings;

	/**
	 * @var array
	 */
	protected $vulnerability_details = [];

	/**
	 * @var Known_Vulnerability
	 */
	private $known_vulnerability;

	/**
	 * @var Malware_Scan
	 */
	private $malware_scan;

	public function __construct() {
		$this->attach_behavior( WPMUDEV::class, WPMUDEV::class );
		$this->attach_behavior( Gather_Fact::class, Gather_Fact::class );
		$this->attach_behavior( Core_Integrity::class, Core_Integrity::class );
		$this->attach_behavior( Plugin_Integrity::class, Plugin_Integrity::class );
	}

	/**
	 * @param object $model
	 */
	public function advanced_scan_actions( $model ) {
		$this->reindex_ignored_issues( $model );
		$this->clean_up();

		if ( wd_di()->get( \WP_Defender\Admin::class )->is_wp_org_version()  ) {
			\WP_Defender\Component\Rate::run_counter_of_completed_scans();
		}
	}

	/**
	 * Process current scan.
	 *
	 * @return bool|int
	 * @throws \ReflectionException
	 */
	public function process() {
		$scan = Model_Scan::get_active();
		if ( ! is_object( $scan ) ) {
			// This case can be a scan get cancel.
			return - 1;
		}
		$this->scan = $scan;
		$this->settings = new \WP_Defender\Model\Setting\Scan();
		$tasks = $this->get_tasks();
		$runner = new \ArrayIterator( $tasks );
		$task = $this->scan->status;
		if ( Model_Scan::STATUS_INIT === $scan->status ) {
			// Get the first.
			$this->log( 'Prepare facts for a scan', 'scan.log' );
			$task = Model_Scan::STEP_GATHER_INFO;
			$this->scan->percent = 0;
			$this->scan->total_tasks = $runner->count();
			$this->scan->save();
		}
		if (
			in_array(
				$this->scan->status,
				[
					Model_Scan::STATUS_ERROR,
					Model_Scan::STATUS_IDLE,
				],
				true
			)
		) {
			// Stop and return true to abort the process.
			return true;
		}
		// Find the current task.
		$offset = array_search( $task, array_values( $tasks ), true );
		if ( false === $offset ) {
			$this->log( sprintf( 'offset is not found, search %s', $task ), 'scan.log' );

			return false;
		}
		// Reset the tasks to current.
		$runner->seek( $offset );
		$this->log( sprintf( 'Current task %s', $runner->current() ), 'scan.log' );
		if ( $this->has_method( $task ) ) {
			$this->log( sprintf( 'processing %s', $runner->key() ), 'scan.log' );
			$result = $this->task_handler( $task );
			if ( true === $result ) {
				$this->log( sprintf( 'task %s processed', $runner->key() ), 'scan.log' );
				// Task is done, move to next.
				$runner->next();
				if ( $runner->valid() ) {
					$this->log( sprintf( 'queue %s for next', $runner->key() ), 'scan.log' );
					$this->scan->status = $runner->key();
					$this->scan->task_checkpoint = '';
					$this->scan->date_end = gmdate( 'Y-m-d H:i:s' );
					$this->scan->save();
					// Queue for next run.
					return false;
				}
				$this->log( 'All done!', 'scan.log' );
				// No more task in the queue, we are done.
				$this->scan->status = Model_Scan::STATUS_FINISH;
				$this->scan->save();
				$this->advanced_scan_actions( $this->scan );
				do_action( 'defender_notify', 'malware-notification', $this->scan );

				return true;
			}
			$this->scan->status = $task;
			$this->scan->save();
		}

		return false;
	}

	/**
	 * @param \WP_Defender\Model\Scan $model
	 */
	private function reindex_ignored_issues( $model ) {
		$issues = $model->get_issues( null, Scan_Item::STATUS_IGNORE );
		$ignore_lists = [];
		foreach ( $issues as $issue ) {
			$data = $issue->raw_data;
			if ( isset( $data['file'] ) ) {
				$ignore_lists[] = $data['file'];
			} elseif ( isset( $data['slug'] ) ) {
				$ignore_lists[] = $data['slug'];
			}
		}
		$model->update_ignore_list( $ignore_lists );
	}

	/**
	 * Get a list of tasks will run in a scan.
	 *
	 * @return array
	 */
	public function get_tasks(): array {
		$tasks = [ Model_Scan::STEP_GATHER_INFO => 'gather_info' ];
		if ( $this->settings->integrity_check ) {
			// Nested options.
			if ( $this->settings->check_core ) {
				$tasks[ Model_Scan::STEP_CHECK_CORE ] = 'core_integrity_check';
			}
			if ( $this->settings->check_plugins ) {
				$tasks[ Model_Scan::STEP_CHECK_PLUGIN ] = 'plugin_integrity_check';
			}
		}
		if ( $this->is_pro() ) {
			if ( $this->settings->check_known_vuln ) {
				if ( $this->has_method( Model_Scan::STEP_VULN_CHECK ) ) {
					$tasks[ Model_Scan::STEP_VULN_CHECK ] = 'vuln_check';
				}
			}
			if ( $this->settings->scan_malware ) {
				if ( $this->has_method( Model_Scan::STEP_SUSPICIOUS_CHECK ) ) {
					$tasks[ Model_Scan::STEP_SUSPICIOUS_CHECK ] = 'suspicious_check';
				}
			}
		}

		return $tasks;
	}

	/**
	 * A simple strategy pattern method to invoke various type of scan method.
	 */
	private function task_handler( $task ) {
		switch ( $task ) {
			case 'vuln_check':
				if ( class_exists( Known_Vulnerability::class ) ) {
					$this->set_known_vulnerability(
						wd_di()->make( Known_Vulnerability::class, [ 'scan' => $this->scan ] )
					);
				}
				return $this->vuln_check( $this->known_vulnerability );

			case 'suspicious_check':
				if ( class_exists( Malware_Scan::class ) ) {
					$this->set_malware_scan(
						wd_di()->make( Malware_Scan::class, [ 'scan' => $this->scan ] )
					);
				}
				return $this->suspicious_check( $this->malware_scan );

			default:
				return $this->$task();
		}
	}

	/**
	 * A wrapper method for Known_Vulnerability class method vuln_check.
	 *
	 * @param Known_Vulnerability $known_vulnerability An instance of Known_Vulnerability.
	 *
	 * @return bool True always as in wrapped method Known_Vulnerability::vuln_check.
	 */
	private function vuln_check( Known_Vulnerability $known_vulnerability ): bool {
		if ( method_exists( $known_vulnerability, 'vuln_check' ) ) {
			return $known_vulnerability->vuln_check();
		}

		return true; // Followed Known_Vulnerability::vuln_check return pattern i.e. always true for skipped vuln check.
	}

	/**
	 * Setter injection method for Known_Vulnerability instance.
	 */
	public function set_known_vulnerability( Known_Vulnerability $known_Vulnerability ) {
		if ( class_exists( Known_Vulnerability::class ) ) {
			$this->known_vulnerability = $known_Vulnerability;
		}
	}

	/**
	 * A wrapper method for Malware_Scan class method vuln_check.
	 *
	 * @param Malware_Scan $malware_scan An instance of Malware_Scan.
	 *
	 * @return bool True if method Malware_Scan::suspicious_check not exists else bool value returned by that method.
	 */
	private function suspicious_check( Malware_Scan $malware_scan ): bool {
		if ( method_exists( $malware_scan, 'suspicious_check' ) ) {
			$quick_scan = wd_di()->get( Malware_Quick_Scan::class );
			$deep_scan = wd_di()->get( Malware_Deep_Scan::class );

			return $malware_scan->suspicious_check( $quick_scan, $deep_scan );
		}

		return true;
	}

	/**
	 * Setter injection method for Malware_Scan instance.
	 */
	public function set_malware_scan( Malware_Scan $malware_scan ) {
		if ( class_exists( Malware_Scan::class ) ) {
			$this->malware_scan = $malware_scan;
		}
	}

	public function cancel_a_scan() {
		$scan = Model_Scan::get_active();
		if ( is_object( $scan ) ) {
			$scan->delete();
		}
		$this->clean_up();
		$this->remove_lock();

		/**
		 * @var Scan_Analytics
		 */
		$scan_analytics = wd_di()->get( Scan_Analytics::class );

		$scan_analytics->track_feature(
			$scan_analytics::EVENT_SCAN_FAILED,
			[
				$scan_analytics::EVENT_SCAN_FAILED_PROP => $scan_analytics::EVENT_SCAN_FAILED_CANCEL,
			]
		);
	}

	/**
	 * Clean up data generate by current scan.
	 */
	public function clean_up() {
		$this->delete_interim_data();

		$models = Model_Scan::get_last_all();
		if ( ! empty( $models ) ) {
			// Remove the latest. Don't remove code to find the first value.
			$current = array_shift( $models );
			foreach ( $models as $model ) {
				$model->delete();
			}
		}
	}

	/**
	 * Create a file lock, so we can check if a process already running.
	 */
	public function create_lock() {
		file_put_contents( $this->get_lock_path(), time(), LOCK_EX );
	}

	/**
	 * Delete file lock.
	 */
	public function remove_lock() {
		@unlink( $this->get_lock_path() );
	}

	/**
	 * Check if a lock is valid.
	 *
	 * @return bool
	 */
	public function has_lock(): bool {
		if ( ! file_exists( $this->get_lock_path() ) ) {
			return false;
		}
		$time = file_get_contents( $this->get_lock_path() );
		if ( strtotime( '+90 seconds', $time ) < time() ) {
			// Usually a timeout window is 30 seconds, so we should allow lock at 1.30min for safe.
			return false;
		}

		return true;
	}

	/**
	 * Get the total scanning active issues.
	 *
	 * @return int $count
	 */
	public function indicator_issue_count(): int {
		$count = 0;
		$scan = Model_Scan::get_last();
		if ( is_object( $scan ) && ! is_wp_error( $scan ) ) {
			// Only Scan issues.
			$count = (int) $scan->count( null, Scan_Item::STATUS_ACTIVE );
		}

		return $count;
	}

	/**
	 * @param array $scan_settings
	 * @param bool  $is_pro
	 *
	 * @return bool
	 */
	public function is_any_scan_active( $scan_settings, $is_pro ): bool {
		if ( empty( $scan_settings['integrity_check'] ) ) {
			// Check the parent type.
			$file_change_check = false;
		} elseif (
			! empty( $scan_settings['integrity_check'] )
			&& empty( $scan_settings['check_core'] )
			&& empty( $scan_settings['check_plugins'] )
		) {
			// Check the parent and child types.
			$file_change_check = false;
		} else {
			$file_change_check = true;
		}
		// Similar to is_any_active(...) method from the controller.
		if ( $is_pro ) {
			// Pro version. Check all parent types.
			return $file_change_check || ! empty( $scan_settings['check_known_vuln'] ) || ! empty( $scan_settings['scan_malware'] );
		} else {
			// Free version. Check the 'File change detection' type because only it's available with nested types.
			return $file_change_check;
		}
	}

	/**
	 * Update the idle scan status.
	 *
	 * @since 2.6.1
	 */
	public function update_idle_scan_status() {
		$idle_scan = wd_di()->get( Model_Scan::class )->get_idle();

		if ( is_object( $idle_scan ) ) {
			$ready_to_send = false;
			if ( Model_Scan::STATUS_IDLE === $idle_scan->status ) {
				$ready_to_send = true;
			}
			$this->delete_interim_data();

			as_unschedule_all_actions( 'defender/async_scan' );

			$idle_scan->status = Model_Scan::STATUS_IDLE;
			$idle_scan->save();

			$this->remove_lock();
			if ( $ready_to_send ) {
				do_action( 'defender_notify', 'malware-notification', $idle_scan );
			}
		}
	}

	/**
	 * Clear all temporary scan data.
	 *
	 * @since 2.6.1
	 */
	private function delete_interim_data() {
		delete_site_option( Gather_Fact::CACHE_CORE );
		delete_site_option( Gather_Fact::CACHE_CONTENT );
		delete_site_option( Malware_Scan::YARA_RULES );
		delete_site_option( Core_Integrity::CACHE_CHECKSUMS );
		delete_site_option( Plugin_Integrity::PLUGIN_SLUGS );
		delete_site_option( Plugin_Integrity::PLUGIN_PREMIUM_SLUGS );
	}

	/**
	 * Display styles on the Plugins page.
	 */
	public function show_plugin_admin_styles() {
		$custom_css = '.vulnerability-indent{ padding-left: 26px; }
		.plugins .plugin-update-tr .plugin-update.plugin-vulnerability{box-shadow: inset 0 0px 0 rgb(0 0 0 / 10%);
		border-bottom: rgb(0 0 0 / 10%) solid 1px;}';
		wp_add_inline_style( 'defender-menu', $custom_css );
	}

	/**
	 * Display update information for a plugin.
	 * @param string $file        Plugin basename.
	 * @param array  $plugin_data Plugin information.
	 *
	 * @return void
	 */
	public function attach_plugin_vulnerability_warning( $file, $plugin_data ) {
		/** @var WP_Plugins_List_Table $wp_list_table */
		$wp_list_table = _get_list_table(
			'WP_Plugins_List_Table',
			[ 'screen' => get_current_screen() ]
		);
		$bugs = $this->vulnerability_details[ $file ]['bugs'];
		if ( empty( $bugs ) ) {
			return;
		}
		$last_fixed_in = '0';
		// Check if there have been updates since the last scan.
		$exist_update = true;
		if ( isset( $plugin_data['Version'] ) && ! empty( $plugin_data['Version'] ) ) {
			// The current plugin version.
			$current_version = $plugin_data['Version'];
			foreach ( $bugs as $bug_details ) {
				// If the fixed version is existed then get the latest one.
				if ( isset( $bug_details['fixed_in'] ) && ! empty( $bug_details['fixed_in'] )
					&& version_compare( $bug_details['fixed_in'], $last_fixed_in, '>' )
				) {
					$last_fixed_in = $bug_details['fixed_in'];
				}
			}
			if ( version_compare( $last_fixed_in, $current_version, '>' ) ) {
				$exist_update = false;
			}
		}
		// If there were updates, do not display notice.
		if ( $exist_update ) {
			return;
		}
		// Sometimes $plugin_data['slug'] is empty.
		if ( empty( $plugin_data['slug'] ) && isset( $this->vulnerability_details[ $file ]['base_slug'] ) ) {
			$plugin_data['slug'] = $this->vulnerability_details[ $file ]['base_slug'];
		}

		if ( is_network_admin() || ! is_multisite() ) {
			if ( is_network_admin() ) {
				$active_class = is_plugin_active_for_network( $file ) ? ' active' : '';
			} else {
				$active_class = is_plugin_active( $file ) ? ' active' : '';
			}

			printf(
				'<tr class="plugin-update-tr%s" id="vulnerability-%s" data-slug="%s" data-plugin="%s">' .
				'<td colspan="%s" class="plugin-update colspanchange plugin-vulnerability">' .
				'<div class="update-message notice inline %s notice-alt"><p>',
				$active_class,
				esc_attr( $plugin_data['slug'] ),
				esc_attr( $plugin_data['slug'] ),
				esc_attr( $file ),
				esc_attr( $wp_list_table->get_column_count() ),
				'notice-error'
			);

			$notice = sprintf(
			/* translators: %s - Plugin name. */
				__( '%s has detected a vulnerability in this plugin that may cause harm to your site.', 'defender-security' ),
				'<b>' . __( 'Defender Pro', 'defender-security' ) . '</b>'
			);
			if ( ( is_array( $bugs ) || $bugs instanceof \Countable ? count( $bugs ) : 0 ) > 1 ) {
				$notice .= '<hr/>';
				$lines = [];
				foreach ( $bugs as $bug ) {
					$lines[] = '<span class="vulnerability-indent"></span>' . $bug['title'];
				}
				$notice .= implode( '<br/>', $lines );
				$notice .= '<hr/><span class="vulnerability-indent"></span>';
				if ( '0' !== $last_fixed_in ) {
					$notice .= sprintf(
					/* translators: %s - Version number. */
						__( 'The vulnerability has been fixed in version %s. We recommend that you update this plugin accordingly.', 'defender-security' ),
						$last_fixed_in
					);
				} else {
					$notice .= __( 'Important! We recommend that you deactivate this plugin until the vulnerability has been fixed.', 'defender-security' );
				}
			} else {
				$notice .= '<br/><span class="vulnerability-indent"></span>' . $bugs[0]['title'] . '<br/><span class="vulnerability-indent"></span>';
				$notice .= empty( $last_fixed_in )
					? __( 'We recommend that you deactivate this plugin until the vulnerability has been fixed.', 'defender-security' )
					: sprintf(
					/* translators: 1: Version number. */
						__( 'The vulnerability has been fixed in version %s. We recommend that you update this plugin accordingly.', 'defender-security' ),
						$last_fixed_in
					);
			}

			printf( $notice );
		}
	}

	/**
	 * Display warnings.
	 * @since 2.6.2
	 */
	public function display_vulnerability_warnings() {
		if ( ! current_user_can( 'update_plugins' ) ) {
			return;
		}

		$last = \WP_Defender\Model\Scan::get_last();
		if ( is_object( $last ) && ! is_wp_error( $last ) ) {
			$vulnerability_issues = $last->get_issues( Scan_Item::TYPE_VULNERABILITY );
			if ( empty( $vulnerability_issues ) ) {
				return;
			}

			add_action( 'admin_print_styles-plugins.php', [ $this, 'show_plugin_admin_styles' ] );
			// Vulnerability list.
			foreach ( $vulnerability_issues as $vulnerability_obj ) {
				$plugin_slug = $vulnerability_obj->raw_data['slug'];
				// Get the details so that you can apply them later for each plugin.
				$this->vulnerability_details[ $plugin_slug ] = $vulnerability_obj->raw_data;
				add_action(
					"after_plugin_row_$plugin_slug",
					[
						$this,
						'attach_plugin_vulnerability_warning',
					],
					100,
					2
				);
			}
		}
	}

	/**
	 * Clear completed action scheduler logs.
	 *
	 * @since 2.6.5
	 */
	public static function clear_logs() {
		global $wpdb;

		$table_actions = ! empty( $wpdb->actionscheduler_actions ) ?
			$wpdb->actionscheduler_actions :
			$wpdb->prefix . 'actionscheduler_actions';
		$table_logs = ! empty( $wpdb->actionscheduler_logs ) ?
			$wpdb->actionscheduler_logs :
			$wpdb->prefix . 'actionscheduler_logs';

		$table_count = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT count(*)
				 FROM information_schema.tables
				 WHERE table_schema = %s AND table_name IN (%s, %s);",
				$wpdb->dbname,
				$table_actions,
				$table_logs
			)
		);

		if ( 2 !== $table_count ) {
			return [ 'error' => __( 'Action scheduler is not setup', 'defender-security' ) ];
		}

		$hook = 'defender/async_scan';
		$status = 'complete';
		$limit = 100;
		while ( $action_ids = $wpdb->get_col( $wpdb->prepare( "SELECT action_id FROM {$table_actions} as_actions WHERE as_actions.hook = %s AND as_actions.status = %s LIMIT %d", $hook, $status, $limit ) ) ) {
			if ( empty( $action_ids ) ) {
				break;
			}

			$where_in = implode( ', ', array_fill( 0, is_array( $action_ids ) || $action_ids instanceof \Countable ? count( $action_ids ) : 0, '%s' ) );
			$wpdb->query(
				$wpdb->prepare(
					"DELETE as_actions, as_logs
					 FROM {$table_actions} as_actions
					 LEFT JOIN {$table_logs} as_logs
						ON as_actions.action_id = as_logs.action_id
					 WHERE as_actions.action_id IN ( {$where_in} )",
					$action_ids
				)
			);
		}

		return [ 'success' => __( 'Malware scan logs are cleared', 'defender-security' ) ];
	}
}
