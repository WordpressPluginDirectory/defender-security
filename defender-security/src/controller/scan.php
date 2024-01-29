<?php

namespace WP_Defender\Controller;

use Calotes\Component\Request;
use Calotes\Component\Response;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Component\Config\Config_Hub_Helper;
use WP_Defender\Event;
use WP_Defender\Model\Notification\Malware_Report;
use Valitron\Validator;
use WP_Defender\Model\Scan as Model_Scan;
use WP_Defender\Traits\Formats;
use WP_Defender\Controller\Quarantine;
use WP_Defender\Component\Quarantine as Quarantine_Component;
use WP_Defender\Helper\Analytics\Scan as Scan_Analytics;
use WP_Defender\Model\Scan_Item;
use WP_Defender\Component\Rate;

class Scan extends Event {
	use Formats;

	protected $slug = 'wdf-scan';

	/**
	 * @var \WP_Defender\Model\Setting\Scan
	 */
	protected $model;

	/**
	 * @var \WP_Defender\Component\Scan
	 */
	protected $service;

	/**
	 * @var \WP_Defender\Controller\Quarantine
	 */
	private $quarantine_controller;

	/**
	 * Scan constructor.
	 */
	public function __construct() {
		$this->register_page(
			esc_html__( 'Malware Scanning', 'defender-security' ),
			$this->slug,
			[
				&$this,
				'main_view',
			],
			$this->parent_slug
		);

		$this->model = new \WP_Defender\Model\Setting\Scan();
		$this->service = wd_di()->get( \WP_Defender\Component\Scan::class );

		if ( class_exists( 'WP_Defender\Controller\Quarantine' ) ) {
			$this->quarantine_controller = wd_di()->get( Quarantine::class );
		}

		$this->register_routes();
		add_action( 'defender_enqueue_assets', [ &$this, 'enqueue_assets' ] );
		add_action( 'wp_ajax_defender_process_scan', [ &$this, 'process' ] );
		add_action( 'wp_ajax_nopriv_defender_process_scan', [ &$this, 'process' ] );
		add_action( 'defender/async_scan', [ &$this, 'process' ] );
		// Clean up data after successful core update.
		add_action( '_core_updated_successfully', [ &$this, 'clean_up_data' ] );

		global $pagenow;
		// @since 2.6.2.
		if (
			is_admin() &&
			'plugins.php' === $pagenow &&
			apply_filters( 'wd_display_vulnerability_warnings', true )
		) {
			$this->service->display_vulnerability_warnings();
		}

		// Schedule a time to clear completed action scheduler logs.
		if ( ! wp_next_scheduled( 'wpdef_clear_scan_logs' ) ) {
			wp_schedule_event( time(), 'weekly', 'wpdef_clear_scan_logs' );
		}
		add_action( 'wpdef_clear_scan_logs', [ $this, 'clear_scan_logs' ] );

		add_filter( 'heartbeat_nopriv_send', [ $this, 'nopriv_heartbeat' ], 10, 2 );

		add_action(
			'action_scheduler_completed_action',
			[ $this, 'scan_completed_analytics' ]
		);
	}

	/**
	 * Clean up data after core updating.
	 *
	 * @return void
	 */
	public function clean_up_data(): void {
		$this->service->clean_up();
	}

	/**
	 * Start a scan.
	 *
	 * @param Request $request
	 *
	 * @return Response
	 * @throws \Exception
	 * @defender_route
	 * @defender_redirect
	 */
	public function start( Request $request ): Response {
		$model = Model_Scan::create();
		if ( is_object( $model ) && ! is_wp_error( $model ) ) {
			$this->log( 'Initial ping self', 'scan.log' );

			$this->scan_started_analytics(
				[
					'Triggered From' => 'Plugin',
					'Scan Type' => 'Manual',
				]
			);

			$this->do_async_scan( 'scan' );

			return new Response(
				true,
				[
					'status' => $model->status,
					'status_text' => $model->get_status_text(),
					'percent' => 0,
				]
			);
		}

		return new Response(
			false,
			[
				'message' => __( 'A scan is already in progress', 'defender-security' ),
			]
		);
	}

	/**
	 * Use this for self ping, so it can both run in background and active mode with good performance.
	 *
	 * @return void
	 * @throws \ReflectionException
	 * @defender_route
	 * @is_public
	 */
	public function process() {
		if ( $this->service->has_lock() ) {
			$this->log( 'Fallback as already a process is running', 'scan.log' );

			return;
		}

		// This creates file lock, for make sure only 1 process run as a time.
		$this->service->create_lock();
		// Check if the ping is from self or not.
		$ret = $this->service->process();
		$this->log( 'process done, queue for next', 'scan.log' );
		if ( false === $ret ) {
			// Ping self.
			$this->log( 'Scan not done, pinging', 'scan.log' );
			$this->service->remove_lock();
			$this->process();
		} else {
			$this->queue_to_sync_with_hub();
			$this->service->remove_lock();
		}
	}

	/**
	 * Query status.
	 *
	 * @return Response
	 * @defender_route
	 * @defender_redirect
	 */
	public function status(): Response {
		$idle_scan = wd_di()->get( Model_Scan::class )->get_idle();

		if ( is_object( $idle_scan ) ) {
			$this->service->update_idle_scan_status();

			return new Response( false, $idle_scan->to_array() );
		}

		$scan = Model_Scan::get_active();
		if ( is_object( $scan ) ) {

			return new Response( false, $scan->to_array() );
		}
		$scan = Model_Scan::get_last();
		if ( is_object( $scan ) && ! is_wp_error( $scan ) ) {

			return new Response( true, $scan->to_array() );
		}

		return new Response(
			false,
			[
				'message' => __( 'Error during scanning', 'defender-security' ),
			]
		);
	}

	/**
	 * Cancel current scan.
	 *
	 * @return Response
	 * @defender_route
	 * @defender_redirect
	 */
	public function cancel(): Response {
		/**
		 * @var \WP_Defender\Component\Scan
		 */
		$component = wd_di()->get( \WP_Defender\Component\Scan::class );
		$component->cancel_a_scan();
		$last = Model_Scan::get_last();
		if ( is_object( $last ) && ! is_wp_error( $last ) ) {
			$last = $last->to_array();
		}

		return new Response(
			true,
			[
				'scan' => $last,
			]
		);
	}

	/**
	 * Track scan item action analytics.
	 *
	 * @param Scan_Item $scan_item Individual item of scan issues list.
	 * @param string $intention What action is going to be executed.
	 */
	private function item_action_analytics( Scan_Item $scan_item, string $intention ) {
		$allowed_intentions = [
			'resolve',
			'ignore',
			'delete',
			'unignore',
			'quarantine',
		];

		$event_name = 'def_threat_resolved';

		if ( in_array( $intention, $allowed_intentions ) ) {
			$intention_desc = [
				'resolve' => 'Safe Repair',
				'ignore' => 'Ignore',
				'delete' => 'Delete',
				'unignore' => 'Unignore',
				'quarantine' => 'Safe Repair & Quarantine',
			];

			$resolution_method = $intention_desc[ $intention ];
			$threat_type = '';

			if ( Scan_Item::TYPE_INTEGRITY === $scan_item->type ) {
				$threat_type = 'Unknown file in WordPress core';
			} elseif ( Scan_Item::TYPE_PLUGIN_CHECK === $scan_item->type ) {
				$raw_data = $scan_item->raw_data;

				if ( isset( $raw_data['type'] ) && 'modified' === $raw_data['type'] ) {
					$threat_type = 'plugin file modified';
				}
			} elseif ( Scan_Item::TYPE_VULNERABILITY === $scan_item->type ) {
				$threat_type = 'Vulnerability';

				if ( 'resolve' === $intention ) {
					$resolution_method = 'Update';
				}
			} elseif ( Scan_Item::TYPE_SUSPICIOUS === $scan_item->type ) {
				$threat_type = 'Suspicious function';
			}

			$this->track_feature(
				$event_name,
				[
					'Resolution Method' => $resolution_method,
					'Threat type' => $threat_type,
				]
			);
		}
	}

	/**
	 * A central controller to pass any request from frontend to scan item.
	 *
	 * @param Request $request
	 *
	 * @return Response
	 * @defender_route
	 */
	public function item_action( Request $request ): Response {
		$data = $request->get_data(
			[
				'id' => [
					'type' => 'int',
					'sanitize' => 'sanitize_text_field',
				],
				'intention' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
				'parent_action' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				]
			]
		);
		$id = $data['id'] ?? false;
		$intention = $data['intention'] ?? false;
		if ( false === $id || false === $intention || ! in_array(
			$intention,
			[
				'pull_src',
				'resolve',
				'ignore',
				'delete',
				'unignore',
				'quarantine',
			]
		) ) {
			wp_die();
		}

		$result = [];

		$scan = Model_Scan::get_last();

		if ( $scan instanceof Model_Scan ) {

			$item = $scan->get_issue( $id );
			if ( is_object( $item ) && $item->has_method( $intention ) ) {

				if ( $intention === 'quarantine' ) {
					$result = $item->$intention( $data['parent_action'] );
				} else {
					$result = $item->$intention();
				}

				$this->item_action_analytics( $item, $intention );

				if ( is_wp_error( $result ) ) {
					return new Response(
						false,
						[
							'message' => $result->get_error_message(),
						]
					);
				} elseif ( isset( $result['type_notice'] ) ) {
					return new Response(
						true,
						$result
					);
				} elseif ( isset( $result['url'] ) ) {
					// Without message and interval args.
					return new Response(
						true,
						[ 'redirect' => $result['url'] ]
					);
				}

				$this->queue_to_sync_with_hub();

				// Refresh scan instance.
				$scan = Model_Scan::get_last();

				if ( $scan instanceof Model_Scan ) {
					$result['scan'] = $scan->to_array();

					$success = true;
					if ( isset( $result['success'] ) && $result['success'] === false ) {
						$success = false;
					}

					return new Response( $success, $result );
				}
			}
		}

		return new Response( false, [] );
	}

	/**
	 * Process for bulk action.
	 * There is no Update-intention because it is a lengthy process. There may not be enough execution time.
	 *
	 * @param Request $request
	 *
	 * @defender_route
	 * @return Response
	 */
	public function bulk_action( Request $request ): Response {
		$data = $request->get_data(
			[
				'items' => [
					'type' => 'array',
					'sanitize' => 'sanitize_text_field',
				],
				'bulk' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
			]
		);
		$items = $data['items'] ?? [];
		$intention = $data['bulk'] ?? false;

		if (
			empty( $items )
			|| ! is_array( $items )
			|| false === $intention
			|| ! in_array( $intention, [ 'ignore', 'unignore', 'delete' ], true )
		) {
			return new Response( false, [] );
		}
		// Try to get Scan.
		$scan = Model_Scan::get_last();
		if ( ! is_object( $scan ) ) {
			return new Response( false, [] );
		}

		$is_delete = false;
		$delete_items = [];
		foreach ( $items as $id ) {
			if ( 'ignore' === $intention ) {
				$scan->ignore_issue( (int) $id );
			} elseif ( 'unignore' === $intention ) {
				$scan->unignore_issue( (int) $id );
			} elseif ( 'delete' === $intention ) {
				$item = $scan->get_issue( (int) $id );
				// Work with every item.
				if ( is_object( $item ) && $item->has_method( $intention ) ) {
					$item_result = $item->delete();
					if ( is_wp_error( $item_result ) ) {
						return new Response( false, [ 'message' => $item_result->get_error_message() ] );
					} elseif ( isset( $item_result['type_notice'] ) ) {
						return new Response( true, $item_result );
					} elseif ( isset( $item_result['collect_type'] ) ) {
						$is_delete = true;
						$delete_items[] = $item_result['message'];
					}
				} else {
					return new Response( false, [] );
				}
			}
		}

		$this->queue_to_sync_with_hub();

		$result = [];
		if ( $is_delete ) {
			$result['message'] = sprintf(
			/* translators: %s: Vulnerability item(es) */
				__( '%s has (have) been deleted', 'defender-security' ),
				implode( ', ', $delete_items )
			);
		}
		// Refresh scan instance.
		$scan = Model_Scan::get_last();
		$result['scan'] = $scan->to_array();

		return new Response( true, $result );
	}

	/**
	 * Endpoint for saving data.
	 * @since 2.7.0 Add Scheduled Scanning to Malware settings and hide it on Malware Scanning - Reporting.
	 * Also, the backward compatibility of settings for Scan and Malware_Report models.
	 *
	 * @param Request $request
	 *
	 * @defender_route
	 * @return Response
	 */
	public function save_settings( Request $request ): Response {
		$data = $request->get_data_by_model( $this->model );
		// Case#1: enable all child options, if parent and all child options are disabled, so that there is no notice when saving.
		if (
			! $data['integrity_check']
			&& ! $data['check_core']
			&& ! $data['check_plugins']
		) {
			$data['check_core'] = true;
			$data['check_plugins'] = true;
		}

		// Case#2: Suspicious code is activated BUT File change detection is deactivated then show the notice.
		if ( $data['scan_malware'] && ! $data['integrity_check'] ) {
			$response = [
				'type_notice' => 'info',
				'message' => __( 'To reduce false-positive results, we recommend enabling' .
					' <strong>File change detection</strong> options for all scan types while the' .
					' <strong>Suspicious code</strong> option is enabled.', 'defender-security' ),
			];
		} else {
			// Prepare response message for usual successful case.
			$response = [
				'message' => __( 'Your settings have been updated.', 'defender-security' ),
				'auto_close' => true,
			];
		}
		// Additional cases are in the Scan model.
		$report_change = false;
		// If 'Scheduled Scanning' is checked then need to change Malware_Report.
		if ( true === $data['scheduled_scanning'] ) {
			$report = new Malware_Report();
			$report_change = true;
			$report->frequency = $data['frequency'];
			$report->day = $data['day'];
			$report->day_n = $data['day_n'];
			$report->time = $data['time'];
			// Disable 'Scheduled Scanning'.
		} elseif ( true === $this->model->scheduled_scanning && false === $data['scheduled_scanning'] ) {
			$report = new Malware_Report();
			$report_change = true;
			$report->status = \WP_Defender\Model\Notification::STATUS_DISABLED;
		}

		$before_import_schedule = $this->model->quarantine_expire_schedule;

		$this->model->import( $data );
		if ( $this->model->validate() ) {

			if ( class_exists( 'WP_Defender\Component\Quarantine' ) ) {
				/**
				 * @var Quarantine_Component
				 */
				$quarantine_component = wd_di()->get( Quarantine_Component::class );
				$quarantine_component->reschedule_file_expiry_cron(
					$before_import_schedule,
					$data['quarantine_expire_schedule']
				);
			}

			// Todo: need to disable Malware_Notification & Malware_Report if all scan settings are deactivated?
			$this->model->save();
			// Save Report's changes.
			if ( $report_change ) {
				$report->save();
			}
			Config_Hub_Helper::set_clear_active_flag();

			return new Response(
				true,
				array_merge( $response, $this->data_frontend() )
			);
		} else {
			return new Response(
				false,
				array_merge(
					[
						'message' => $this->model->get_formatted_errors(),
					],
					$this->data_frontend()
				)
			);
		}
	}

	/**
	 * Get the issues mainly for pagination request.
	 *
	 * @param Request $request
	 *
	 * @return Response
	 * @defender_route
	 */
	public function get_issues( Request $request ): Response {
		$data = $request->get_data(
			[
				'scenario' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
				'type' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
				'per_page' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
				'paged' => [
					'type' => 'int',
					'sanitize' => 'sanitize_text_field',
				],
			]
		);

		// Validate the request.
		$v = new Validator( $data, [] );
		$v->rule( 'required', [ 'scenario', 'type', 'per_page', 'paged' ] );
		if ( ! $v->validate() ) {
			return new Response(
				false,
				[
					'message' => '',
				]
			);
		}

		$scan = Model_Scan::get_last();
		$issues = $scan->to_array( $data['per_page'], $data['paged'], $data['type'] );

		return new Response(
			true,
			[
				'issue' => $issues['issues_items'],
				'ignored' => $issues['ignored_items'],
				'paging' => $issues['paging'],
				'count' => $issues['count'],
			]
		);
	}

	/**
	 * @param Request $request
	 *
	 * @defender_route
	 * @return Response
	 */
	public function handle_notice( Request $request ): Response {
		update_site_option( Rate::SLUG_FOR_BUTTON_RATE, true );

		return new Response( true, [] );
	}

	/**
	 * @param Request $request
	 *
	 * @defender_route
	 * @return Response
	 */
	public function postpone_notice( Request $request ): Response {
		Rate::reset_counters();

		return new Response( true, [] );
	}

	/**
	 * @param Request $request
	 *
	 * @defender_route
	 * @return Response
	 */
	public function refuse_notice( Request $request ): Response {
		update_site_option( Rate::SLUG_FOR_BUTTON_THANKS, true );

		return new Response( true, [] );
	}

	/**
	 * Render main page.
	 *
	 * @return void
	 */
	public function main_view(): void {
		$this->render( 'main' );
	}

	/**
	 * Enqueue assets.
	 *
	 * @return void
	 */
	public function enqueue_assets() {
		if ( ! $this->is_page_active() ) {
			return;
		}
		wp_localize_script( 'def-scan', 'scan', $this->data_frontend() );
		wp_enqueue_script( 'def-scan' );
		wp_enqueue_script( 'clipboard' );
		$this->enqueue_main_assets();
		wp_enqueue_script( 'def-codemirror', defender_asset_url( '/assets/js/vendor/codemirror/codemirror.js' ) );
		wp_enqueue_script( 'def-codemirror-xml', defender_asset_url( '/assets/js/vendor/codemirror/xml/xml.js' ) );
		wp_enqueue_script(
			'def-codemirror-clike',
			defender_asset_url( '/assets/js/vendor/codemirror/clike/clike.js' )
		);
		wp_enqueue_script( 'def-codemirror-css', defender_asset_url( '/assets/js/vendor/codemirror/css/css.js' ) );
		wp_enqueue_script(
			'def-codemirror-javascript',
			defender_asset_url( '/assets/js/vendor/codemirror/javascript/javascript.js' )
		);
		wp_enqueue_script(
			'def-codemirror-htmlmixed',
			defender_asset_url( '/assets/js/vendor/codemirror/htmlmixed/htmlmixed.js' )
		);
		wp_enqueue_script( 'def-codemirror-php', defender_asset_url( '/assets/js/vendor/codemirror/php/php.js' ) );
		wp_enqueue_script(
			'def-codemirror-merge',
			defender_asset_url( '/assets/js/vendor/codemirror/merge/merge.js' )
		);
		wp_enqueue_script( 'def-diff-match-patch', defender_asset_url( '/assets/js/vendor/diff-match-patch.js' ) );
		wp_enqueue_script(
			'def-codemirror-annotatescrollbar',
			defender_asset_url( '/assets/js/vendor/codemirror/scroll/annotatescrollbar.js' )
		);
		wp_enqueue_script(
			'def-codemirror-simplescrollbars',
			defender_asset_url( '/assets/js/vendor/codemirror/scroll/simplescrollbars.js' )
		);
		wp_enqueue_script(
			'def-codemirror-searchcursor',
			defender_asset_url( '/assets/js/vendor/codemirror/search/searchcursor.js' )
		);
		wp_enqueue_script(
			'def-codemirror-matchonscrollbars',
			defender_asset_url( '/assets/js/vendor/codemirror/search/matchesonscrollbar.js' )
		);

		wp_enqueue_style( 'def-codemirror', defender_asset_url( '/assets/js/vendor/codemirror/codemirror.css' ) );
		wp_enqueue_style( 'def-codemirror-dracula', defender_asset_url( '/assets/js/vendor/codemirror/dracula.css' ) );
		wp_enqueue_style(
			'def-codemirror-merge',
			defender_asset_url( '/assets/js/vendor/codemirror/merge/merge.css' )
		);
		wp_enqueue_style(
			'def-codemirror-matchonscrollbars',
			defender_asset_url( '/assets/js/vendor/codemirror/search/matchesonscrollbar.css' )
		);
		wp_enqueue_style(
			'def-codemirror-simplescrollbars',
			defender_asset_url( '/assets/js/vendor/codemirror/scroll/simplescrollbars.css' )
		);
	}

	/**
	 * @return array
	 */
	public function to_array(): array {
		$scan = Model_Scan::get_active();
		$last = Model_Scan::get_last();
		if ( ! is_object( $scan ) && ! is_object( $last ) ) {
			$scan = null;
		} else {
			$scan = is_object( $scan ) ? $scan->to_array() : $last->to_array();
		}

		return array_merge(
			[
				'scan' => $scan,
				'report' => [
					'enabled' => true,
					'frequency' => 'weekly',
				],
			],
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * @return void
	 */
	public function remove_settings(): void {
		( new \WP_Defender\Model\Setting\Scan() )->delete();
	}

	/**
	 * @return void
	 */
	public function remove_data(): void {
		delete_site_option( Model_Scan::IGNORE_INDEXER );
	}

	/**
	 * @return array
	 */
	public function data_frontend(): array {
		$scan = Model_Scan::get_active();
		$last = Model_Scan::get_last();
		$per_page = 10;
		$paged = 1;
		if ( ! is_object( $scan ) && ! is_object( $last ) ) {
			$scan = null;
		} else {
			$scan = is_object( $scan ) ? $scan->to_array( $per_page, $paged ) : $last->to_array( $per_page, $paged );
		}
		$settings = new \WP_Defender\Model\Setting\Scan();
		$report = wd_di()->get( Malware_Report::class );
		$report_text = __( 'Automatic scans are disabled', 'defender-security' );
		if ( $settings->scheduled_scanning && isset( $settings->frequency ) ) {
			$report_text = sprintf(
			/* translators: 1. Line break tag. 2. Frequency value. */
				__( 'Automatic scans are %1$srunning %2$s', 'defender-security' ),
				'<br/>',
				$settings->frequency
			);
		}
		// Prepare additional data.
		if ( wd_di()->get( \WP_Defender\Admin::class )->is_wp_org_version() ) {
			$scan_array = Rate::what_scan_notice_display();
			$misc = [
				'rating_is_displayed' => ! Rate::was_rate_request() && ! empty( $scan_array['text'] ),
				'rating_text' => $scan_array['text'],
				'rating_type' => $scan_array['slug'],
			];
		} else {
			$misc = [
				'days_of_week' => $this->get_days_of_week(),
				'times_of_day' => $this->get_times(),
				'timezone_text' => sprintf(
				/* translators: %s - timezone, %s - time */
					__( 'Your timezone is set to %1$s, so your current time is %2$s.', 'defender-security' ),
					'<strong>' . wp_timezone_string() . '</strong>',
					'<strong>' . date( 'H:i', current_time( 'timestamp' ) ) . '</strong>'// phpcs:ignore
				),
				'show_notice' => ! $settings->scheduled_scanning
								&& isset( $_GET['enable'] ) && 'scheduled_scanning' === $_GET['enable'],
				'rating_is_displayed' => false,
				'rating_text' => '',
				'rating_type' => '',
			];
		}

		// Todo: add logic for deactivated scan settings. Maybe display some notice.
		$data = [
			'scan' => $scan,
			'settings' => $settings->export(),
			'report' => $report_text,
			'active_tools' => [
				'integrity_check' => $settings->integrity_check,
				'check_known_vuln' => $settings->check_known_vuln,
				'scan_malware' => $settings->scan_malware,
				'scheduled_scanning' => $settings->scheduled_scanning,
			],
			'notification' => $report->to_string(),
			'next_run' => $report->get_next_run_as_string(),
			'misc' => $misc,
		];

		if ( class_exists( 'WP_Defender\Controller\Quarantine' ) ) {
			$data['quarantine'] = $this->quarantine_controller->data_frontend();
		}

		return array_merge( $data, $this->dump_routes_and_nonces() );
	}

	/**
	 * @param array $data
	 *
	 * @return void
	 */
	public function import_data( $data ): void {
		$model = $this->model;
		if ( empty( $data ) ) {
			$model->scheduled_scanning = false;
			$model->frequency = 'weekly';
			$model->day_n = '1';
			$model->day = 'sunday';
			$model->time = '4:00';
			$model->save();
		} else {
			$model->import( $data );
			if ( $model->validate() ) {
				$model->save();
			}
		}
	}

	/**
	 * @param bool $is_pro
	 *
	 * @return bool
	 */
	private function is_any_active( bool $is_pro ): bool {
		$settings = new \WP_Defender\Model\Setting\Scan();
		$file_change_check = $settings->is_checked_any_file_change_types();

		if ( $is_pro ) {
			// Pro version. Check all parent types.
			return $file_change_check || $settings->check_known_vuln || $settings->scan_malware;
		} else {
			// Free version. Check the 'File change detection' type because only it's available with nested types.
			return $file_change_check;
		}
	}

	/**
	 * @return array
	 */
	public function export_strings(): array {
		$strings = [];
		$is_pro = ( new WPMUDEV() )->is_pro();
		if ( $this->is_any_active( $is_pro ) ) {
			$strings[] = __( 'Active', 'defender-security' );
		} else {
			$strings[] = __( 'Inactive', 'defender-security' );
		}

		$scan_report = new Malware_Report();
		$scan_notification = new \WP_Defender\Model\Notification\Malware_Notification();
		if ( 'enabled' === $scan_notification->status ) {
			$strings[] = __( 'Email notifications active', 'defender-security' );
		}
		if ( $is_pro && 'enabled' === $scan_report->status ) {
			$strings[] = sprintf(
			/* translators: %s: Frequency value. */
				__( 'Email reports sending %s', 'defender-security' ),
				$scan_report->frequency
			);
		} elseif ( ! $is_pro ) {
			$strings[] = sprintf(
			/* translators: %s: Html for Pro-tag. */
				__( 'Email report inactive %s', 'defender-security' ),
				'<span class="sui-tag sui-tag-pro">Pro</span>'
			);
		}

		return $strings;
	}

	/**
	 * @param array $config
	 * @param bool  $is_pro
	 *
	 * @return array
	 */
	public function config_strings( array $config, bool $is_pro ): array {
		$strings = [];
		$strings[] = $this->service->is_any_scan_active( $config, $is_pro )
			? __( 'Active', 'defender-security' )
			: __( 'Inactive', 'defender-security' );

		if ( 'enabled' === $config['notification'] ) {
			$strings[] = __( 'Email notifications active', 'defender-security' );
		}
		if ( $is_pro && 'enabled' === $config['report'] ) {
			$strings[] = sprintf(
			/* translators: %s: Frequency value. */
				__( 'Email reports sending %s', 'defender-security' ),
				$config['frequency']
			);
		} elseif ( ! $is_pro ) {
			$strings[] = sprintf(
			/* translators: %s: Html for Pro-tag. */
				__( 'Email report inactive %s', 'defender-security' ),
				'<span class="sui-tag sui-tag-pro">Pro</span>'
			);
		}

		return $strings;
	}

	/**
	 * Triggers the asynchronous scan.
	 *
	 * @param string $type Denotes type of the scan from the following four possible values scan, install, hub or report.
	 *
	 * @return void
	 */
	public function do_async_scan( string $type ): void {
		wd_di()->get( Model_Scan::class )->delete_idle();

		as_enqueue_async_action(
			'defender/async_scan',
			[
				'type' => $type,
			],
			'defender'
		);
	}

	/**
	 * Clear completed action scheduler logs.
	 *
	 * @return void
	 * @since 2.6.5
	 */
	public function clear_scan_logs(): void {
		$scan_component = wd_di()->get( \WP_Defender\Component\Scan::class );
		$result = $scan_component::clear_logs();

		if ( isset( $result['error'] ) ) {
			$this->log( 'WP CRON Error : ' . $result['error'], 'scan.log' );
		}
	}

	/**
	 * When user session is expired and scan is running, then don't login via heartbeat modal.
	 *
	 * @param $response
	 * @param $screen_id
	 *
	 * @since 3.11.0
	 * @return mixed
	 */
	public function nopriv_heartbeat( $response, $screen_id ) {
		if ( false !== strpos( $screen_id, $this->slug ) ) {
			$scan = Model_Scan::get_active();

			if ( is_object( $scan ) ) {
				$response['wp-auth-check'] = true;
			}
		}

		return $response;
	}

	/**
	 * Triggers and send analytics data on scan started.
	 *
	 * @return void
	 */
	public function scan_started_analytics( array $extra_data ) {
		/**
		 * @var Scan_Analytics
		 */
		$scan_analytics = wd_di()->get( Scan_Analytics::class );
		$analytics_data = $scan_analytics->scan_started( $this->model );

		$this->track_feature(
			$analytics_data['event'],
			array_merge( $analytics_data['data'], $extra_data )
		);
	}

	/**
	 * Triggers and send analytics data on scan completed.
	 *
	 * @param int $action_id Action ID.
	 *
	 * @return void
	 */
	public function scan_completed_analytics( $action_id ) {
		if ( 'defender' === \ActionScheduler::store()->fetch_action( $action_id )->get_group() ) {
			/**
			 * @var Scan_Analytics
			 */
			$scan_analytics = wd_di()->get( Scan_Analytics::class );

			$scan_model = wd_di()->get( Model_Scan::class );
			$analytics_data = $scan_analytics->scan_completed( $scan_model );

			$this->track_feature(
				$analytics_data['event'],
				$analytics_data['data']
			);
		}
	}
}
