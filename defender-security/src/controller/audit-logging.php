<?php

namespace WP_Defender\Controller;

use Calotes\Component\Request;
use Calotes\Component\Response;
use Calotes\Helper\Array_Cache;
use Calotes\Helper\HTTP;
use WP_Defender\Component\Audit;
use WP_Defender\Component\Config\Config_Hub_Helper;
use WP_Defender\Event;
use WP_Defender\Model\Audit_Log;
use WP_Defender\Model\Notification\Audit_Report;
use WP_Defender\Traits\Formats;
use WP_Defender\Traits\User;
use WP_Defender\Model\Setting\Audit_Logging as Model_Audit_Logging;

class Audit_Logging extends Event {
	use User, Formats;

	public $slug = 'wdf-logging';

	/**
	 * Use for cache.
	 *
	 * @var Model_Audit_Logging
	 */
	public $model;

	/**
	 * @var Audit
	 */
	public $service;

	public function __construct() {
		$this->register_page(
			esc_html( Model_Audit_Logging::get_module_name() ),
			$this->slug,
			[
				&$this,
				'main_view',
			],
			$this->parent_slug
		);
		add_action( 'defender_enqueue_assets', [ &$this, 'enqueue_assets' ] );
		$this->model = wd_di()->get( Model_Audit_Logging::class );
		$this->service = new Audit();
		$this->register_routes();
		if ( $this->model->is_active() ) {
			$this->service->enqueue_event_listener();
			add_action( 'shutdown', [ &$this, 'cache_audit_logs' ] );
			/**
			 * We will schedule the time for flush data into cloud.
			 */
			if ( ! wp_next_scheduled( 'audit_sync_events' ) ) {
				wp_schedule_event( time() + 15, 'hourly', 'audit_sync_events' );
			}
			add_action( 'audit_sync_events', [ &$this, 'sync_events' ] );

			/**
			 * We will schedule the time to clean up old logs.
			 */
			if ( ! wp_next_scheduled( 'audit_clean_up_logs' ) ) {
				wp_schedule_event( time(), 'hourly', 'audit_clean_up_logs' );
			}
			add_action( 'audit_clean_up_logs', [ &$this, 'clean_up_audit_logs' ] );
		}
	}

	/**
	 * Sync all the events into cloud, this will happen per hourly basis.
	 *
	 * @return void
	 */
	public function sync_events(): void {
		$this->service->flush();
	}

	/**
	 * Clean up all the old logs from the local storage, this will happen per hourly basis.
	 *
	 * @return void
	 */
	public function clean_up_audit_logs(): void {
		$this->service->audit_clean_up_logs();
	}

	/**
	 * @return void
	 * @throws \Exception
	 * @defender_route
	 */
	public function export_as_csv(): void {
		$date_from = HTTP::get(
			'date_from',
			date( 'Y-m-d H:i:s', strtotime( '-7 days', current_time( 'timestamp' ) ) )
		);
		$date_to = HTTP::get( 'date_to', date( 'Y-m-d H:i:s', current_time( 'timestamp' ) ) );
		// Convert date using timezone.
		$timezone = wp_timezone();
		$date_from = ( new \DateTime( $date_from, $timezone ) )->setTime( 0, 0, 0 )->getTimestamp();
		$date_to = ( new \DateTime( $date_to, $timezone ) )->setTime( 23, 59, 59 )->getTimestamp();
		$username = HTTP::get( 'term', '' );
		$user_id = '';
		$user = get_user_by( 'login', $username );
		$events = HTTP::get( 'event_type', [] );
		if ( is_object( $user ) ) {
			$user_id = $user->ID;
		}

		$handler = new Audit();
		$ip_address = HTTP::get( 'ip_address', '' );
		$result = $handler->fetch( $date_from, $date_to, $events, $user_id, $ip_address, false );
		// Have data, now prepare to flush.
		$fp = fopen( 'php://memory', 'w' );
		$headers = [
			__( 'Summary', 'defender-security' ),
			__( 'Date / Time', 'defender-security' ),
			__( 'Context', 'defender-security' ),
			__( 'Type', 'defender-security' ),
			__( 'IP address', 'defender-security' ),
			__( 'User', 'defender-security' ),
		];
		fputcsv( $fp, $headers );
		foreach ( $result as $log ) {
			$fields = $log->export();
			$vars = [
				$fields['msg'],
				is_array( $fields['timestamp'] )
					? $this->format_date_time( date( 'Y-m-d H:i:s', $fields['timestamp'][0] ) )
					: $this->format_date_time( date( 'Y-m-d H:i:s', $fields['timestamp'] ) ),
				$fields['context'],
				$fields['action_type'],
				$fields['ip'],
				$this->get_user_display( $fields['user_id'] ),
			];
			fputcsv( $fp, $vars );
		}
		$filename = 'wdf-audit-logs-export-' . date( 'ymdHis' ) . '.csv';
		fseek( $fp, 0 );
		header( 'Content-Type: text/csv' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '";' );
		// Make php send the generated csv lines to the browser.
		fpassthru( $fp );
		exit();
	}

	/**
	 * We'll pass all the event logs into the db handler, so it writes down to db.
	 * Do it in shutdown runtime, so no delay time.
	 *
	 * @return void
	 */
	public function cache_audit_logs(): void {
		$audit = new Audit();
		$audit->log_audit_events();
	}

	/**
	 * Pull the logs from db cached:
	 * - date_from: the start of the date we will run the query, as mysql time format,
	 * - date_to: similar to the above,
	 * others will refer to Audit.
	 *
	 * @param Request $request
	 *
	 * @return Response
	 * @throws \Exception
	 * @defender_route
	 */
	public function pull_logs( Request $request ): Response {
		$data = $request->get_data(
			[
				'date_from' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
				'date_to' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
				'username' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
				'events' => [
					'type' => 'array',
					'sanitize' => 'sanitize_text_field',
				],
				'ip_address' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
				'paged' => [
					'type' => 'int',
					'sanitize' => 'sanitize_text_field',
				],
			]
		);
		if ( empty( $data['date_from'] ) || empty( $data['date_to'] ) ) {
			return new Response( false, [ 'message' => __( 'Invalid data.', 'defender-security' ) ] );
		}
		// Convert date using timezone.
		$timezone = wp_timezone();
		$date_from = ( new \DateTime( $data['date_from'], $timezone ) )
			->setTime( 0, 0, 0 )
			->getTimestamp();
		$date_to = ( new \DateTime( $data['date_to'], $timezone ) )
			->setTime( 23, 59, 59 )
			->getTimestamp();

		$events = $data['events'] ?? [];
		$ip_address = $data['ip_address'] ?? '';
		$paged = $data['paged'] ?? 1;
		$username = $data['username'] ?? '';
		$user_id = '';
		if ( ! empty( $username ) ) {
			$user = get_user_by( 'login', $username );
			if ( is_object( $user ) ) {
				$user_id = $user->ID;
				// Fetch result with the specified user.
				$result = $this->service->fetch( $date_from, $date_to, $events, $user_id, $ip_address, $paged );
			} else {
				// A non-existent username.
				$result = [];
			}
		} else {
			// Fetch result with empty user field.
			$result = $this->service->fetch( $date_from, $date_to, $events, $user_id, $ip_address, $paged );
		}

		if ( is_wp_error( $result ) ) {
			return new Response( false, [ 'message' => $result->get_error_message() ] );
		}
		$logs = [];
		if ( ! empty( $result ) ) {
			foreach ( $result as $item ) {
				$logs[] = array_merge(
					$item->export(),
					[
						'user' => $this->get_user_display( $item->user_id ),
						'user_url' => (int) $item->user_id > 0 ? get_edit_user_link( $item->user_id ) : '',
						'log_date' => $this->get_date( $item->timestamp ),
						'format_date' => $this->format_date_time( gmdate( 'Y-m-d H:i:s', $item->timestamp ) ),
					]
				);
			}
		}
		// @since 3.0.0 If no logs then $count = 0.
		if ( empty( $logs ) ) {
			$count = 0;
		} else {
			$count = Audit_Log::count( $date_from, $date_to, $events, $user_id, $ip_address );
		}
		$per_page = 20;
		// Get the count for the submitted data.
		return new Response(
			true,
			[
				'logs' => $logs,
				'total_items' => $count,
				'total_pages' => ceil( $count / $per_page ),
				'per_page' => $per_page,
			]
		);
	}

	/**
	 * @param Audit_Report $audit_report
	 *
	 * @return string
	 */
	public function get_frequency_text( Audit_Report $audit_report ): string {
		$text = '';
		switch ( $audit_report->frequency ) {
			case 'daily':
				$text = ucfirst( $audit_report->day ) . 's at ' . $audit_report->time;
				break;
			case 'weekly':
			case 'monthly':
				$text = ucfirst( $audit_report->frequency ) . ' on ' . ucfirst( $audit_report->day ) . 's at ' . $audit_report->time;
				break;
			default:
				break;
		}

		return $text;
	}

	/**
	 * @return void
	 */
	public function enqueue_assets() {
		if ( ! $this->is_page_active() ) {
			return;
		}

		wp_enqueue_script( 'def-moment', defender_asset_url( '/assets/js/vendor/moment/moment.min.js' ) );
		wp_enqueue_script(
			'def-daterangepicker',
			defender_asset_url( '/assets/js/vendor/daterangepicker/daterangepicker.js' )
		);
		wp_localize_script(
			'def-audit',
			'audit',
			$this->data_frontend()
		);
		wp_enqueue_script( 'def-audit' );
		$this->enqueue_main_assets();
	}

	/**
	 * Render the root element for frontend.
	 *
	 * @return void
	 */
	public function main_view(): void {
		$this->render( 'main' );
	}

	/**
	 * @return void
	 * @throws \Exception
	 * @defender_route
	 */
	public function summary(): void {
		$response = $this->model->is_active() ? $this->summary_data() : [];
		wp_send_json_success( $response );
	}

	/**
	 * @param bool $for_hub. Default 'false' because it's displayed on site summary sections.
	 *
	 * @return array
	*/
	public function summary_data( bool $for_hub = false ): array {
		// Monthly count.
		$date_from = ( new \DateTime( date( 'Y-m-d', strtotime( '-30 days' ) ) ) )
			->setTime( 0, 0, 0 )
			->getTimestamp();
		$date_to = ( new \DateTime( date( 'Y-m-d' ) ) )->setTime( 23, 59, 59 )->getTimestamp();
		$month_count = Audit_Log::count( $date_from, $date_to );
		// Weekly count.
		$date_from = ( new \DateTime( date( 'Y-m-d', strtotime( '-7 days' ) ) ) )
			->setTime( 0, 0, 0 )
			->getTimestamp();
		$week_count = Audit_Log::count( $date_from, $date_to );
		// Daily count. Sync data to the Hub without timezone.
		$date_from = $for_hub ? new \DateTime( 'now' ) : new \DateTime( 'now', wp_timezone() );
		$date_from = $date_from->modify( '-24 hours' )->setTime( 0, 0, 0 )->getTimestamp();
		$day_count = Audit_Log::count( $date_from, $date_to );
		// Get the last item.
		$last = Audit_Log::get_last();
		if ( is_object( $last ) ) {
			$last = $for_hub
				? $this->persistent_hub_datetime_format( $last->timestamp )
				: $this->format_date_time( $last->timestamp );
		} else {
			$last = 'n/a';
		}

		return [
			'monthCount' => $month_count,
			'weekCount' => $week_count,
			'dayCount' => $day_count,
			'lastEvent' => $last,
		];
	}

	/**
	 * Save settings.
	 * @param Request $request
	 *
	 * @return Response
	 * @defender_route
	 */
	public function save_settings( Request $request ): Response {
		$data = $request->get_data_by_model( $this->model );
		if ( false === $data['enabled'] && $data['enabled'] !== $this->model->is_active() ) {
			// Toggle off, so we need to flush everything to cloud.
			$this->service->flush();
		}

		$this->model->import( $data );
		if ( $this->model->validate() ) {
			$this->model->save();
		}

		Config_Hub_Helper::set_clear_active_flag();

		return new Response(
			true,
			array_merge(
				$this->data_frontend(),
				[
					'message' => __( 'Your settings have been updated.', 'defender-security' ),
					'auto_close' => true,
				]
			)
		);
	}

	/**
	 * @return array
	 */
	public function to_array(): array {
		return array_merge(
			[
				'enabled' => $this->model->is_active(),
				'report' => true,
			],
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * @return void
	 */
	public function remove_settings(): void {
		( new Model_Audit_Logging() )->delete();
	}

	/**
	 * Delete all the data & the cache.
	 *
	 * @return void
	 */
	public function remove_data(): void {
		Audit_Log::truncate();
		// Remove cached data.
		Array_Cache::remove( 'sockets', 'audit' );
		Array_Cache::remove( 'logs', 'audit' );
		Array_Cache::remove( 'menu_updated', 'audit' );
		Array_Cache::remove( 'post_updated', 'audit' );
		delete_site_option( Audit::CACHE_LAST_CHECKPOINT );
	}

	/**
	 * All the variables that we will show on frontend, both in the main page, or dashboard widget.
	 *
	 * @return array
	 */
	public function data_frontend(): array {
		$logs = [];
		$count = 0;
		$per_page = 20;
		$total_page = 1;
		if ( $this->model->is_active() ) {
			$timezone = wp_timezone();
			$date_from = ( new \DateTime() )->setTimezone( $timezone )
				->sub( new \DateInterval( 'P7D' ) )->setTime( 0, 0, 0 );
			$date_to = ( new \DateTime() )->setTimezone( $timezone )->setTime( 23, 59, 59 );
			$result = $this->service->fetch(
				$date_from->getTimestamp(),
				$date_to->getTimestamp(),
				[],
				'',
				'',
				1
			);
			if ( ! is_wp_error( $result ) ) {
				foreach ( $result as $item ) {
					$logs[] = array_merge(
						$item->export(),
						[
							'user' => $this->get_user_display( $item->user_id ),
							'user_url' => (int) $item->user_id > 0 ? get_edit_user_link( $item->user_id ) : '',
							'log_date' => $this->get_date( $item->timestamp ),
							'format_date' => $this->format_date_time( gmdate( 'Y-m-d H:i:s', $item->timestamp ) ),
						]
					);
				}
				$count = Audit_Log::count( $date_from->getTimestamp(), $date_to->getTimestamp() );
				$total_page = ceil( $count / $per_page );
			}
		}

		return array_merge(
			[
				'model' => $this->model->export(),
				'logs' => $logs,
				'events_type' => Audit_Log::allowed_events(),
				'summary' => [
					'count_7_days' => $count,
					'report' => wd_di()->get( Audit_Report::class )->to_string(),
				],
				'paging' => [
					'paged' => 1,
					'total_pages' => $total_page,
					'count' => $count,
				],
			],
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * @param array $data
	 *
	 * @return void
	 */
	public function import_data( $data ): void {
		$model = $this->model;
		if ( empty( $data ) ) {
			$model->enabled = false;
			$model->storage_days = '6 months';
			$model->save();
		} else {
			$model->import( $data );
			if ( $model->validate() ) {
				$model->save();
			}
		}
	}

	/**
	 * @return array
	 */
	public function export_strings(): array {
		if ( ! ( new \WP_Defender\Behavior\WPMUDEV() )->is_pro() ) {
			return [
				sprintf(
				/* translators: %s: Html for Pro-tag. */
					__( 'Inactive %s', 'defender-security' ),
					'<span class="sui-tag sui-tag-pro">Pro</span>'
				),
			];
		}

		if ( $this->model->is_active() ) {
			$strings = [ __( 'Active', 'defender-security' ) ];
			$audit_report = new \WP_Defender\Model\Notification\Audit_Report();
			if ( 'enabled' === $audit_report->status ) {
				$strings[] = sprintf(
				/* translators: %s: Frequency value. */
					__( 'Email reports sending %s', 'defender-security' ),
					$audit_report->frequency
				);
			}
		} else {
			$strings = [ __( 'Inactive', 'defender-security' ) ];
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
		if ( $is_pro ) {
			if ( $config['enabled'] ) {
				$strings = [ __( 'Active', 'defender-security' ) ];
				if ( isset( $config['report'] ) && 'enabled' === $config['report'] ) {
					$strings[] = sprintf(
					/* translators: %s: Frequency value. */
						__( 'Email reports sending %s', 'defender-security' ),
						$config['frequency']
					);
				}
			} else {
				$strings = [ __( 'Inactive', 'defender-security' ) ];
			}
		} else {
			$strings = [
				sprintf(
				/* translators: %s: Html for Pro-tag. */
					__( 'Inactive %s', 'defender-security' ),
					'<span class="sui-tag sui-tag-pro">Pro</span>'
				)
			];
		}

		return $strings;
	}
}
