<?php

namespace WP_Defender\Controller;

use Calotes\Component\Request;
use Calotes\Component\Response;
use Calotes\Helper\Array_Cache;
use Calotes\Helper\HTTP;
use WP_Defender\Component\Blacklist_Lockout;
use WP_Defender\Component\Config\Config_Hub_Helper;
use WP_Defender\Component\User_Agent as User_Agent_Component;
use WP_Defender\Event;
use WP_Defender\Controller\Dashboard;
use WP_Defender\Model\Lockout_Ip;
use WP_Defender\Model\Lockout_Log;
use WP_Defender\Model\Notification\Firewall_Report;
use WP_Defender\Model\Notification\Firewall_Notification;
use WP_Defender\Model\Setting\Login_Lockout as Login_Lockout_Model;
use WP_Defender\Model\Setting\Notfound_Lockout;
use WP_Defender\Model\Setting\User_Agent_Lockout;
use WP_Defender\Model\Setting\Blacklist_Lockout as Blacklist_Model;
use WP_Defender\Model\Setting\Global_Ip_Lockout;
use WP_Defender\Behavior\WPMUDEV;

class Firewall extends Event {
	use \WP_Defender\Traits\IP;
	use \WP_Defender\Traits\Formats;

	public const FIREWALL_LOG = 'firewall.log';

	protected $slug = 'wdf-ip-lockout';

	/**
	 * @var \WP_Defender\Model\Setting\Firewall
	 */
	protected $model;

	/**
	 * @var \WP_Defender\Component\Firewall
	 */
	public $service;

	public function __construct() {
		$title = esc_html__( 'Firewall', 'defender-security' );
		$this->register_page(
			$title,
			$this->slug,
			[ &$this, 'main_view' ],
			$this->parent_slug,
			null,
			$this->menu_title( $title )
		);
		$this->model = wd_di()->get( \WP_Defender\Model\Setting\Firewall::class );
		$this->service = wd_di()->get( \WP_Defender\Component\Firewall::class );
		$this->register_routes();
		$this->maybe_show_demo_lockout();
		$this->maybe_lockout_gathered_ips();
		// Todo: pass $ip as argument to Login_Lockout/Nf_Lockout.
		wd_di()->get( Login_Lockout::class );
		wd_di()->get( Nf_Lockout::class );
		wd_di()->get( Blacklist::class );
		wd_di()->get( Firewall_Logs::class );
		wd_di()->get( UA_Lockout::class );
		wd_di()->get( Global_Ip::class );

		// We will schedule the time to clean up old firewall logs.
		if ( ! wp_next_scheduled( 'firewall_clean_up_logs' ) ) {
			wp_schedule_event( time() + 10, 'hourly', 'firewall_clean_up_logs' );
		}

		// Schedule cleanup blocklist ips event.
		$this->schedule_cleanup_blocklist_ips_event();

		add_action( 'firewall_clean_up_logs', [ &$this, 'clean_up_firewall_logs' ] );
		add_action( 'firewall_cleanup_temp_blocklist_ips', [ &$this, 'clean_up_temporary_ip_blocklist' ] );

		// Clean unwanted records from lockout table.
		if ( ! wp_next_scheduled( 'wpdef_firewall_clean_up_lockout' ) ) {
			wp_schedule_event( time() + 10, 'weekly', 'wpdef_firewall_clean_up_lockout' );
		}
		add_action( 'wpdef_firewall_clean_up_lockout', [ &$this, 'clean_up_firewall_lockout' ] );

		// Additional hooks.
		add_action( 'defender_enqueue_assets', [ &$this, 'enqueue_assets' ], 11 );
		add_action( 'admin_print_scripts', [ &$this, 'print_emoji_script' ] );

		$this->maybe_extend_mime_types();
	}

	/**
	 * Get menu title.
	 *
	 * @param string $title
	 *
	 * @since 3.11.0
	 * @return string
	 */
	protected function menu_title( string $title ): string {
		$info = defender_white_label_status();
		if ( ! $info['hide_doc_link'] ) {
			$suffix = '<span style="padding: 2px 6px;border-radius: 9px;background-color: #17A8E3;color: #FFF;font-size: 8px;letter-spacing: -0.25px;text-transform: uppercase;vertical-align: middle;">' . __( 'NEW', 'defender-security' ) . '</span>';
			$title .= ' ' . $suffix;
		}

		return $title;
	}

	/**
	 * Clean up all the old logs from the local storage, this will happen per hourly basis.
	 *
	 * @return void
	 */
	public function clean_up_firewall_logs(): void {
		$this->service->firewall_clean_up_logs();
	}

	/**
	 * Clean up temporary IP block list.
	 *
	 * @return void
	 */
	public function clean_up_temporary_ip_blocklist(): void {
		$this->service->firewall_clean_up_temporary_ip_blocklist();
	}

	/**
	 * This is for handling request from dashboard.
	 *
	 * @defender_route
	 * @return Response
	 */
	public function dashboard_activation() {
		$il = wd_di()->get( Login_Lockout_Model::class );
		$nf = wd_di()->get( Notfound_Lockout::class );
		$ua = wd_di()->get( User_Agent_Lockout::class );

		$il->enabled = true;
		$il->save();
		$nf->enabled = true;
		$nf->save();
		$ua->enabled = true;
		$ua->save();

		return new Response( true, $this->to_array() );
	}

	/**
	 * Render the view page.
	 *
	 * @return void
	 */
	public function main_view(): void {
		$this->render( 'main' );
	}

	/**
	 * Save the main settings.
	 *
	 * @param Request $request
	 *
	 * @return Response
	 * @defender_route
	 */
	public function save_settings( Request $request ) {
		$data = $request->get_data_by_model( $this->model );
		$this->model->import( $data );
		if ( $this->model->validate() ) {
			$this->service->update_cron_schedule_interval( $data['ip_blocklist_cleanup_interval'] );
			$this->model->save();
			Config_Hub_Helper::set_clear_active_flag();

			return new Response(
				true,
				[
					'message' => __( 'Your settings have been updated.', 'defender-security' ),
					'auto_close' => true,
				]
			);
		}

		return new Response(
			false,
			[
				'message' => $this->model->get_formatted_errors(),
			]
		);
	}

	/**
	 * @return array
	 */
	public function to_array(): array {
		$il = wd_di()->get( Login_Lockout_Model::class );
		$nf = wd_di()->get( Notfound_Lockout::class );
		$ua = wd_di()->get( User_Agent_Lockout::class );

		return array_merge(
			[
				'summary' => [
					'ip' => [
						'week' => Lockout_Log::count_login_lockout_last_7_days(),
					],
					'nf' => [
						'week' => Lockout_Log::count_404_lockout_last_7_days(),
					],
					'ua' => [
						'week' => Lockout_Log::count_ua_lockout_last_7_days(),
					],
					'lastLockout' => Lockout_Log::get_last_lockout_date(),
				],
				'notification' => true,
				'enabled' => $nf->enabled || $il->enabled || $ua->enabled,
				'enable_login' => $il->enabled,
				'enable_404' => $nf->enabled,
				'enable_ua' => $ua->enabled,
			],
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * @return void
	 */
	public function enqueue_assets() {
		if ( ! $this->is_page_active() ) {
			return;
		}

		wp_enqueue_media();

		wp_localize_script( 'def-iplockout', 'iplockout', $this->data_frontend() );
		wp_enqueue_script( 'def-iplockout' );
		$this->enqueue_main_assets();

		do_action( 'defender_ip_lockout_action_assets' );
	}

	/**
	 * Renders the preview of lockout screen.
	 *
	 * @return void
	 */
	private function maybe_show_demo_lockout(): void {
		$is_test = HTTP::get( 'def-lockout-demo', 0 );
		if ( 1 === (int) $is_test ) {
			$type = HTTP::get( 'type' );

			$remaining_time = 0;

			switch ( $type ) {
				case 'login':
					$settings = wd_di()->get( Login_Lockout_Model::class );
					$message = $settings->lockout_message;
					$remaining_time = 3600;
					break;
				case '404':
					$settings = wd_di()->get( Notfound_Lockout::class );
					$message = $settings->lockout_message;
					$remaining_time = 3600;
					break;
				case 'blocklist':
					$settings = wd_di()->get( Blacklist_Model::class );
					$message = $settings->ip_lockout_message;
					break;
				case 'ua-lockout':
					$settings = wd_di()->get( User_Agent_Lockout::class );
					$message = $settings->message;
					break;
				default:
					$message = __( 'Demo', 'defender-security' );
					break;
			}

			$this->actions_for_blocked( $message, $remaining_time );
			exit;
		}
	}

	/**
	 * Run actions for locked entities.
	 *
	 * @param string $message        The message to show.
	 * @param int    $remaining_time Remaining countdown time in seconds.
	 *
	 * @return void
	 */
	private function actions_for_blocked( string $message, int $remaining_time = 0 ): void {
		ob_start();

		if ( ! headers_sent() ) {
			if ( ! defined( 'DONOTCACHEPAGE' ) ) {
				define( 'DONOTCACHEPAGE', true );
			}

			header( 'HTTP/1.0 403 Forbidden' );
			header( 'Cache-Control: no-cache, no-store, must-revalidate, max-age=0' ); // HTTP 1.1.
			header( 'Pragma: no-cache' ); // HTTP 1.0.
			header( 'Expires: ' . gmdate('D, d M Y H:i:s', time()-3600) . ' GMT' ); // Proxies.
			header( 'Clear-Site-Data: "cache"' ); // Clear cache of the current request.

			$this->render_partial(
				'ip-lockout/locked',
				[
					'message' => $message,
					'remaining_time' => $remaining_time,
				]
			);
		}

		echo ob_get_clean();
		exit();
	}

	/**
	 * We will check and prevent the access if the current IP is blacklist, or get temporary banned.
	 *
	 * @param string $ip
	 *
	 * @return void|string
	 */
	public function maybe_lockout( $ip ) {
		do_action( 'wd_before_lockout', $ip );

		if ( $this->service->skip_priority_lockout_checks( $ip ) ) {
			return;
		}

		if ( $this->service->is_blocklisted_ip( $ip ) ) {
			// Get Blacklist_Lockout instance.
			$blacklist_model = wd_di()->get( Blacklist_Model::class );
			// This one is get blacklisted.
			$this->actions_for_blocked( $blacklist_model->ip_lockout_message );
		}
		// Get an instance of UA component.
		$service_ua = wd_di()->get( User_Agent_Component::class );

		if ( $service_ua->is_active_component() ) {
			$user_agent = $service_ua->sanitize_user_agent();
			if ( $service_ua->is_bad_post( $user_agent ) ) {
				$service_ua->block_user_agent_or_ip( $user_agent, $ip, User_Agent_Component::REASON_BAD_POST );
				return $service_ua->get_message();
			}
			if ( ! empty( $user_agent )
				/**
				 * Additional conditions for User Agent.
				 *
				 * @param bool
				 * @param string $user_agent
				 * @param string $ip
				 *
				 * @since 3.1.0
				 */
				&& apply_filters(
					'wd_user_agent_additional_check',
					$service_ua->is_bad_user_agent( $user_agent ),
					$user_agent,
					$ip
				)
			) {
				// Todo: if we use a hook then we should extend cases with a custom reason and send it for log.
				$service_ua->block_user_agent_or_ip( $user_agent, $ip, User_Agent_Component::REASON_BAD_USER_AGENT );
				return $service_ua->get_message();
			}
		}

		$notfound_lockout = wd_di()->get( Notfound_Lockout::class );
		if ( $notfound_lockout->enabled && false === $notfound_lockout->detect_logged && is_user_logged_in() ) {
			/**
			 * We don't need to check the IP if:
			 * the current user can logged-in and isn't from blacklisted,
			 * the option detect_404_logged is disabled.
			 */
			return;
		}
		// Check blacklist.
		$model = Lockout_Ip::get( $ip );
		if ( is_object( $model ) && $model->is_locked() ) {
			$remaining_time = $model->remaining_release_time();
			$this->actions_for_blocked( $model->lockout_message, $remaining_time );
		}
	}

	/**
	 * Remove all IP logs.
	 *
	 * @param Request $request
	 *
	 * @return Response
	 * @defender_route
	 */
	public function empty_logs( Request $request ): Response {
		if ( Lockout_Log::truncate() ) {
			$this->log( 'Logs have been successfully deleted.', self::FIREWALL_LOG );

			return new Response(
				true,
				[
					'message' => __( 'Your logs have been successfully deleted.', 'defender-security' ),
					'interval' => 1,
				]
			);
		}

		return new Response(
			false,
			[
				'message' => __( 'Failed remove!', 'defender-security' ),
			]
		);
	}

	/**
	 * Return summary data.
	 *
	 * @return array
	 */
	public function get_summary(): array {
		$summary = Lockout_Log::get_summary();

		return [
			'lockout_last' => isset( $summary['lockout_last'] ) ?
				$this->format_date_time( $summary['lockout_last'] ) :
				__( 'Never', 'defender-security' ),
			'lockout_today' => $summary['lockout_today'] ?? 0,
			'lockout_this_month' => $summary['lockout_this_month'] ?? 0,
			'lockout_login_today' => $summary['lockout_login_today'] ?? 0,
			'lockout_login_this_week' => $summary['lockout_login_this_week'] ?? 0,
			'lockout_404_today' => $summary['lockout_404_today'] ?? 0,
			'lockout_404_this_week' => $summary['lockout_404_this_week'] ?? 0,
			'lockout_ua_today' => $summary['lockout_ua_today'] ?? 0,
			'lockout_ua_this_week' => $summary['lockout_ua_this_week'] ?? 0,
		];
	}

	/**
	 * Delete the settings of all submodules. Use separate submodule classes for individual options.
	 *
	 * @return void
	 */
	public function remove_settings(): void {
		( new Login_Lockout_Model )->delete();
		( new Blacklist_Model )->delete();
		( new Notfound_Lockout )->delete();
		( new \WP_Defender\Model\Setting\Firewall() )->delete();
		( new User_Agent_Lockout )->delete();
		( new Global_Ip_Lockout() )->delete();
	}

	/**
	 * Delete data of all submodules. Use separate submodule classes for individual options.
	 *
	 * @return void
	 */
	public function remove_data(): void {
		Lockout_Log::truncate();
		// Remove cached data.
		Array_Cache::remove( 'countries', 'ip_lockout' );
		// Remove Global IP data.
		( new \WP_Defender\Controller\Global_Ip() )->remove_data();
	}

	/**
	 * All the variables that we will show on frontend, both in the main page, or dashboard widget.
	 *
	 * @return array
	 */
	public function data_frontend(): array {
		$summary_data = $this->get_summary();

		$user_ip = $this->get_user_ip();

		/**
		 * @var \WP_Defender\Component\Http\Remote_Address
		 */
		$remote_addr = wd_di()->get( \WP_Defender\Component\Http\Remote_Address::class );
		$http_ip_header_value = $remote_addr->get_http_ip_header_value( esc_html( $this->model->http_ip_header ) );

		$data = [
			'login' => [
				'week' => $summary_data['lockout_login_this_week'],
				'day' => $summary_data['lockout_login_today'],
			],
			'nf' => [
				'week' => $summary_data['lockout_404_this_week'],
				'day' => $summary_data['lockout_404_today'],
			],
			'ua' => [
				'week' => $summary_data['lockout_ua_this_week'],
				'day' => $summary_data['lockout_ua_today'],
			],
			'month' => $summary_data['lockout_this_month'],
			'day' => $summary_data['lockout_today'],
			'last_lockout' => $summary_data['lockout_last'],
			'settings' => $this->model->export(),
			'login_lockout' => wd_di()->get( Login_Lockout_Model::class )->enabled,
			'nf_lockout' => wd_di()->get( Notfound_Lockout::class )->enabled,
			'report' => wd_di()->get( Firewall_Report::class )->to_string(),
			'notification_lockout' => 'enabled' === wd_di()->get( Firewall_Notification::class )->status,
			'ua_lockout' => wd_di()->get( User_Agent_Lockout::class )->enabled,
			'user_ip' => implode( ', ', $user_ip ),
			'user_ip_header' => $http_ip_header_value,
		];

		return array_merge( $data, $this->dump_routes_and_nonces() );
	}

	/**
	 * @return array
	 */
	public function dashboard_widget(): array {
		return [
			'countries' => wd_di()->get( Blacklist_Lockout::class )->get_top_countries_blocked(),
		];
	}

	/**
	 * @param array $data
	 *
	 * @return void
	 */
	public function import_data( $data ): void {
		$model = $this->model;

		$model->import( $data );
		if ( $model->validate() ) {
			$model->save();
		}
	}

	/**
	 * @return array
	 */
	public function export_strings(): array {
		$strings = [];
		$is_pro = ( new WPMUDEV() )->is_pro();
		$firewall_report = new Firewall_Report();
		// Login lockout.
		$strings[] = Login_Lockout_Model::get_module_name() . ' '
			. Login_Lockout_Model::get_module_state( (bool) ( new Login_Lockout_Model() )->enabled );
		// Notfound lockout.
		$strings[] = Notfound_Lockout::get_module_name() . ' '
			. Notfound_Lockout::get_module_state( (bool) ( new Notfound_Lockout() )->enabled );
		// Global IP lockout.
		$strings[] = Global_Ip_Lockout::get_module_name() .' '
			. Global_Ip_Lockout::get_module_state( (bool) ( new Global_Ip_Lockout() )->enabled );
		// UA lockout.
		$strings[] = User_Agent_Lockout::get_module_name() . ' '
			. User_Agent_Lockout::get_module_state( (bool) ( new User_Agent_Lockout() )->enabled );
		// Notifications and reports.
		if ( 'enabled' === ( new Firewall_Notification() )->status ) {
			$strings[] = __( 'Email notifications active', 'defender-security' );
		}
		if ( $is_pro && 'enabled' === $firewall_report->status ) {
			$strings[] = sprintf(
			/* translators: %s: Frequency value. */
				__( 'Email reports sending %s', 'defender-security' ),
				$firewall_report->frequency
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
		// Login lockout.
		if ( isset( $config['login_protection'] ) ) {
			$strings[] = Login_Lockout_Model::get_module_name() . ' '
				. Login_Lockout_Model::get_module_state( (bool) $config['login_protection'] );
		}
		// NF lockout.
		if ( isset( $config['detect_404'] ) ) {
			$strings[] = Notfound_Lockout::get_module_name() . ' '
				. Notfound_Lockout::get_module_state( (bool) $config['detect_404'] );
		}
		// Global IP blocker.
		if ( isset( $config['global_ip_list'] ) ) {
			$strings[] = Global_Ip_Lockout::get_module_name() . ' '
			. Global_Ip_Lockout::get_module_state( (bool) $config['global_ip_list'] );
		}
		// UA lockout.
		if ( isset( $config['ua_banning_enabled'] ) ) {
			$strings[] = User_Agent_Lockout::get_module_name() . ' '
				. User_Agent_Lockout::get_module_state( (bool) $config['ua_banning_enabled'] );
		}
		// Notifications.
		if ( isset( $config['notification'] ) && 'enabled' === $config['notification'] ) {
			$strings[] = __( 'Email notifications active', 'defender-security' );
		}
		// Report.
		if ( $is_pro && 'enabled' === $config['report'] ) {
			$strings[] = sprintf(
			/* translators: %s: Frequency value. */
				__( 'Email reports sending %s', 'defender-security' ),
				$config['report_frequency']
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
	 * Schedule cleanup blocklist ips event.
	 *
	 * @return void
	 */
	private function schedule_cleanup_blocklist_ips_event() {
		// Sometimes multiple requests come at the same time. So we will only count the web requests.
		if ( defined( 'DOING_AJAX' ) || defined( 'DOING_CRON' ) ) {
			return;
		}

		$clear = get_site_option( 'wpdef_clear_schedule_firewall_cleanup_temp_blocklist_ips', false );

		if ( $clear ) {
			wp_clear_scheduled_hook( 'firewall_cleanup_temp_blocklist_ips' );
		}

		if ( wp_next_scheduled( 'firewall_cleanup_temp_blocklist_ips' ) ) {
			return;
		}

		$interval = $this->model->ip_blocklist_cleanup_interval;

		if ( ! $interval || 'never' === $interval ) {
			return;
		}

		wp_schedule_event( time() + 15, $interval, 'firewall_cleanup_temp_blocklist_ips' );
	}

	/**
	 * Maybe add a filter to extend mime types.
	 *
	 * @since 2.6.3
	 * @return void
	 */
	public function maybe_extend_mime_types(): void {
		if ( is_admin() ) {
			$current_url = set_url_scheme( 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'] );
			$current_query = wp_parse_url( $current_url, PHP_URL_QUERY );
			$current_query = $current_query ?? '';
			$referer_url = ! empty( $_SERVER['HTTP_REFERER'] ) ?
				filter_var( $_SERVER['HTTP_REFERER'], FILTER_SANITIZE_URL ) :
				'';
			$referer_query = wp_parse_url( $referer_url, PHP_URL_QUERY );
			$referer_query = $referer_query ?? '';

			parse_str( $current_query, $current_queries );
			parse_str( $referer_query, $referer_queries );

			if (
				( preg_match( '#^' . network_admin_url() . '#i', $current_url ) &&
				  ! empty( $current_queries['page'] ) && $this->slug === $current_queries['page']
				) ||
				( preg_match( '#^' . network_admin_url() . '#i', $referer_url ) &&
				  ! empty( $referer_queries['page'] ) && $this->slug === $referer_queries['page']
				)
			) {
				// Add action hook here.
				add_filter( 'upload_mimes', [ &$this, 'extend_mime_types' ] );
			}
		}
	}

	/**
	 * Filter list of allowed mime types and file extensions.
	 *
	 * @param array $types
	 *
	 * @return array
	 */
	public function extend_mime_types( array $types ): array {
		if ( empty( $types['csv'] ) ) {
			$types['csv'] = 'text/csv';
		}

		return $types;
	}

	/**
	 * Remove all lockouts.
	 *
	 * @since 3.3.0
	 * @return Response
	 * @defender_route
	 */
	public function empty_lockouts() {
		if ( Lockout_Ip::truncate() ) {
			$this->log( 'Deleted lockout records successfully.', self::FIREWALL_LOG );

			return new Response(
				true,
				[
					'message' => __( 'Deleted lockout records successfully.', 'defender-security' ),
					'interval' => 1,
				]
			);
		}

		return new Response(
			false,
			[
				'message' => __( 'Failed remove!', 'defender-security' ),
			]
		);
	}

	/**
	 * Sync IP and it's HTTP header.
	 *
	 * @param Request $request
	 *
	 * @return Response
	 * @defender_route
	 */
	public function sync_ip_header( Request $request ): Response {
		$data = $request->get_data();

		/**
		 * @var \WP_Defender\Component\Http\Remote_Address
		 */
		$remote_addr = wd_di()->get( \WP_Defender\Component\Http\Remote_Address::class );
		$remote_addr->set_http_ip_header( $data['selected_http_header'] );

		$user_ip = $remote_addr->get_ip_address();
		$user_ip_header = $remote_addr->get_http_ip_header_value( $data['selected_http_header'] );
		$data = [
			'user_ip' => is_array( $user_ip ) ? implode( ', ', $user_ip ) : $user_ip,
			'user_ip_header' => $user_ip_header,
		];

		return new Response(
			true,
			$data
		);
	}

	/**
	 * Prints inline Emoji detection script on specific admin pages only.
	 * The conflict happens when other plugins work with emoji flags.
	 *
	 * @since 3.7.0
	 * @return void
	 */
	public function print_emoji_script(): void {
		$allowed_pages = [
			$this->slug,
			wd_di()->get( Dashboard::class )->slug,
		];

		if ( in_array( HTTP::get( 'page' ), $allowed_pages, true ) ) {
			if ( ! function_exists( 'print_emoji_detection_script' ) ) {
				include_once ABSPATH . WPINC . '/formatting.php';
			}

			remove_filter( 'emoji_svg_url', '__return_false' );
			print_emoji_detection_script();
		}
	}

	/**
	 * Clean up unwanted records from lockout table.
	 *
	 * @since 3.8.0
	 * @return void
	 */
	public function clean_up_firewall_lockout(): void {
		$this->service->firewall_clean_up_lockout();
	}

	/**
	 * Gather IP(s) from various headers and check if any IP is blacklisted, or temporary banned.
	 *
	 * @since 4.4.2
	 *
	 * @return void
	 */
	public function maybe_lockout_gathered_ips(): void {
		$msg = '';
		$ips = $this->service->gather_ips();

		if ( ! empty( $ips ) && is_array( $ips ) ) {
			foreach( $ips as $ip ) {
				$result = $this->maybe_lockout( $ip );
				if ( empty( $msg ) && ! empty( $result ) ) {
					$msg = $result;
				}
			}
		}

		if ( ! empty( $msg ) ) {
			$this->actions_for_blocked( $msg );
		}
	}
}
