<?php

namespace WP_Defender\Controller;

use Calotes\Component\Request;
use Calotes\Component\Response;
use WP_Defender\Component\Config\Config_Hub_Helper;
use WP_Defender\Controller;
use WP_Defender\Traits\Setting;
use WP_Defender\Model\Setting\Global_Ip_Lockout;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Component\IP\Global_IP as Global_IP_Component;

/**
 * Class Global_Ip
 * @package WP_Defender\Controller
 */
class Global_Ip extends Controller {
	use Setting;

	/**
	 * @var string
	 */
	protected $slug = 'wdf-ip-lockout';

	/**
	 * @var Global_Ip_Lockout
	 */
	protected $model;

	/**
	 * @var Global_IP_Component
	 */
	protected $service;

	/**
	 * @var WPMUDEV
	 */
	private $wpmudev;

	public function __construct() {
		$this->register_routes();
		add_action( 'defender_enqueue_assets', [ &$this, 'enqueue_assets' ] );
		$this->model = wd_di()->get( Global_Ip_Lockout::class );
		$this->service = wd_di()->get( Global_IP_Component::class );
		$this->wpmudev = wd_di()->get( WPMUDEV::class );

		if ( ! wp_next_scheduled( 'wpdef_fetch_global_ip_list' ) ) {
			wp_schedule_event( time(), 'hourly', 'wpdef_fetch_global_ip_list' );
		}
		add_action( 'wpdef_fetch_global_ip_list', [ $this, 'fetch_global_ip_list' ] );

		if ( $this->service->can_blocklist_autosync() ) {
			add_action( 'wd_blacklist_this_ip', [ $this, 'blacklist_an_ip' ] );
		}
	}

	/**
	 * @param Request $request
	 *
	 * @defender_route
	 * @return Response
	 */
	public function save_settings( Request $request ) {
		$data = $request->get_data_by_model( $this->model );
		$old_enabled = (bool) $this->model->enabled;

		$this->model->import( $data );
		if ( $this->model->validate() ) {
			$this->model->save();
			Config_Hub_Helper::set_clear_active_flag();

			return new Response(
				true,
				array_merge(
					[
						'message' => $this->get_update_message( $data, $old_enabled, Global_Ip_Lockout::get_module_name() ),
						'auto_close' => true,
					],
					$this->data_frontend()
				)
			);
		}

		return new Response(
			false,
			[ 'message' => $this->model->get_formatted_errors() ]
		);
	}

	/**
	 * Queue assets and require data.
	 *
	 * @return void
	 */
	public function enqueue_assets() {
		if ( $this->is_page_active() ) {
			wp_localize_script( 'def-iplockout', 'global_ip', $this->data_frontend() );
		}
	}

	/**
	 * All the variables that we will show on frontend, both in the main page, or dashboard widget.
	 *
	 * @return array
	 */
	public function data_frontend(): array {
		return array_merge( [
			'model' => $this->model->export(),
			'misc' => [
				'show_global_ips_disable' => $this->wpmudev->is_disabled_hub_option(),
				'module_name' => Global_Ip_Lockout::get_module_name(),
				'text_to_connect' => __( 'Connect to a WPMU DEV account to activate Global IP Blocker.', 'defender-security' ),
				'is_show_dashboard_notice' => $this->service->is_show_dashboard_notice(),
			],
			'hub' => [
				'global_ip_list' => $this->service->get_formated_global_ip_list(),
				'global_ip_setting_url' => $this->wpmudev->get_api_base_url() . 'hub2/ip-banning',
			],
		], $this->dump_routes_and_nonces() );
	}

	/**
	 * Fetch Global IP list from HUB.
	 *
	 * @since 3.4.0
	 * @return void
	 */
	public function fetch_global_ip_list(): void {
		if ( true === $this->model->enabled ) {
			$this->service->fetch_global_ip_list();
		}
	}

	/**
	 * Refresh Global IP list.
	 *
	 * @param Request $request
	 *
	 * @since 3.4.0
	 * @return Response
	 * @defender_route
	 */
	public function refresh_global_ip_list( Request $request ) {
		$data = $this->service->fetch_global_ip_list();

		if ( ! is_wp_error( $data ) ) {
			return new Response( true, [
				'message' => __(
					'The global IP addresses have been updated.',
					'defender-security'
				),
				'global_ip_list' => $this->service->get_formated_global_ip_list(),
			] );
		} else {
			return new Response( false, [
				'message' =>  __(
					'An error occurred while synchronizing the global IPs.',
					'defender-security'
				),
			] );
		}
	}

	/**
	 * Add an IP to blacklist.
	 *
	 * @param string $ip
	 *
	 * @return void
	 */
	public function blacklist_an_ip( string $ip ): void {
		$data = [
			'block_list' => [ $ip ],
		];
		$this->service->add_to_global_ip_list( $data );
	}

	/**
	 * Export the data of this module, we will use this for export to HUB, create a preset etc.
	 */
	public function to_array() {}

	/**
	 * @param array $data
	 *
	 * @return void
	 */
	public function import_data( $data ) {
		$model = $this->model;
		if ( isset( $data['global_ip_list'] ) ) {
			$model->enabled = (bool) $data['global_ip_list'];
			if ( isset( $data['global_ip_list_blocklist_autosync'] ) ) {
				$model->blocklist_autosync = (bool) $data['global_ip_list_blocklist_autosync'];
			}
		} else {
			$model->enabled = false;
			$model->blocklist_autosync = false;
		}
		$model->save();
	}

	/**
	 * Remove all settings, configs generated in this container runtime.
	 */
	public function remove_settings() {}

	/**
	 * Remove all data.
	 */
	public function remove_data() {
		delete_site_transient( Global_IP_Component::LIST_KEY );
		$this->service->delete_dashboard_notice_reminder();
	}

	/**
	 * @return array
	 */
	public function export_strings() {
		return [];
	}
}
