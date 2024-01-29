<?php

namespace WP_Defender\Controller;

use Calotes\Component\Request;
use Calotes\Component\Response;
use WP_Defender\Component\Blacklist_Lockout;
use WP_Defender\Component\Config\Config_Hub_Helper;
use WP_Defender\Event;
use WP_Defender\Traits\IP;
use WP_Defender\Traits\Setting;
use WP_Defender\Model\Setting\Login_Lockout as Model_Login_Lockout;

/**
 * Class Login_Lockout
 * @package WP_Defender\Controller
 */
class Login_Lockout extends Event {
	use IP, Setting;

	/**
	 * @var string
	 */
	protected $slug = 'wdf-ip-lockout';

	/**
	 * @var \WP_Defender\Component\Login_Lockout
	 */
	protected $service;

	/**
	 * @var Model_Login_Lockout
	 */
	protected $model;

	public function __construct() {
		$this->register_routes();
		add_action( 'defender_enqueue_assets', [ &$this, 'enqueue_assets' ] );
		$this->model = wd_di()->get( Model_Login_Lockout::class );
		$this->service = wd_di()->get( \WP_Defender\Component\Login_Lockout::class );
		$service = wd_di()->get( Blacklist_Lockout::class );
		$ip = $this->get_user_ip();
		if ( $this->model->enabled && ! $service->are_ips_whitelisted( $ip ) ) {
			$this->service->add_hooks();
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
		$prev_data = $this->model->export();

		$this->model->import( $data );
		if ( $this->model->validate() ) {
			$this->model->save();
			Config_Hub_Helper::set_clear_active_flag();
			// Maybe track.
			if ( ! defender_is_wp_cli() && $this->is_feature_state_changed( $prev_data, $data ) ) {
				$track_data = [
					'Action' => $data['enabled'] ? 'Enabled' : 'Disabled',
					'Duration' => 'timeframe' === $data['lockout_type'] ? 'Temporary' : 'Permanent',
				];
				$this->track_feature( 'def_login_protection', $track_data );
			}

			return new Response( true, array_merge( [
				'message' => $this->get_update_message( $data, $old_enabled, Model_Login_Lockout::get_module_name() ),
				'auto_close' => true,
			], $this->data_frontend() ) );
		}

		return new Response( false, [
			'message' => $this->model->get_formatted_errors()
		] );
	}

	/**
	 * Queue assets and require data.
	 *
	 * @return void
	 */
	public function enqueue_assets() {
		if ( ! $this->is_page_active() ) {
			return;
		}
		wp_localize_script( 'def-iplockout', 'login_lockout', $this->data_frontend() );
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
				'host' => defender_get_hostname(),
				'module_name' => Model_Login_Lockout::get_module_name(),
			],
		], $this->dump_routes_and_nonces() );
	}

	/**
	 * Export the data of this module, we will use this for export to HUB, create a preset etc.
	 */
	public function to_array() {}

	/**
	 * @param array $data
	 *
	 * @return array
	 */
	private function adapt_data( array $data ): array {
		$adapted_data = [];
		if ( isset( $data['login_protection'] ) ) {
			$adapted_data['enabled'] = $data['login_protection'];
		}
		if ( isset( $data['login_protection_login_attempt'] ) ) {
			$adapted_data['attempt'] = $data['login_protection_login_attempt'];
		}
		if ( isset( $data['login_protection_lockout_timeframe'] ) ) {
			$adapted_data['timeframe'] = $data['login_protection_lockout_timeframe'];
		}
		if ( isset( $data['login_protection_lockout_duration'] ) ) {
			$adapted_data['duration'] = $data['login_protection_lockout_duration'];
		}
		if ( isset( $data['login_protection_lockout_duration_unit'] ) ) {
			$adapted_data['duration_unit'] = $data['login_protection_lockout_duration_unit'];
		}
		if ( isset( $data['login_protection_lockout_ban'] ) ) {
			$adapted_data['lockout_type'] = 'permanent' === $data['login_protection_lockout_ban'] ? 'permanent' : 'timeframe';
		}
		if ( isset( $data['login_protection_lockout_message'] ) ) {
			$adapted_data['lockout_message'] = $data['login_protection_lockout_message'];
		}
		if ( isset( $data['username_blacklist'] ) ) {
			$adapted_data['username_blacklist'] = $data['username_blacklist'];
		}

		return array_merge( $data, $adapted_data );
	}

	/**
	 * Import the data of other source into this, it can be when HUB trigger the import, or user apply a preset.
	 *
	 * @param array $data
	 *
	 * @return void
	 */
	public function import_data( $data ): void {
		if ( ! empty( $data ) ) {
			// Upgrade for old versions.
			$data = $this->adapt_data( $data );
			$model = $this->model;
			$model->import( $data );
			if ( $model->validate() ) {
				$model->save();
			}
		}
	}

	/**
	 * Remove all settings, configs generated in this container runtime.
	 */
	public function remove_settings() {}

	/**
	 * Remove all data.
	 */
	public function remove_data() {}

	/**
	 * @return array
	 */
	public function export_strings() {
		return [];
	}
}
