<?php

namespace WP_Defender\Controller;

use Calotes\Component\Request;
use Calotes\Component\Response;
use WP_Defender\Component\Config\Config_Hub_Helper;
use WP_Defender\Event;
use WP_Defender\Traits\Setting;
use WP_Defender\Model\Setting\User_Agent_Lockout;

/**
 * Class UA_Lockout.
 *
 * @package WP_Defender\Controller
 * @since 2.6.0
 */
class UA_Lockout extends Event {
	use Setting;

	/**
	 * @var string
	 */
	protected $slug = 'wdf-ip-lockout';

	/**
	 * Use for cache.
	 *
	 * @var User_Agent_Lockout
	 */
	protected $model;

	/**
	 * @var \WP_Defender\Component\User_Agent
	 */
	protected $service;

	public function __construct() {
		$this->register_routes();
		$this->model = $this->get_model();
		$this->service = wd_di()->get( \WP_Defender\Component\User_Agent::class );
		add_action( 'defender_enqueue_assets', [ &$this, 'enqueue_assets' ] );
	}

	/**
	 * @return User_Agent_Lockout
	 */
	private function get_model() {
		if ( is_object( $this->model ) ) {
			return $this->model;
		}

		return new User_Agent_Lockout();
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
		wp_localize_script( 'def-iplockout', 'ua_lockout', $this->data_frontend() );
	}


	/**
	 * Save settings.
	 * @param Request $request
	 *
	 * @return Response
	 * @defender_route
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
					'No of Bots in the Whitelist' => count( $this->model->get_lockout_list( 'allowlist', false ) ),
					'No of Bots in the Blocklist' => count( $this->model->get_lockout_list( 'blocklist', false ) ),
				];
				$this->track_feature( 'def_user_agent_banning', $track_data );
			}

			return new Response(
				true,
				array_merge(
					[
						'message' => $this->get_update_message( $data, $old_enabled, User_Agent_Lockout::get_module_name() ),
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

	public function remove_settings() {}

	public function remove_data() {}

	public function to_array() {}

	/**
	 * @return array
	 */
	public function data_frontend(): array {
		$arr_model = $this->model->export();

		return array_merge(
			[
				'model' => $arr_model,
				'misc' => [
					'no_ua' => '' === $arr_model['blacklist'] && '' === $arr_model['whitelist'],
					'module_name' => User_Agent_Lockout::get_module_name(),
				],
			],
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * @param array $data
	 *
	 * @return array
	 */
	private function adapt_data( array $data ): array {
		$adapted_data = [];
		if ( isset( $data['ua_banning_enabled'] ) ) {
			$adapted_data['enabled'] = (bool) $data['ua_banning_enabled'];
		}
		if ( isset( $data['ua_banning_message'] ) ) {
			$adapted_data['message'] = $data['ua_banning_message'];
		}
		if ( isset( $data['ua_banning_blacklist'] ) ) {
			$adapted_data['blacklist'] = $data['ua_banning_blacklist'];
		}
		if ( isset( $data['ua_banning_whitelist'] ) ) {
			$adapted_data['whitelist'] = $data['ua_banning_whitelist'];
		}
		if ( isset( $data['ua_banning_empty_headers'] ) ) {
			$adapted_data['empty_headers'] = (bool) $data['ua_banning_empty_headers'];
		}

		return array_merge( $data, $adapted_data );
	}

	/**
	 * @param array $data
	 *
	 * @return void
	 */
	public function import_data( $data ): void {
		$model = $this->get_model();
		if ( ! empty( $data ) ) {
			$data = $this->adapt_data( $data );
			$model->import( $data );
			if ( $model->validate() ) {
				$model->save();
			}
		} else {
			$default_ua_values = $model->get_default_values();
			$model->enabled = false;
			$model->message = $default_ua_values['message'];
			$model->blacklist = $default_ua_values['blacklist'];
			$model->whitelist = $default_ua_values['whitelist'];
			$model->empty_headers = false;
			$model->save();
		}
	}

	/**
	 * @return void
	 * @defender_route
	 */
	public function export_ua(): void {
		$data = [];

		foreach ( $this->model->get_lockout_list( 'blocklist', false ) as $ua ) {
			$data[] = [
				'ua' => $ua,
				'type' => 'blocklist',
			];
		}
		foreach ( $this->model->get_lockout_list( 'allowlist', false ) as $ua ) {
			$data[] = [
				'ua' => $ua,
				'type' => 'allowlist',
			];
		}

		$fp = fopen( 'php://memory', 'w' );
		foreach ( $data as $fields ) {
			fputcsv( $fp, $fields );
		}
		$filename = 'wdf-ua-export-' . gmdate( 'ymdHis' ) . '.csv';
		fseek( $fp, 0 );
		header( 'Content-Type: text/csv' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '";' );
		// Make php send the generated csv lines to the browser.
		fpassthru( $fp );
		exit();
	}

	/**
	 * Importing UAs from exporter.
	 *
	 * @param Request $request
	 *
	 * @defender_route
	 * @return Response
	 */
	public function import_ua( Request $request ) {
		$data = $request->get_data(
			[
				'id' => [
					'type' => 'int',
				],
			]
		);

		$attached_id = $data['id'];
		if ( ! is_object( get_post( $attached_id ) ) ) {
			return new Response(
				false,
				[ 'message' => __( 'Your file is invalid!', 'defender-security' ) ]
			);
		}

		$file = get_attached_file( $attached_id );
		if ( ! is_file( $file ) ) {
			return new Response(
				false,
				[ 'message' => __( 'Your file is invalid!', 'defender-security' ) ]
			);
		}

		$data = $this->service->verify_import_file( $file );
		if ( ! $data ) {
			return new Response(
				false,
				[ 'message' => __( 'Your file content is invalid! Please use a CSV file format and try again.', 'defender-security' ) ]
			);
		}

		// All good, start to import.
		foreach ( $data as $line ) {
			$this->model->add_to_list( $line[0], $line[1] );
		}

		return new Response(
			true,
			[
				'message' => __( 'Your blocklist and allowlist have been successfully imported.', 'defender-security' ),
				'interval' => 1,
			]
		);
	}

	/**
	 * @return array
	 */
	public function export_strings(): array {
		return [];
	}
}
