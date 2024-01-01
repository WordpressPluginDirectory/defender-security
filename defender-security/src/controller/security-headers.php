<?php

namespace WP_Defender\Controller;

use Calotes\Component\Request;
use Calotes\Component\Response;
use Calotes\Helper\HTTP;
use WP_Defender\Component\Config\Config_Hub_Helper;
use WP_Defender\Event;

/**
 * Class Security_Headers
 *
 * @package WP_Defender\Controller
 */
class Security_Headers extends Event {
	/**
	 * Use for cache.
	 *
	 * @var \WP_Defender\Model\Setting\Security_Headers
	 */
	public $model;

	/**
	 * @throws \DI\DependencyException
	 * @throws \DI\NotFoundException
	 */
	public function __construct() {
		add_filter( 'wp_defender_advanced_tools_data', [ $this, 'script_data' ] );
		$this->model = wd_di()->get( \WP_Defender\Model\Setting\Security_Headers::class );
		$this->init_headers();
		$this->register_routes();
	}

	/**
	 * Safe way to get cached model.
	 *
	 * @return \WP_Defender\Model\Setting\Security_Headers
	 */
	private function get_model() {
		if ( is_object( $this->model ) ) {
			return $this->model;
		}

		return new \WP_Defender\Model\Setting\Security_Headers();
	}

	/**
	 * @param array $data
	 *
	 * @return array
	 * @throws \ReflectionException
	 */
	public function script_data( array $data ): array {
		$data['security_headers'] = $this->data_frontend();

		return $data;
	}

	/**
	 * Save settings.
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
			$this->model->save();
			Config_Hub_Helper::set_clear_active_flag();
			// Maybe track.
			if ( ! defender_is_wp_cli() && $this->is_tracking_active() ) {
				// The current model data.
				$is_active_curr_data = $this->get_model()->is_any_activated();
				// The previous model data.
				$prev_data = $this->get_model()->old_settings;

				$is_active_prev_data = false;

				if ( ! empty( $prev_data ) ) {
					$is_active_prev_data = true === $prev_data['sh_xframe'] || true === $prev_data['sh_xss_protection']
							|| true === $prev_data['sh_content_type_options'] || true === $prev_data['sh_feature_policy']
							|| true === $prev_data['sh_strict_transport'] || true === $prev_data['sh_referrer_policy'];
				}

				$need_track = false;

				if ( $is_active_prev_data && ! $is_active_curr_data ) {
					$need_track = true;
					$event = 'def_feature_deactivated';
				} elseif ( ! $is_active_prev_data && $is_active_curr_data ) {
					$need_track = true;
					$event = 'def_feature_activated';
				}

				// Other conditionds without State's changes.
				if ( $need_track ) {
					$data = [
						'Feature' => 'Security Headers',
						'Triggered From' => 'Feature page',
					];
					$this->track_feature( $event, $data );
				}
			}

			return new Response(
				true,
				array_merge(
					[
						'message' => __( 'Your settings have been updated.', 'defender-security' ),
						'auto_close' => true,
					],
					$this->data_frontend()
				)
			);
		}

		return new Response( false, [ 'message' => $this->model->get_formatted_errors() ] );
	}

	/**
	 * Init headers.
	 *
	 * @return void
	 */
	public function init_headers(): void {
		if ( ! defined( 'DOING_AJAX' ) ) {
			// Refresh if on admin, on page with headers.
			if ( ( is_admin() || is_network_admin() )
				&&
				(
					( 'wdf-advanced-tools' === HTTP::get( 'page' ) )
					|| ( 'wp-defender' === HTTP::get( 'page' ) )
				)
			) {
				// This meant we don't have any data or data is overdue need to refresh list of headers.
				$this->model->refresh_headers();
			} elseif ( defined( 'DOING_CRON' ) ) {
				// If this is in cronjob, we refresh it too.
				$this->model->refresh_headers();
			}
		}

		foreach ( $this->model->get_headers() as $rule ) {
			$rule->add_hooks();
		}
	}

	public function remove_settings() {}

	public function remove_data() {}

	/**
	 * A summary data for dashboard.
	 *
	 * @return array
	 */
	public function to_array() {
		$misc = $this->get_model()->refresh_headers();

		return array_slice( $misc, 0, 3 );
	}

	/**
	 * Get data about headers.
	 *
	 * @return array
	 */
	public function get_type_headers(): array {
		return $this->get_model()->get_headers_by_type();
	}

	/**
	 * @return array
	 */
	public function data_frontend(): array {
		$model = $this->get_model();

		return array_merge(
			[
				'model' => $model->export(),
				'misc' => $model->get_headers_as_array( true ),
				'enabled' => $model->get_enabled_headers( 3 ),
			],
			$this->dump_routes_and_nonces()
		);
	}

	/**
	 * @return array
	 */
	public function dashboard_widget(): array {
		return [ 'enabled' => $this->get_model()->get_enabled_headers( 3 ) ];
	}

	/**
	 * @param array $data
	 *
	 * @return void
	 */
	public function import_data( $data ): void {
		$model = $this->get_model();

		$model->import( $data );
		if ( $model->validate() ) {
			$model->save();
		}
	}

	/**
	 * @return array
	 */
	public function export_strings(): array {
		return [
			$this->get_model()->is_any_activated() ? __( 'Active', 'defender-security' ) : __( 'Inactive', 'defender-security' ),
		];
	}
}
