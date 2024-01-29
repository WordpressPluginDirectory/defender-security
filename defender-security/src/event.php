<?php
/**
 * Class to handle mixpanel events functionality.
 *
 * @since   4.2.0
 * @package WP_Defender
 */

namespace WP_Defender;

use Calotes\Component\Request;
use Calotes\Component\Response;

/**
 * Abstract class for Mixpanel Events.
 */
abstract class Event extends \WP_Defender\Controller {

	/**
	 * @var string
	 */
	protected $location = '';

	/**
	 * Get mixpanel instance.
	 */
	private function tracker() {
		return wd_di()->get( \WP_Defender\Component\Product_Analytics::class )->get_mixpanel();
	}

	/**
	 * Check if usage tracking is active.
	 *
	 * @return bool
	 */
	protected function is_tracking_active() {
		return wd_di()->get( \WP_Defender\Model\Setting\Main_Setting::class )->usage_tracking;
	}

	/**
	 *  Has the data changed?
	 *
	 * @param array $old_data
	 * @param array $new_data
	 *
	 * @return bool
	 */
	protected function is_feature_state_changed( $old_data, $new_data ) {
		return ! empty( array_diff( $old_data, $new_data ) );
	}

	/**
	 * Track data tracking opt in and opt out.
	 *
	 * @param bool $active Toggle value.
	 * @param string $from Triggered method.
	 *
	 * @return void
	 */
	protected function track_opt_toggle( $active, $from ) {
		$this->tracker()->track(
			$active ? 'Opt In' : 'Opt Out',
			[
				'Method' => $from,
			]
		);
	}

	/**
	 * Track data tracking opt in and opt out.
	 *
	 * @param string $event
	 * @param array $data
	 *
	 * @return void
	 */
	public function track_feature( $event, $data ) {
		if ( $this->is_tracking_active() ) {
			$this->tracker()->track( $event, $data );
		}
	}

	/**
	 * Save tracking state.
	 *
	 * @param Request $request
	 *
	 * @return Response
	 * @defender_route
	 */
	public function track_feature_handler( Request $request ): Response {
		if ( $this->is_tracking_active() ) {
			$data = $request->get_data();
			$this->track_feature( $data['event'], $data['data'] );
		}

		return new Response( true, [] );
	}

	/**
	 * @param string $location
	 */
	public function set_intention( string $location ) {
		$this->location = $location;
	}
	/**
	 * @return string
	 */
	public function get_triggered_location() {
		return $this->location;
	}
}
