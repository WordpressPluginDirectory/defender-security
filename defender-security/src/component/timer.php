<?php

namespace WP_Defender\Component;

use Calotes\Base\Component;

/**
 * Class Timer
 *
 * @package WP_Defender\Component
 */
class Timer extends Component {
	/**
	 * @var int
	 */
	protected $clock;

	public function __construct() {
		$this->start();
	}

	public function get_max_time() {
		$max = ini_get( 'max_execution_time' );
		if ( ! filter_var( $max, FILTER_VALIDATE_INT ) ) {
			$max = 30;
		}

		return $max / 2;
	}

	/**
	 * @return void
	 */
	public function start(): void {
		$this->clock = time();
	}

	/**
	 * @return bool
	 */
	public function check(): bool {
		if ( ( $this->get_difference() / 1000 ) >= $this->get_max_time() ) {
			return false;
		}

		return true;
	}

	/**
	 * @return int
	 */
	public function get_difference(): int {
		return time() - $this->clock;
	}
}
