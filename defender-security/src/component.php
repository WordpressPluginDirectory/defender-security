<?php

namespace WP_Defender;

class Component extends \Calotes\Base\Component {
	use \WP_Defender\Traits\IO;
	use \WP_Defender\Traits\User;
	use \WP_Defender\Traits\Formats;
	use \WP_Defender\Traits\IP;

	/**
	 * @param $freq
	 *
	 * @return string
	 */
	public function frequency_to_text( $freq ): string {
		switch ( $freq ) {
			case 1:
				$text = __( 'daily', 'defender-security' );
				break;
			case 7:
				$text = __( 'weekly', 'defender-security' );
				break;
			case 30:
				$text = __( 'monthly', 'defender-security' );
				break;
			default:
				$text = '';
				// Param not from the button on frontend, log it.
				$this->log( sprintf( 'Unexpected value %s from IP %s', $freq, $this->get_user_ip() ) );
				break;
		}

		return $text;
	}
}
