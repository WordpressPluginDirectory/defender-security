<?php

namespace WP_Defender\Component\Security_Tweaks\Servers;

/**
 * Class for case when we need to "compile PHP to WebAssembly".
 *
 * @since 4.5.1
 * @package WP_Defender\Component\Security_Tweaks\Servers
*/
class PHP_Wasm {

	/**
	 * Service type.
	 *
	 * @var string
	 */
	private $type = null;

	public function __construct( $type ) {
		$this->type = $type;
	}

	/**
	 * Check whether the issue has been resolved or not.
	 *
	 * @return bool
	 */
	public function check() {
		//Todo:add logic using $this->type for 'prevent-php-executed' & 'protect-information'.
		return false;
	}

	/**
	 * Process the rule.
	 *
	 * @return bool
	 */
	public function process() {
		return true;
	}

	/**
	 * Revert the rule.
	 *
	 * @return bool
	 */
	public function revert() {
		return true;
	}
}
