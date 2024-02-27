<?php
/**
 * The trusted proxy preset class.
 *
 *  @package WP_Defender\Component\Trusted_Proxy_Preset
 */

namespace WP_Defender\Component\Trusted_Proxy_Preset;

class Trusted_Proxy_Preset {
	/**
	 * @var string Proxy preset name.
	 */
	private $proxy_preset = '';

	/**
	 * Sets the proxy preset.
	 *
	 * @param string $proxy_preset Proxy preset name.
	 */
	public function set_proxy_preset( string $proxy_preset ): void {
		$this->proxy_preset = $proxy_preset;
	}

	/**
	 * Get proxy preset instance.
	 *
	 * @return mixed
	 */
	private function instance() {
		switch ( $this->proxy_preset ) {
			case 'cloudflare':
				return wd_di()->get( Cloudflare_Proxy::class );
			default:
				throw new \InvalidArgumentException("Unknown proxy type: $this->proxy_preset");
		}
	}

	/**
	 * Get trusted preset IPs.
	 *
	 * @return mixed
	 */
	public function get_ips() {
		try {
			return $this->instance()->get_ips();
		} catch ( \Exception $e ) {
			return false;
		}
	}

	/**
	 * Update trusted preset IPs.
	 *
	 * @return mixed
	 */
	public function update_ips() {
		try {
			return $this->instance()->update_ips();
		} catch ( \Exception $e ) {
			return false;
		}
	}

	/**
	 * Delete trusted preset IPs.
	 *
	 * @return false
	 */
	public function delete_ips() {
		try {
			return $this->instance()->delete_ips();
		} catch ( \Exception $e ) {
			return false;
		}
	}
}