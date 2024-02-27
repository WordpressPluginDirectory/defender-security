<?php
/**
 * The interface for trusted proxy preset class.
 *
 *  @package WP_Defender\Component\Trusted_Proxy_Preset
 */

namespace WP_Defender\Component\Trusted_Proxy_Preset;

interface Trusted_Proxy_Preset_Strategy_Interface {
	public function get_ips(): array;
	public function update_ips();
	public function delete_ips(): bool;
}