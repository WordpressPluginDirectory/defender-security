<?php

namespace WP_Defender\Component;

use Calotes\Base\Component;
use WP_Defender\Component\Security_Tweaks\Servers\Server;
use WP_Defender\Traits\Device;

/**
 * Class Product_Analytics.
 *
 * @since 4.2.0
 * @package WP_Defender\Component
 */
class Product_Analytics extends Component {
	use Device;

	private const PROJECT_TOKEN = '5d545622e3a040aca63f2089b0e6cae7';

	/**
	 * @var null|\Mixpanel
	 */
	private $mixpanel = null;

	private $mysql_version;

	public function __construct() {
		if ( is_null( $this->mixpanel ) ) {
			// Create new mixpanel instance.
			$this->mixpanel = $this->prepare_mixpanel_instance();
		}
		$this->mixpanel->identify( $this->get_unique_id() );
		$this->mixpanel->registerAll( $this->get_super_properties() );
	}

	/**
	 * Get configured mixpanel instance.
	 *
	 * @return \Mixpanel
	 */
	public function get_mixpanel() {
		return $this->mixpanel;
	}

	/**
	 * Handle mixpanel error.
	 *
	 * @param string $code Error code.
	 * @param string $data Error data.
	 *
	 * @return void
	 */
	private function handle_error( $code, $data ) {
		$this->log( $code . ':' . $data );
	}

	/**
	 * Prepare Mixpanel instance.
	 * @method identify(int $user_id)
	 * @method register(string $property, mixed $value)
	 * @method registerAll(array $properties)
	 * @method track(string $event, array $properties = array())
	 *
	 * @return \Mixpanel
	 */
	private function prepare_mixpanel_instance() {
		if ( is_null( $this->mixpanel ) ) {
			$this->mixpanel = \Mixpanel::getInstance(
				self::PROJECT_TOKEN,
				[
					'error_callback' => [ $this, 'handle_error' ],
					'consumers' => [
						'file' => 'ConsumerStrategies_FileConsumer',
						'curl' => 'ConsumerStrategies_CurlConsumer',
						'socket' => 'ConsumerStrategies_SocketConsumer',
					],
					'consumer' => 'socket',
				]
			);
		}

		return $this->mixpanel;
	}

	/**
	 * Get super properties for all events.
	 *
	 * @return array
	 */
	private function get_super_properties(): array {
		global $wp_version;

		return [
			'active_theme' => get_stylesheet(),
			'locale' => get_locale(),
			'mysql_version' => $this->get_mysql_version(),
			'php_version' => PHP_VERSION,
			'plugin' => 'Defender',
			'plugin_type' => ( new \WP_Defender\Behavior\WPMUDEV() )->is_pro() ? 'pro' : 'free',
			'plugin_version' => DEFENDER_VERSION,
			'server_type' => Server::get_current_server(),
			'wp_type' => is_multisite() ? 'multisite' : 'single',
			'wp_version' => $wp_version,
			'memory_limit' => $this->convert_to_megabytes( $this->get_memory_limit() ),
			'max_execution_time' => $this->get_max_execution_time(),
			'device' => $this->get_device(),
			'user_agent' => defender_get_user_agent(),
		];
	}

	/**
	 * Get unique identity for current site.
	 *
	 * @return string
	 */
	private function get_unique_id(): string {
		$url = str_replace( array( 'http://', 'https://', 'www.' ), '', home_url() );

		return untrailingslashit( $url );
	}

	/**
	 * @return int
	 */
	private function get_memory_limit(): int {
		if ( function_exists( 'ini_get' ) ) {
			$memory_limit = ini_get( 'memory_limit' );
		} else {
			// Sensible default.
			$memory_limit = '128M';
		}

		if ( ! $memory_limit || - 1 === $memory_limit ) {
			// Unlimited, set to 32GB.
			$memory_limit = '32000M';
		}

		return (int) $memory_limit * 1024 * 1024;
	}

	/**
	 * @param int $size_in_bytes
	 *
	 * @return int|float
	 */
	private function convert_to_megabytes( $size_in_bytes ) {
		if ( empty( $size_in_bytes ) ) {
			return 0;
		}
		$unit_mb = pow( 1024, 2 );

		return round( $size_in_bytes / $unit_mb, 2 );
	}

	/**
	 * @return int
	 */
	private function get_max_execution_time() {
		return (int) ini_get( 'max_execution_time' );
	}

	private function get_mysql_version() {
		if ( ! $this->mysql_version ) {
			global $wpdb;
			$this->mysql_version = $wpdb->db_version();
		}

		return $this->mysql_version;
	}
}
