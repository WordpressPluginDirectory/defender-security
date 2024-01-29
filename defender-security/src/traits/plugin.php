<?php

namespace WP_Defender\Traits;

use WP_Defender\Component\Quarantine as Quarantine_Component;
use WP_Error;

trait Plugin {

	/**
	 * Version URL.
	 *
	 * @var string Versioned path of the plugin file.
	 */
	private $url_plugin_vcs = 'https://plugins.svn.wordpress.org/%s/tags/%s/%s';

	/**
	 * Trunk URL.
	 *
	 * @var string Trunk path of the plugin file.
	 */
	private $url_plugin_vcs_trunk = 'https://plugins.svn.wordpress.org/%s/trunk/%s';

	/**
	 * Get all installed plugins.
	 *
	 * @return array
	 */
	public function get_plugins(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		// WordPress caches this internally.
		return get_plugins();
	}

	/**
	 * Get all slugs.
	 *
	 * @return array
	 */
	public function get_plugin_slugs(): array {
		$slugs = [];
		foreach ( $this->get_plugins() as $slug => $plugin ) {
			$base_slug = explode( '/', $slug );
			$slugs[] = array_shift( $base_slug );
		}

		return $slugs;
	}

	/**
	 * Get plugin data by slug.
	 *
	 * @param string $plugin_slug
	 *
	 * @return array
	 */
	public function get_plugin_data( $plugin_slug ): array {
		foreach ( $this->get_plugins() as $slug => $plugin ) {
			if ( $plugin_slug === $slug ) {
				return $plugin;
			}
		}

		return [];
	}

	/**
	 * @return string
	 */
	public function get_plugin_base_dir(): string {
		if ( defined( 'WP_PLUGIN_DIR' ) ) {
			return wp_normalize_path( WP_PLUGIN_DIR . '/' );
		}

		return wp_normalize_path( WP_CONTENT_DIR . '/plugins/' );
	}

	/**
	 * Does the plugin exist on wp.org?
	 *
	 * @param string $slug
	 *
	 * @return array Index message: describes what happened.
	 *               Index success: true if plugin in WordPress plugin repository
	 *               else false.
	 */
	public function check_plugin_on_wp_org( $slug ): array {
		$url = 'https://api.wordpress.org/plugins/info/1.0/' . $slug . '.json';
		$http_args = [
			'timeout' => 15,
			'sslverify' => false, // Many hosts have no updated CA bundle.
			'user-agent' => 'Defender/' . DEFENDER_VERSION,
		];
		$response = wp_remote_get( $url, $http_args );

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			$body_json = json_decode( wp_remote_retrieve_body( $response ), true );

			$message = __( 'Plugin unknown error.', 'defender-security' );
			if ( is_array( $body_json ) && isset( $body_json['error'] ) ) {
				$message = $body_json['error'];
			}

			return [
				'message' => $message,
				'success' => false,
			];
		}

		$results = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $results ) ) {
			return [
				'message' => __( 'Plugin response is not in expected format.', 'defender-security' ),
				'success' => false,
			];
		}

		return [
			'message' => __( 'Plugin exists in WordPress respository.', 'defender-security' ),
			'success' => true,
		];
	}

	/**
	 * Check the resulting plugin slug against WordPress.org plugin rules.
	 *
	 * @param string $slug Plugin folder name.
	 *
	 * @return bool
	 */
	public function is_likely_wporg_slug( $slug ): bool {
		// Does file readme.txt exist?
		$readme_file = $this->get_plugin_base_dir() . $slug . '/readme.txt';
		if ( file_exists( $readme_file ) && is_readable( $readme_file ) ) {
			$contents = trim( (string) file_get_contents( $readme_file ) );

			if ( false !== strpos( $contents, '===' ) ) {
				return true;
			}

			if ( false !== strpos( $contents, '#' ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @param string $file_path
	 *
	 * @return bool
	 */
	public function is_active_plugin( $file_path ): bool {
		$path_data = explode( DIRECTORY_SEPARATOR, plugin_basename( $file_path ) );
		if ( ! empty( $path_data[0] ) ) {
			$plugin_slug = $path_data[0];
		} else {
			return false;
		}

		$active = false;
		foreach ( $this->get_plugins() as $slug => $data ) {
			if ( $plugin_slug === $slug || 0 === strpos( $slug, $plugin_slug ) ) {
				$active = is_multisite() ? is_plugin_active_for_network( $slug ) : is_plugin_active( $slug );
				break;
			}
		}

		return $active;
	}

	/**
	 * Get plugin header from any file of the plugin.
	 *
	 * @param string $file_path Absolute file path to the plugin file.
	 *
	 * @return array Return plugin details as array.
	 */
	public function get_plugin_headers( $file_path ): array {
		$plugin_directory = $this->get_plugin_directory_name( $file_path );

		return get_plugins( DIRECTORY_SEPARATOR . $plugin_directory );
	}

	/**
	 * Get plugin directory name.
	 *
	 * @param string $file_path Absolute file path to the plugin file.
	 *
	 * @return string Return plugin directory name.
	 */
	public function get_plugin_directory_name( $file_path ): string {
		return (string) strtok( plugin_basename( $file_path ), '/' );
	}

	/**
	 * Get plugin relative path.
	 *
	 * @param string $file_path Absolute file path to the plugin file.
	 *
	 * @return string Return plugin relative path.
	 */
	public function get_plugin_relative_path( $file_path ): string {
		strtok( plugin_basename( $file_path ), DIRECTORY_SEPARATOR );

		return (string) strtok( '' );
	}

	/**
	 * Check file exists at wp.org svn.
	 *
	 * @param string $url URL of the file.
	 *
	 * @return boolean Return true for file exists else false.
	 */
	private function is_origin_file_exists( $url ): bool {
		$result = wp_remote_head( $url );

		if ( ! is_wp_error( $result ) ) {
			$http_status_code = wp_remote_retrieve_response_code( $result );

			return 200 === $http_status_code;
		}

		return false;
	}

	/**
	 * @return string
	 */
	private function get_version_url( string $directory_name, string $version, string $file_path ): string {
		return sprintf(
			$this->url_plugin_vcs,
			$directory_name,
			$version,
			$file_path
		);
	}

	/**
	 * @return string
	 */
	private function get_trunk_url( string $directory_name, string $file_path ): string {
		return sprintf(
			$this->url_plugin_vcs_trunk,
			$directory_name,
			$file_path
		);
	}

	private function get_file_url( string $directory_name, string $version, string $file_path ): string {
		$file_url = $this->get_version_url( $directory_name, $version, $file_path );

		if ( ! $this->is_origin_file_exists( $file_url ) ) {
			return $this->get_trunk_url( $directory_name, $file_path );
		}

		return $file_url;
	}

	private function get_url_content( $url ) {
		if ( ! function_exists( 'download_url' ) ) {
			$ds = DIRECTORY_SEPARATOR;
			require_once ABSPATH . 'wp-admin' . $ds . 'includes' . $ds . 'file.php';
		}

		$tmp = download_url( $url );
		if ( is_wp_error( $tmp ) ) {
			return $tmp;
		}

		$content = file_get_contents( $tmp );
		@unlink( $tmp );

		return $content;
	}

	/**
	 * @param string $parent_action
	 *
	 * @return array|WP_Error
	 */
	public function quarantine( string $parent_action ) {
		if ( ! class_exists( 'WP_Defender\Controller\Quarantine' ) ) {
			return new WP_Error(
				'DEFENDER_PRO_ONLY_FEATURE',
				defender_quarantine_pro_only()
			);
		}

		/**
		 * @var Quarantine_Component
		 */
		$quarantine_component = wd_di()->get( Quarantine_Component::class );

		$action = $quarantine_component->quarantine_file( $this->owner, $parent_action );

		return $action;
	}

	/**
	 * Detect if the plugin file is quarantinable.
	 *
	 * @param string $file_path File path.
	 *
	 * @return bool Return true if file is in wp.org plugin else false.
	 */
	private function is_quarantinable( $file_path ): bool {
		return $this->is_likely_wporg_slug(
			$this->get_plugin_directory_name(
				$file_path
			)
		);
	}
}
