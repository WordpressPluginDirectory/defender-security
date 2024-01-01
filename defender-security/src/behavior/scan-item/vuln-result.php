<?php

namespace WP_Defender\Behavior\Scan_Item;

use Calotes\Component\Behavior;
use WP_Defender\Component\Error_Code;
use WP_Defender\Model\Scan;
use WP_Defender\Model\Scan_Item;
use WP_Defender\Traits\Formats;
use WP_Defender\Traits\IO;
use WP_Defender\Traits\Plugin;
use WP_Defender\Traits\Theme;
use WP_Error;

class Vuln_Result extends Behavior {
	use Formats, IO, Plugin, Theme;

	/**
	 * @param array $bugs
	 *
	 * @return string
	 */
	protected function upgrade_possible( array $bugs ): string {
		$upgrade = 'disabled';
		foreach ( $bugs as $bug ) {
			if ( ! empty( $bug['fixed_in'] ) ) {
				$upgrade = 'enabled';
				break;
			}
		}

		return $upgrade;
	}

	/**
	 * @return array
	 */
	public function to_array(): array {
		$data = $this->owner->raw_data;
		if ( isset( $data['name'], $data['version'], $data['bugs'] ) ) {
			if ( 'wp_core' === $data['type'] ) {
				// Check if the current WP version is the latest.
				$upgrade = ( new \WP_Defender\Component\Security_Tweaks\WP_Version() )->check() ? 'disabled' : 'enabled';
			} elseif ( in_array( $data['type'], [ 'plugin', 'theme' ], true ) ) {
				$upgrade = $this->upgrade_possible( $data['bugs'] );
			} else {
				$upgrade = 'disabled';
			}

			return [
				'id' => $this->owner->id,
				'type' => Scan_Item::TYPE_VULNERABILITY,
				'file_name' => $data['name'],
				'short_desc' => sprintf(
				/* translators: %s: Version of WP core, plugin or theme. */
					__( 'Vulnerability found in %s.', 'defender-security' ), $data['version']
				),
				'details' => isset( $data['new_structure'] )
					? $this->get_details_as_array( $data )
					: $this->get_detail_as_string( $data ),
				// Need for all scan items for WP-CLI command. Full path = base slug for this item.
				'full_path' => $data['slug'],
				'new_structure' => isset( $data['new_structure'] ) ? 'yes' : 'no',
				'upgrade' => $upgrade,
			];
		}

		return [];
	}

	/**
	 * @return array
	 */
	public function ignore(): array {
		$scan = Scan::get_last();
		$scan->ignore_issue( $this->owner->id );

		return [
			'message' => __( 'The suspicious file has been successfully ignored.', 'defender-security' ),
		];
	}

	/**
	 * @return array
	 */
	public function unignore(): array {
		$scan = Scan::get_last();
		$scan->unignore_issue( $this->owner->id );

		return [
			'message' => __( 'The suspicious file has been successfully restored.', 'defender-security' ),
		];
	}

	/**
	 * @return array|bool|WP_Error
	 */
	public function resolve() {
		$data = $this->owner->raw_data;
		// Redirect for WordPress-type.
		if ( 'wp_core' === $data['type'] ) {
			return [ 'url' => network_admin_url( 'update-core.php' ) ];
		} elseif ( 'plugin' === $data['type'] ) {
			return $this->upgrade_plugin( $data['slug'] );
		} elseif ( 'theme' === $data['type'] ) {
			return $this->upgrade_theme( $data['base_slug'] );
		}
		// If type does not match.
		return new WP_Error(
			Error_Code::INVALID,
			__( 'Please try again! We could not find the issue type.', 'defender-security' )
		);
	}

	/**
	 * @param $slug
	 *
	 * @return array|bool|WP_Error
	 */
	private function upgrade_theme( $slug ) {
		$skin = new Silent_Skin();
		$upgrader = new \Theme_Upgrader( $skin );
		$ret = $upgrader->upgrade( $slug );

		if ( true === $ret ) {
			$model = Scan::get_last();
			$model->remove_issue( $this->owner->id );

			do_action( 'wpdef_fixed_scan_issue', 'vulnerability', 'resolve' );

			return [ 'message' => __( 'This item has been resolved.', 'defender-security' ) ];
		}

		// This is WP error.
		if ( is_wp_error( $ret ) ) {
			return $ret;
		}
		// Sometimes it returns false because of it could not complete the update process.
		return new WP_Error(
			Error_Code::INVALID,
			__( "We couldn't update your theme. Please try updating with another method.", 'defender-security' )
		);
	}

	/**
	 * @param string $slug
	 *
	 * @return array
	 * @since 2.8.1 Change Upgrade plugin logic.
	 */
	private function upgrade_plugin( $slug ): array {
		$skin = new Plugin_Skin();
		$upgrader = new \Plugin_Upgrader( $skin );
		$result = $upgrader->bulk_upgrade( [ $slug ] );

		if ( is_wp_error( $skin->result ) ) {
			return [
				'type_notice' => 'error',
				'message' => $skin->result->get_error_message(),
			];
		} elseif ( $skin->get_errors()->has_errors() ) {
			return [
				'type_notice' => 'error',
				'message' => $skin->get_error_messages(),
			];
		} elseif ( is_array( $result ) && ! empty( $result[ $slug ] ) ) {
			/*
			 * Plugin is already at the latest version.
			 *
			 * This may also be the return value if the `update_plugins` site transient is empty,
			 * e.g. when you update two plugins in quick succession before the transient repopulates.
			 *
			 * Preferably something can be done to ensure `update_plugins` isn't empty.
			 * For now, surface some sort of error here.
			 */
			if ( true === $result[ $slug ] ) {
				return [
					'type_notice' => 'error',
					'message' => $upgrader->strings['up_to_date'],
				];
			}
			$model = Scan::get_last();
			$model->remove_issue( $this->owner->id );

			do_action( 'wpdef_fixed_scan_issue', 'vulnerability', 'resolve' );

			return [ 'message' => __( 'This item has been resolved.', 'defender-security' ) ];
		} elseif ( false === $result ) {
			return [
				'type_notice' => 'error',
				'message' => __( 'Unable to connect to the filesystem. Please confirm your credentials.', 'defender-security' ),
			];
		}

		return [
			'type_notice' => 'info',
			'message' => __( 'There is no update available for this plugin.', 'defender-security' ),
		];
	}

	/**
	 * @param string $path
	 *
	 * @return bool
	 */
	private function remove_vulnerability( string $path ): bool {
		if ( is_dir( $path ) ) {
			return $this->delete_dir( $path );
		} else {
			// Sometimes a plugin consists of one file.
			return unlink( $path );
		}
	}

	/**
	 * @param array $data
	 *
	 * @return array
	 */
	private function remove_plugin( array $data ): array {
		$active = $this->is_active_plugin( $data['slug'] );
		if ( $active ) {
			return [
				'type_notice' => 'error',
				'message' => __( 'This plugin cannot be removed because it is active.', 'defender-security' ),
			];
		}

		$abs_path = wp_normalize_path( WP_PLUGIN_DIR ) . DIRECTORY_SEPARATOR . $data['base_slug'];
		if ( file_exists( $abs_path ) && ! $this->remove_vulnerability( $abs_path ) ) {
			return [
				'type_notice' => 'error',
				'message' => __( 'Defender does not have enough permission to remove this plugin.', 'defender-security' ),
			];
		}

		$message = sprintf(
		/* translators: %s: Plugin name. */
			__( '%s plugin', 'defender-security' ),
			'<b>' . $data['name'] . '</b>'
		);
		$this->log( $message . 'is deleted', 'scan.log' );
		$model = Scan::get_last();
		$model->remove_issue( $this->owner->id );

		do_action( 'wpdef_fixed_scan_issue', 'vulnerability', 'delete' );

		return [
			'collect_type' => true,
			'message' => $message,
		];
	}

	/**
	 * @param array $data
	 *
	 * @return array
	 */
	private function remove_theme( array $data ): array {
		$active = $this->is_active_theme( $data['base_slug'] );
		if ( $active ) {
			return [
				'type_notice' => 'error',
				'message' => __( 'This theme cannot be removed because it is active.', 'defender-security' ),
			];
		}

		$abs_path = $this->get_path_of_themes_dir() . $data['base_slug'];
		if ( file_exists( $abs_path ) && ! $this->remove_vulnerability( $abs_path ) ) {
			return [
				'type_notice' => 'error',
				'message' => __( 'Defender does not have enough permission to remove this theme.', 'defender-security' ),
			];
		}

		$message = sprintf(
		/* translators: %s: Plugin theme. */
			__( '%s theme', 'defender-security' ),
			'<b>' . $data['name'] . '</b>'
		);
		$this->log( $message . 'is deleted', 'scan.log' );
		$model = Scan::get_last();
		$model->remove_issue( $this->owner->id );

		do_action( 'wpdef_fixed_scan_issue', 'vulnerability', 'delete' );

		return [
			'collect_type' => true,
			'message' => $message,
		];
	}

	/**
	 * @param array $bug
	 *
	 * @return string
	 */
	protected function get_vulnerability_body( array $bug ): string {
		$text = '#' . $bug['title'] . PHP_EOL;
		$text .= '-' . __( 'Vulnerability type:', 'defender-security' ) . ' ' . $bug['vuln_type'] . PHP_EOL;
		if ( empty( $bug['fixed_in'] ) ) {
			$text .= '-' . __( 'No Update Available', 'defender-security' ) . PHP_EOL;
		} else {
			$text .= '-' . __( 'This bug has been fixed in version:', 'defender-security' ) . ' ' . $bug['fixed_in'] . PHP_EOL;
		}

		return $text;
	}

	/**
	 * @param array $data
	 *
	 * @return string
	 */
	public function get_detail_as_string( array $data ): string {
		$strings = [];
		foreach ( $data['bugs'] as $bug ) {
			$strings[] = $this->get_vulnerability_body( $bug );
		}

		return implode( PHP_EOL, $strings );
	}

	/**
	 * @param array $data
	 *
	 * @return array
	 */
	public function get_details_as_array( array $data ): array {
		$arr = [];
		foreach ( $data['bugs'] as $bug ) {
			$text = $this->get_vulnerability_body( $bug );
			$arr[] = [
				'score' => $bug['cvss_score'],
				'detail' => str_replace( PHP_EOL, '<br/>', $text ),
			];
		}

		return $arr;
	}

	/**
	 * Delete inactive plugin or theme.
	 *
	 * @return array|WP_Error
	 */
	public function delete() {
		$data = $this->owner->raw_data;
		// WP core, plugin or theme.
		if ( 'wp_core' === $data['type'] ) {
			return [
				'type_notice' => 'error',
				'message' => __( 'WordPress core cannot be removed.', 'defender-security' ),
			];
		} elseif ( 'plugin' === $data['type'] ) {
			return $this->remove_plugin( $data );
		} elseif ( 'theme' === $data['type'] ) {
			return $this->remove_theme( $data );
		}
		// Sometimes it returns false because of it could not complete the remove process.
		return new WP_Error(
			Error_Code::INVALID,
			__( "We couldn't remove this item.", 'defender-security' )
		);
	}
}

if ( ! class_exists( \WP_Upgrader::class ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
}
if ( ! class_exists( \Theme_Upgrader::class ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-theme-upgrader.php';
}

class Silent_Skin extends \Automatic_Upgrader_Skin {
	public function footer() {
		return;
	}

	public function header() {
		return;
	}

	public function feedback( $data, ...$args ) {
		return '';
	}
}

class Plugin_Skin extends \WP_Ajax_Upgrader_Skin {
	public function feedback( $data, ...$args ) {
		return '';
	}
}
