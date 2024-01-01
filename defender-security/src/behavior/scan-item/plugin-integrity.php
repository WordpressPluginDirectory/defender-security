<?php

namespace WP_Defender\Behavior\Scan_Item;

use Calotes\Component\Behavior;
use WP_Defender\Component\Error_Code;
use WP_Defender\Component\Quarantine as Quarantine_Component;
use WP_Defender\Model\Scan;
use WP_Defender\Model\Scan_Item;
use WP_Defender\Traits\Formats;
use WP_Defender\Traits\IO;
use WP_Defender\Traits\Plugin;
use WP_Error;

class Plugin_Integrity extends Behavior {
	use Formats, IO, Plugin;

	/**
	 * Return general data so we can output on frontend.
	 *
	 * @return array
	 */
	public function to_array(): array {
		$data = $this->owner->raw_data;
		$file = $data['file'];
		$file_created_at = @filemtime( $file );
		if ( $file_created_at ) {
			$file_created_at = $this->format_date_time( $file_created_at );
		} else {
			$file_created_at = 'n/a';
		}
		$file_size = @filesize( $file );
		if ( ! $file_size ) {
			$file_size = 'n/a';
		} else {
			$file_size = $this->format_bytes_into_readable( $file_size );
		}

		$is_quarantinable = $this->is_quarantinable( $this->owner->raw_data['file'] );

		$quarantine_data = class_exists( 'WP_Defender\Component\Quarantine' ) ?
			wd_di()->get( Quarantine_Component::class )->scan_item_data( $this->owner ) :
			[ 'is_quarantinable' => $is_quarantinable ];

		return array_merge(
			[
				'id' => $this->owner->id,
				'type' => Scan_Item::TYPE_PLUGIN_CHECK,
				'file_name' => pathinfo( $file, PATHINFO_BASENAME ),
				'full_path' => $file,
				'date_added' => $file_created_at,
				'size' => $file_size,
				'scenario' => $data['type'],
				'short_desc' => $this->get_short_description(),
			],
			$quarantine_data
		);
	}

	/**
	 * We will get the origin code by looking into svn repo.
	 *
	 * @return false|string|WP_Error
	 */
	private function get_origin_code() {
		$file = $this->owner->raw_data['file'];

		$directory_name = $this->get_plugin_directory_name( $file );
		$plugin_header = $this->get_plugin_headers( $file );
		$plugin_header = reset( $plugin_header );
		$file_path = $this->get_plugin_relative_path( $file );

		$source_file_url = $this->get_file_url(
			$directory_name,
			$plugin_header['Version'],
			$file_path
		);

		return $this->get_url_content( $source_file_url );
	}

	/**
	 * Restore the file with its origin content.
	 *
	 * @return void|array|WP_Error
	 */
	public function resolve() {
		$data = $this->owner->raw_data;
		if ( 'modified' !== $data['type'] ) {
			// Should not be here unless case changed.
			return;
		}

		$origin = $this->get_origin_code();
		if ( false === $origin || is_wp_error( $origin ) ) {
			return;
		}

		$path = $data['file'];
		$ret = @file_put_contents( $path, $origin );// phpcs:ignore
		if ( $ret ) {
			$scan = Scan::get_last();
			$scan->remove_issue( $this->owner->id );
			$this->log( sprintf( '%s is deleted', $path ), 'scan.log' );

			do_action( 'wpdef_fixed_scan_issue', 'plugin_integrity', 'resolve' );

			return [ 'message' => __( 'This item has been resolved.', 'defender-security' ) ];
		} else {
			return new WP_Error(
				'defender_permissions_denied',
				__( 'Permissions Denied. Defender does not have the needed permissions to edit the file. Please change file permissions to 640 or contact your hosting provider so they could change them for you.', 'defender-security' )
			);
		}
	}

	/**
	 * @return array
	 */
	public function ignore(): array {
		$scan = Scan::get_last();
		$scan->ignore_issue( $this->owner->id );

		return [ 'message' => __( 'The suspicious file has been successfully ignored.', 'defender-security' ) ];
	}

	/**
	 * @return array
	 */
	public function unignore(): array {
		$scan = Scan::get_last();
		$scan->unignore_issue( $this->owner->id );

		return [ 'message' => __( 'The suspicious file has been successfully restored.', 'defender-security' ) ];
	}

	/**
	 * Delete the file or whole folder.
	 *
	 * @return array|WP_Error
	 */
	public function delete() {
		$data = $this->owner->raw_data;
		$scan = Scan::get_last();
		if ( 'unversion' === $data['type'] && unlink( $data['file'] ) ) {
			$scan->remove_issue( $this->owner->id );
			$this->log( sprintf( '%s is deleted', $data['file'] ), 'scan.log' );

			do_action( 'wpdef_fixed_scan_issue', 'plugin_integrity', 'delete' );

			return [ 'message' => __( 'This item has been permanently removed.', 'defender-security' ) ];
		} elseif ( 'dir' === $data['type'] && $this->delete_dir( $data['file'] ) ) {
			$scan->remove_issue( $this->owner->id );
			$this->log( sprintf( '%s is deleted', $data['file'] ), 'scan.log' );

			do_action( 'wpdef_fixed_scan_issue', 'plugin_integrity', 'delete' );

			return [ 'message' => __( 'This item has been permanently removed.', 'defender-security' ) ];
		}

		return new WP_Error(
			Error_Code::NOT_WRITEABLE,
			__( 'Defender doesn\'t have enough permission to remove this file.', 'defender-security' )
		);
	}

	/**
	 *  Return the source code depending on the type of the issue.
	 *
	 * @return array
	 */
	public function pull_src(): array {
		$data = $this->owner->raw_data;
		if ( ! file_exists( $data['file'] ) && ! is_dir( $data['file'] ) ) {
			return [
				'code' => '',
				'origin' => '',
			];
		}
		switch ( $data['type'] ) {
			case 'unversion':
				return [ 'code' => file_get_contents( $data['file'] ) ];
			case 'dir':
				$dir_tree = new File( $data['file'], true, true, [], [], false );

				return [ 'code' => implode( PHP_EOL, $dir_tree->get_dir_tree() ) ];
			case 'modified':
			default:
				return [
					'code' => file_get_contents( $data['file'] ),
					'origin' => $this->get_origin_code(),
				];
		}
	}

	/**
	 * @return string
	 */
	private function get_short_description(): string {
		$data = $this->owner->raw_data;
		if ( 'unversion' === $data['type'] ) {
			return esc_html__( 'Unknown file in the WordPress plugin', 'defender-security' );
		} elseif ( 'dir' === $data['type'] ) {
			return esc_html__( 'This directory does not belong to the WordPress plugin', 'defender-security' );
		} elseif ( 'modified' === $data['type'] ) {
			return esc_html__( 'This plugin file appears modified', 'defender-security' );
		}
	}
}
