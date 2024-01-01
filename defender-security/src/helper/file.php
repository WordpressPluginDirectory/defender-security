<?php

namespace WP_Defender\Helper;

/**
 * Class consists file related helper utilities.
 */
class File {

	/**
	 * Check is two files identical.
	 *
	 * @param string $local_file File path of the local file for content comparison.
	 * @param string $remote_file Url of the remote file for content comparison.
	 *
	 * @return WP_Error|string If remote fetch fails return WP_Error object or
	 * true for identical file content or false for non identical file content.
	 */
	public function is_identical_content( string $local_file, string $remote_file ) {
		wp_raise_memory_limit();

		$local_file_content = file( $local_file, FILE_IGNORE_NEW_LINES );

		$tmp = download_url( $remote_file );

		if ( is_wp_error( $tmp ) ) {
			return $tmp;
		}

		$remote_file_content = file( $tmp, FILE_IGNORE_NEW_LINES );

		@unlink( $tmp );

		return $local_file_content === $remote_file_content;
	}

	/**
	 * Deny access for the provided directory.
	 *
	 * @since 4.2.0
	 *
	 * @param string $directory File path to the directory.
	 */
	public function maybe_dir_access_deny( string $directory ) {
		$files = [
			[
				'base' => $directory,
				'file' => '.htaccess',
				'content' => 'deny from all',
			],
			[
				'base' => $directory,
				'file' => 'index.html',
				'content' => '',
			],
		];

		foreach ( $files as $file ) {
			if ( ! file_exists( trailingslashit( $file['base'] ) . $file['file'] ) ) {
				$file_handle = @fopen( trailingslashit( $file['base'] ) . $file['file'], 'wb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_read_fopen
				if ( $file_handle ) {
					fwrite( $file_handle, $file['content'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_fwrite
					fclose( $file_handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_fclose
				}
			}
		}
	}
}
