<?php

namespace WP_Defender\Traits;

use WP_Defender\Component\Error_Code;
use WP_Defender\Model\Scan;
use WP_Error;

trait File_Operations {

	/**
	 * Deletes a file if it exists and is writable.
	 *
	 * @param string $file The path to the file to be deleted.
	 *
	 * @return bool Returns true if the file was successfully deleted, false otherwise.
	 */
	public function delete_infected_file( string $file ): bool {
		return file_exists( $file ) && is_writable( $file ) && unlink( $file );
	}

	/**
	 * Handle actions after deleting a file or folder.
	 *
	 * @param string $deleted_file The file or folder that was deleted.
	 * @param Scan|null $related_scan The scan instance related to the deletion.
	 * @param string $scan_type The type of scan.
	 *
	 * @return array An array with a message confirming the deletion.
	 */
	public function after_delete( string $deleted_file, ?Scan $related_scan, string $scan_type ): array {
		$this->log( sprintf( '%s is deleted', $deleted_file ), 'scan.log' );
		$related_scan->remove_issue( $this->owner->id );
		do_action( 'wpdef_fixed_scan_issue', $scan_type, 'delete' );

		return [ 'message' => __( 'This item has been permanently removed', 'defender-security' ) ];
	}

	/**
	 * Returns a WP_Error object with an error code indicating that the file is not writeable.
	 *
	 * @param string $file The path to the file that is not writeable.
	 * @return WP_Error The WP_Error object with the error code and the basename of the file.
	 */
	public function get_permission_error( string $file ): WP_Error {
		return new WP_Error( Error_Code::NOT_WRITEABLE, wp_basename( $file ) );
	}
}
