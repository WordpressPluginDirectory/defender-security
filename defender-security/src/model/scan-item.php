<?php

namespace WP_Defender\Model;

use WP_Defender\DB;

class Scan_Item extends DB {
	// For 'File change detection' option.
	public const TYPE_INTEGRITY = 'core_integrity', TYPE_PLUGIN_CHECK = 'plugin_integrity';
	// For 'Known vulnerabilities' and 'Suspicious code' options.
	public const TYPE_VULNERABILITY = 'vulnerability', TYPE_SUSPICIOUS = 'malware';
	// Different statuses.
	public const STATUS_ACTIVE = 'active', STATUS_IGNORE = 'ignore';

	protected $table = 'defender_scan_item';
	/**
	 * @var int
	 * @defender_property
	 */
	public $id;
	/**
	 * @var int
	 * @defender_property
	 */
	public $parent_id;
	/**
	 * Type of the issue, base on this we will load the behavior.
	 * @var string
	 * @defender_property
	 */
	public $type;
	/**
	 * Contain generic data.
	 * @var array
	 * @defender_property
	 */
	public $raw_data = [];

	/**
	 * @var string
	 * @defender_property
	 */
	public $status;

	/**
	 * Get the total of each type of provided status either STATUS_ACTIVE or STATUS_IGNORE.
	 *
	 * @param int $parent_id The primary key of the scan table.
	 * @param string $status Acttive or ignore status of scan item(s).
	 *
	 * @return array Return array of group and all total.
	 */
	public function get_types_total( $parent_id, $status ) {
		global $wpdb;

		$table = $wpdb->base_prefix . $this->table;

		$sql = <<<SQL
	SELECT
		IFNULL(`type`, 'all') as `item_type`,
		count(*) as `type_total`
	FROM
		`$table`
	WHERE
		`parent_id` = %d AND `status` = %s
	Group BY
		`type` WITH ROLLUP
SQL;

		$records = $wpdb->get_results(
			$wpdb->prepare( $sql, $parent_id, $status )
		);

		$results = [];
		foreach ( $records as $record ) {
			$results[ $record->item_type ] = (int) $record->type_total;
		}

		return $results;
	}

	public function delete_by_id( int $id ): bool {
		$delete = self::get_orm()->get_repository( self::class )
		->delete( [ 'id' => $id ] );

		return is_int( $delete );
	}
}
