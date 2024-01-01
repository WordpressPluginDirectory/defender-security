<?php

namespace WP_Defender;

use Calotes\Base\Model;
use Calotes\DB\Mapper;

class DB extends Model {
	public function __construct() {
		$this->parse_annotations();
	}

	/**
	 * Save the current instance.
	 *
	 * @return false|int
	 */
	public function save() {
		return self::get_orm()->save( $this );
	}

	/**
	 * @return Mapper
	 */
	protected static function get_orm() {
		return wd_di()->get( Mapper::class );
	}

	/**
	 * Get table name.
	 *
	 * @return string
	 */
	public function get_table(): string {
		return $this->table;
	}
}
