<?php

namespace Calotes\Helper;

use Calotes\Base\Component;

/**
 * This is runtime cache, so the cache content will be flush after each refresh.
 *
 * Class Cache
 *
 * @package Calotes\Helper
 */
class Array_Cache extends Component {
	protected static $cached = [];

	/**
	 * @param $name
	 * @param $value
	 * @param $group
	 */
	public static function set( $name, $value, $group = null ) {
		$key = $name . $group;
		self::$cached[ $key ] = $value;
	}

	/**
	 * @param $name
	 * @param $group
	 * @param $default_name
	 *
	 * @return mixed
	 */
	public static function get( $name, $group = null, $default_name = null ) {
		$key = $name . $group;

		return self::$cached[ $key ] ?? $default_name;
	}

	/**
	 * Quick way for append new element to a cached array.
	 *
	 * @param $name
	 * @param $value
	 * @param $group
	 */
	public static function append( $name, $value, $group = null ) {
		$data = self::get( $name, $group, array() );
		if ( is_array( $data ) ) {
			$data[] = $value;
		}
		self::set( $name, $data, $group );
	}

	/**
	 * @param $name
	 * @param $group
	 *
	 * @return bool
	 */
	public static function remove( $name, $group = null ) {
		$key = $name . $group;
		if ( isset( self::$cached[ $key ] ) ) {
			unset( self::$cached[ $key ] );

			return true;
		}

		return false;
	}
}
