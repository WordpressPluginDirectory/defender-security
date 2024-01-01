<?php

namespace Calotes\Component;

use Calotes\Base\Model;
use Calotes\Helper\HTTP;

/**
 * This will be passed to every defender_route.
 * This will get data from _POST or _GET and sanitize it before land to the actual process method.
 *
 * Class Request
 * @package Calotes\Component
 */
class Request {
	/**
	 * Store the data from request.
	 *
	 * @var array
	 */
	protected $data = [];

	public function __construct() {
		if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			$raw_data = HTTP::post( 'data', '' );
		} else {
			$raw_data = HTTP::get( 'data', '' );
		}
		if ( is_string( $raw_data ) ) {
			$this->data = json_decode( $raw_data, true );
		}
	}

	/**
	 * Retrieve the data that will be in use, it's recommended that $filters should be provided for data validation and cast.
	 *
	 * @param array $filters
	 *
	 * @return array
	 */
	public function get_data( $filters = [] ) {
		if ( empty( $filters ) ) {
			return $this->data;
		}
		$data = [];
		foreach ( $filters as $key => $rule ) {
			if ( ! isset( $this->data[ $key ] ) ) {
				continue; // Moving on.
			}
			// Mandatory.
			$type = $rule['type'];
			$sanitize = $rule['sanitize'] ?? null;

			$value = $this->data[ $key ];
			// Cast.
			settype( $value, $type );
			if ( ! is_array( $sanitize ) ) {
				$sanitize = [ $sanitize ];
			}
			foreach ( $sanitize as $function ) {
				if ( null !== $function && function_exists( $function ) ) {
					if ( is_array( $value ) ) {
						$value = $this->sanitize_array( $value, $function );
					} else {
						$value = $function( $value );
					}
				}
			}
			$data[ $key ] = $value;
		}

		return $data;
	}

	/**
	 * @param $arr
	 * @param $sanitize
	 *
	 * @return mixed
	 */
	protected function sanitize_array( $arr, $sanitize ) {
		foreach ( $arr as &$value ) {
			if ( is_array( $value ) ) {
				$value = $this->sanitize_array( $value, $sanitize );
			} else {
				$value = $sanitize( $value );
			}
		}

		return $arr;
	}

	/**
	 * Get the data from _REQUEST.
	 *
	 * @param Model $model
	 *
	 * @return array
	 */
	public function get_data_by_model( Model $model ) {
		return $this->get_data( $model->annotations );
	}
}
