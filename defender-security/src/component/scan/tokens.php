<?php

namespace WP_Defender\Component\Scan;

use WP_Defender\Component;

class Tokens extends Component {
	public static $tokens = [];

	/**
	 * @param $line
	 *
	 * @return array
	 */
	public static function get_tokens_by_line( $line ): array {
		$catch = [];
		foreach ( self::$tokens as $token ) {
			if ( $line === $token['line'] ) {
				$catch[] = $token;
			}
		}

		return $catch;
	}

	/**
	 * @param $tokens
	 *
	 * @return string
	 */
	public static function formatter( $tokens ): string {
		$string = '';
		foreach ( $tokens as $token ) {
			$string .= $token['content'];
		}

		return $string;
	}

	/**
	 * @param $content
	 * @param $offset
	 *
	 * @return int
	 */
	public static function get_line_from_offset( $content, $offset ): int {
		// Polyfill for PHP version < 8.0.
		$offset = max( $offset, 1 );
		[$before] = str_split( $content, $offset );

		return strlen( $before ) - strlen( str_replace( PHP_EOL, '', $before ) ) + 1;
	}

	/**
	 * Get a list of [line,column] of each token. We will need to use this for highlight the code on frontend.
	 *
	 * @param array $tokens
	 *
	 * @return array
	 */
	public static function get_offsets_map( $tokens = [] ): array {
		$tmp = [];
		$mapper = [];
		foreach ( $tokens as $token ) {
			$tmp[ $token['line'] ][] = $token['column'] + $token['length'];
		}
		foreach ( $tmp as $line => &$cols ) {
			sort( $cols );
			$start = count( $cols ) > 1 ? current( $cols ) : 0;
			$range = [ $start, end( $cols ) ];
			$mapper[] = [
				'line' => $line,
				'range' => $range,
			];
		}

		return $mapper;
	}
}
