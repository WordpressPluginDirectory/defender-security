<?php

namespace WP_Defender\Component;

use WP_Defender\Component;
use WP_Defender\Model\Lockout_Log;

class Firewall_Logs extends Component {

	/**
	 * Fetch compact Firewall logs.
	 *
     * @param int $from  Fetch Logs from this time to current time.
     *
	 * @return array
	 */
	public function get_compact_logs( int $from ): array {
		global $wpdb;

		$table = $wpdb->base_prefix . ( new Lockout_Log() )->get_table();
		$sql = $wpdb->prepare(
			"SELECT IP, `type`, COUNT(*) AS frequency, country_iso_code FROM {$table}" .
			" WHERE `date` >= %s AND type IN ('auth_fail', '404_error', 'ua_lockout')" .
			" GROUP BY IP, `type`",
			$from
        );
        $results = $wpdb->get_results( $sql, ARRAY_A );

        $logs = [];
        if ( is_array( $results ) ) {
            foreach ( $results as $row ) {
                $ip = $row['IP'];
                if ( ! isset( $logs[ $ip ] ) ) {
                    $logs[ $ip ] = ['ip' => $ip];
                }

                $type = '';
                if( 'auth_fail' === $row['type'] ) {
                    $type = 'login';
                } else if ( '404_error' === $row['type'] ) {
                    $type = 'nf';
                } else if ( 'ua_lockout' === $row['type'] ) {
                    $type = 'ua';
                }

                if ( empty( $type ) ) {
                    continue;
                }

                $logs[ $ip ]['reason'][ $type ] = $row['frequency'];
                $logs[ $ip ][ 'country_code' ] = $row['country_iso_code'];
            }
        }

        return array_values( $logs );
	}
}
