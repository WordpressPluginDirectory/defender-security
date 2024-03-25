<?php

namespace WP_Defender\Model;

use Calotes\Base\Model;
use WP_Defender\DB;

/**
 * @since 4.6.0
 */
class Unlockout extends DB {
	// The anonymous type can be used for unauthorized users in the future.
	public const TYPE_REGISTERED = 'registered', TYPE_ANONYMOUS = 'anonymous';
	public const STATUS_RESOLVED = 'resolved', STATUS_PENDING = 'pending';

	protected $table = 'defender_unlockout';

	/**
	 * @var int
	 * @defender_property
	 */
	public $id;
	/**
	 * @var string
	 * @defender_property
	 */
	public $ip;

	/**
	 * @var string
	 * @defender_property
	 */
	public $type;

	/**
	 * @var string
	 * @defender_property
	 */
	public $email;

	/**
	 * @var string
	 * @defender_property
	 */
	public $status;

	/**
	 * @var int
	 * @defender_property
	 */
	public $timestamp;

	/**
	 * @param string $ip
	 * @param string $email
	 *
	 * @return false|int
	*/
	public function create( $ip, $email ) {
		$this->ip = $ip;
		$this->type = self::TYPE_REGISTERED;
		$this->email = $email;
		$this->status = self::STATUS_PENDING;
		$this->timestamp = time();

		return $this->save();
	}

	/**
	 * Remove data by time period.
	 *
	 * @param int $timestamp
	 * @param int $limit
	 *
	 * @return void
	 */
	public static function remove_records( $timestamp, $limit ) {
		$orm = self::get_orm();
		$orm->get_repository( self::class )
			->where( 'timestamp', '<=', $timestamp )
			->order_by( 'id' )
			->limit( $limit )
			->delete_by_limit();
	}

	/**
	 * Remove all records.
	 *
	 * @return void
	 */
	public static function truncate() {
		$orm = self::get_orm();
		$orm->get_repository( self::class )->truncate();
	}

	/**
	 * Resolve lines by passed args.
	 *
	 * @param int $id
	 * @param string $email
	 * @param int $limit_time
	 *
	 * @return string
	 */
	public static function get_resolved_ip_by( $id, $email, $limit_time ) {
		$orm = self::get_orm();

		$model = $orm->get_repository( self::class )
			->where( 'id', $id )
			->where( 'email', $email )
			->first();

		if ( ! is_object( $model ) ) {
			return '';
		}

		if ( $model->timestamp > $limit_time ) {
			$model->status = self::STATUS_RESOLVED;
			$orm->save( $model );

			return $model->ip;
		} else {
			return 'expired';
		}
	}
}
