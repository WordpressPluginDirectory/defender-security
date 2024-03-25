<?php

namespace WP_Defender\Model;

use Calotes\Helper\Array_Cache;
use WP_Defender\DB;
use Calotes\Base\Model;
use WP_Defender\Model\Setting\Blacklist_Lockout;

class Lockout_Ip extends DB {
	public const STATUS_BLOCKED = 'blocked', STATUS_NORMAL = 'normal';

	protected $table = 'defender_lockout';

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
	public $status;
	/**
	 * @var string
	 * @defender_property
	 */
	public $lockout_message;
	/**
	 * @var int
	 * @defender_property
	 */
	public $release_time;
	/**
	 * @since 3.7.0 Used as timestamp for Login/404 lockouts.
	 * @var int
	 * @defender_property
	 */
	public $lock_time;
	/**
	 * Todo: need to use this column less. The lock_time column is used for both lockouts.
	 * @var int
	 * @defender_property
	 */
	public $lock_time_404;
	/**
	 * @var int
	 * @defender_property
	 */
	public $attempt;
	/**
	 * @var int
	 * @defender_property
	 */
	public $attempt_404;
	/**
	 * @var array
	 * @defender_property
	 */
	public $meta = [];
	// Todo: maybe add a new column for type of login-/404-lockouts and remove lock_time_404 & attempt_404 columns?

	/**
	 * Get the record by IP, if it not appears, then create one.
	 *
	 * @param string $ip
	 * @param null|string $status
	 * @param boolean $all
	 *
	 * @return object|null|array
	 */
	public static function get( $ip, $status = null, $all = false ) {
		$model = Array_Cache::get( $ip, 'ip_lockout' );
		if ( is_object( $model ) ) {
			return $model;
		}
		$orm = self::get_orm();
		$builder = $orm->get_repository( Lockout_Ip::class )
				->where( 'ip', $ip );
		if ( null !== $status ) {
			$status = 'unban' === $status ? self::STATUS_BLOCKED : self::STATUS_NORMAL;
			$builder->where( 'status', $status );
		}

		if ( true === $all ) {
			return $builder->get();
		}

		$model = $builder->first();

		if ( ! is_object( $model ) ) {
			$model = new Lockout_Ip();
			$model->ip = $ip;
			$model->attempt = 0;
			$model->status = self::STATUS_NORMAL;
			$model->lockout_message = '';
			$model->release_time = '';
			// @since 3.7.0 The lock_time column is used for both lockouts.
			$model->lock_time = time();
			$model->lock_time_404 = 0;
			$model->attempt_404 = 0;
			$orm->save( $model );
		}

		Array_Cache::set( $ip, $model, 'ip_lockout' );

		return $model;
	}

	/**
	 * Get the first IP.
	 *
	 * @param string $ip
	 *
	 * @return null|Model
	 */
	public static function is_blocklisted_ip( $ip ): ?Model {
		$orm = self::get_orm();

		return $orm->get_repository( self::class )
			->select( 'ip,status' )
			->where( 'ip', $ip )
			->where( 'status', self::STATUS_BLOCKED )
			->first();
	}

	/**
	 * Maybe unblock IP?
	 *
	 * @param string $ip
	 *
	 * @return string
	 */
	public static function get_unlocked_ip_by( $ip ) {
		$orm = self::get_orm();
		$model = $orm->get_repository( self::class )
			->where( 'ip', $ip )
			->first();

		if ( is_object( $model ) ) {
			$model->status = self::STATUS_NORMAL;
			$orm->save( $model );

			return $model->ip;
		}

		return '';
	}

	/**
	 * Get bulk IPs.
	 *
	 * @param string          $status
	 * @param array|null      $ips
	 * @param int|string|null $limit
	 *
	 * @return array
	 */
	public static function get_bulk( string $status, $ips = null, $limit = null ) {
		$orm = self::get_orm();
		$builder = $orm->get_repository( Lockout_Ip::class );
		if ( null === $ips ) {
			$builder->where( 'status', $status );
		}
		if ( null !== $ips ) {
			$builder->where( 'ip', 'in', $ips );
		}
		if ( null !== $limit ) {
			$builder->limit( $limit );
		}

		return $builder->get();
	}

	/**
	 * Get the access status of this IP.
	 *
	 * @return array
	 */
	public function get_access_status(): array {
		$settings = wd_di()->get( Blacklist_Lockout::class );
		if (
			! in_array( $this->ip, $settings->get_list( 'blocklist' ), true )
			&& ! in_array( $this->ip, $settings->get_list( 'allowlist' ), true )
		) {
			return [ 'na' ];
		}

		$result = [];
		if ( in_array( $this->ip, $settings->get_list( 'blocklist' ), true ) ) {
			$result[] = 'banned';
		}
		if ( in_array( $this->ip, $settings->get_list( 'allowlist' ), true ) ) {
			$result[] = 'allowlist';
		}

		return $result;
	}

	/**
	 * Return the IP access status as readable text. The values differ from Table_Lockout:ban_status() method:
	 * 'ban' (STATUS_BAN) --> 'banned',
	 * 'not_ban' (STATUS_NOT_BAN) --> 'na',
	 * 'allowlist' (STATUS_ALLOWLIST) --> 'allowlist'.
	 *
	 * @param string $status
	 *
	 * @return string
	 */
	public function get_access_status_text( string $status ): string {
		switch ( $status ) {
			case 'banned':
				return __( 'Banned', 'defender-security' );
			case 'allowlist':
				return __( 'In Allowlist', 'defender-security' );
			case 'na':
				return __( 'Not banned or in allowlist', 'defender-security' );
			default:
				return '';
		}
	}

	/**
	 * Get locked IPs.
	 *
	 * @return array
	 */
	public static function query_locked_ip(): array {
		$orm = self::get_orm();
		$time = new \DateTime( 'now', wp_timezone() );

		return $orm->get_repository( self::class )
			->select( 'id,ip,status' )
			->where( 'status', self::STATUS_BLOCKED )
			->where( 'release_time', '>', $time->getTimestamp() )
			->group_by( 'ip' )
			->order_by( 'lock_time', 'desc' )
			->get_results();
	}

	/**
	 * @return bool
	 */
	public function is_locked(): bool {
		if ( self::STATUS_BLOCKED === $this->status ) {
			$time = new \DateTime( 'now', wp_timezone() );
			if ( $this->release_time < $time->getTimestamp() ) {
				// Unlock it and clear the metadata.
				$this->attempt = 0;
				$this->meta = [
					'nf' => [],
					'login' => [],
				];
				$this->status = self::STATUS_NORMAL;
				$this->save();

				return false;
			} else {
				return true;
			}
		}

		return false;
	}

	/**
	 * Return remaining release time.
	 *
	 * @return int Remaining release time.
	 */
	public function remaining_release_time(): int {
		$time = new \DateTime( 'now', wp_timezone() );

		return $this->release_time - $time->getTimestamp();
	}

	/**
	 * Remove all records.
	 *
	 * @since 3.3.0
	 * @return bool|int
	 */
	public static function truncate() {
		$orm = self::get_orm();

		return $orm->get_repository( self::class )->truncate();
	}
}
