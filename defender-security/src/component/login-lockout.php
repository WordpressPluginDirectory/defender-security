<?php

namespace WP_Defender\Component;

use WP_Defender\Model\Lockout_Ip;
use WP_Defender\Model\Lockout_Log;
use WP_Defender\Component\User_Agent;
use WP_Error;

/**
 * This class will handle the logic lockout when too many failed login attempts.
 *
 * Class Login_Lockout
 *
 * @package WP_Defender\Component
 */
class Login_Lockout extends \WP_Defender\Component {
	use \WP_Defender\Traits\Country;

	public const SCENARIO_LOGIN_FAIL = 'login_fail', SCENARIO_LOGIN_LOCKOUT = 'login_lockout', SCENARIO_BAN = 'login_ban';

	/**
	 * @var \WP_Defender\Model\Setting\Login_Lockout
	 */
	protected $model;

	/**
	 * @var Blacklist_Lockout
	 */
	protected $service;

	/**
	 * @var string
	 */
	protected $banned_username_message;

	/**
	 * @var array
	 */
	protected $ip;

	public function __construct() {
		// Todo: maybe add model and ip-params?
		$this->model = wd_di()->get( \WP_Defender\Model\Setting\Login_Lockout::class );
		$this->service = wd_di()->get( Blacklist_Lockout::class );
		$this->banned_username_message = __(
			'You have been locked out by the administrator for attempting to login with a banned username.',
			'defender-security'
		);
		$this->ip = $this->get_user_ip();
	}

	/**
	 * Adding main hooks.
	 */
	public function add_hooks() {
		global $wp_version;

		if ( isset( $wp_version ) && version_compare( $wp_version, '5.4.0', '>=' ) ) {
			add_action( 'wp_login_failed', [ &$this, 'process_fail_attempt' ], 10, 2 );
		} else {
			add_action( 'wp_login_failed', [ &$this, 'process_fail_attempt_compatibility' ], 10 );
		}

		add_filter( 'authenticate', [ &$this, 'show_attempt_left' ], 9999, 2 );
		add_action( 'wp_login', [ &$this, 'clear_login_attempt' ] );
		add_action( 'wd_2fa_lockout', [ &$this, 'two_factor_lockout' ], 10, 3 );
	}

	/**
	 * When a user logins successfully, we need to clear the info of failed login attempt.
	 * So it won't affect the next time that user logins again.
	 */
	public function clear_login_attempt() {
		// Record this.
		foreach ( $this->ip as $ip ) {
			$model = Lockout_Ip::get( $ip );
			if ( is_object( $model ) ) {
				$model->meta = [];
				$model->attempt = 0;
				$model->save();
			}
		}
	}

	/**
	 * Show a message to tell user how many attempt they have until get lockout.
	 *
	 * @param \WP_User|WP_Error|null $user
	 * @param string                 $username
	 *
	 * @return \WP_User|WP_Error|null
	 */
	public function show_attempt_left( $user, $username ) {
		if ( ! is_wp_error( $user ) && $user instanceof \WP_User
			&& in_array( $username, $this->model->get_blacklisted_username(), true )
		) {
			// The case#1 of an existing user who has a banned username.
			$msg = sprintf(
				'<strong>%s:</strong> %s',
				__( 'Error', 'defender-security' ),
				$this->banned_username_message
			);
			$errors = new WP_Error();
			$errors->add( 'def_login_banned_user', $msg );

			return $errors;
		} elseif ( 'POST' === $_SERVER['REQUEST_METHOD']
			&& is_wp_error( $user )
			&& ! in_array(
				$user->get_error_code(),
				[ 'empty_username', 'empty_password' ],
				true
			)
		) {
			// The case#2 of a non-existent user who has a banned username.
			if ( in_array( $username, $this->model->get_blacklisted_username(), true ) ) {
				$msg = $this->banned_username_message;
				$user->add( 'def_login_attempt', $msg );

				return $user;
			}
			// This hook is before the @process_fail_attempt, so we will need to add 1 into the attempt count.
			$attempt = $this->get_max_attempt();
			++ $attempt;
			if ( $attempt < $this->model->attempt ) {
				$user->add(
					'def_login_attempt',
					sprintf(
					/* translators: %d: Count of attempts. */
						__( '%d login attempts remaining', 'defender-security' ), $this->model->attempt - $attempt
					)
				);
			} else {
				$user->add( 'def_login_attempt', $this->model->lockout_message );
			}
		}

		return $user;
	}

	/**
	 * Backward compatibility with WP version older than 5.4.
	*/
	public function process_fail_attempt_compatibility( $username ) {
		if ( empty( $username ) ) {
			return;
		}

		if ( in_array( $username, $this->model->get_blacklisted_username(), true ) ) {
			$msg = sprintf(
				'<strong>%s:</strong> %s',
				__( 'Error', 'defender-security' ),
				$this->banned_username_message
			);
			$errors = new WP_Error( 'def_login_banned_user', $msg );
		} else {
			$errors = new WP_Error( 'dummy_failed', __( 'Dummy data.', 'defender-security' ) );
		}

		$this->process_fail_attempt( $username, $errors );
	}

	/**
	 * @param Lockout_Ip $model
	 *
	 * @return Lockout_Ip
	 */
	protected function check_meta_data( &$model ) {
		if (
			! isset( $model->meta['login'] ) ||
			( isset( $model->meta['login'] ) && ! is_array( $model->meta['login'] ) )
		) {
			$model->meta['login'] = [];
		}

		return $model;
	}

	/**
	 * From here, we will:
	 *  1. Record the attempt.
	 *  2. Log it.
	 *  3. Do condition check if we should block or not.
	 *
	 * @param string   $username
	 * @param WP_Error $error
	 */
	public function process_fail_attempt( $username, $error ) {
		if ( empty( $username ) ) {
			return;
		}

		foreach ( $this->ip as $ip ) {
			if ( $this->service->is_ip_whitelisted( $ip ) ) {
				continue;
			}
			// Record this.
			$model = Lockout_Ip::get( $ip );
			$model = $this->record_fail_attempt( $ip, $model );
			// Avoid duplicate logs.
			if ( 'def_login_banned_user' !== $error->get_error_code() ) {
				$this->log_event( $ip, $username, self::SCENARIO_LOGIN_FAIL );
			}
			// Now check, if it is in a banned username.
			$ls = $this->model;
			if ( in_array( $username, $ls->get_blacklisted_username(), true ) ) {
				$model->lockout_message = $this->banned_username_message;
				$model->status = Lockout_Ip::STATUS_BLOCKED;
				$model->save();
				$this->log_event( $ip, $username, self::SCENARIO_BAN );

				do_action( 'wd_login_lockout', $model, self::SCENARIO_BAN );
				do_action( 'wd_blacklist_this_ip', $ip );

				continue;
			}
			// So if we can lock.
			$window = strtotime( '-' . $ls->timeframe . 'seconds' );

			$model = $this->check_meta_data( $model );
			// We will get the latest till oldest, limit by attempt.
			$checks = array_slice( $model->meta['login'], $ls->attempt * -1 );

			if ( count( $checks ) < $ls->attempt ) {
				// Do nothing.
				continue;
			}
			// if the last time is larger.
			$check = min( $checks );
			if ( $check >= $window ) {
				if ( 'permanent' === $ls->lockout_type ) {
					$model->attempt = 0;
					$model->meta['login'] = [];
					$model->save();

					do_action( 'wd_blacklist_this_ip', $ip );
				} else {
					// Lockable.
					$model->status = Lockout_Ip::STATUS_BLOCKED;
					$model->lock_time = time();

					$this->create_blocked_lockout(
						$model,
						$ls->lockout_message,
						strtotime( '+' . $ls->duration . ' ' . $ls->duration_unit )
					);
				}
				// Need to create a log.
				$this->log_event( $ip, $username, self::SCENARIO_LOGIN_LOCKOUT );
				do_action( 'wd_login_lockout', $model, self::SCENARIO_LOGIN_LOCKOUT );
			}
		}
	}

	public function create_blocked_lockout( &$model, $message, $time ) {
		$model->lockout_message = $message;
		$model->release_time = $time;
		$model->save();
	}

	/**
	 * @param int    $user_id
	 * @param string $message
	 * @param int    $time_limit
	 */
	public function two_factor_lockout( $user_id, $message, $time_limit ) {
		// Prepare a record for Lockout_IP.
		$start_time = time();
		$user = get_user_by( 'id', $user_id );
		$def_values = $this->model->get_default_values();

		$ips = array_filter( $this->ip, function( $ip ) {
			return ! $this->service->is_ip_whitelisted( $ip );
		});
		$models = Lockout_Ip::get_bulk( '', $ips );
		foreach ( $models as $model ) {
			$model->status = Lockout_Ip::STATUS_BLOCKED;
			$model->lock_time = $start_time;
			$model = $this->check_meta_data( $model );
			$model->meta['login'][] = $start_time;

			$this->create_blocked_lockout( $model, $def_values['message'], $start_time + $time_limit );
			$this->log_event( $model->ip, $user->user_login ?? '', self::SCENARIO_LOGIN_LOCKOUT, $message );
			// No need to add the current IP to blocklisted.
		}
	}

	/**
	 * Store the failed attempt of current IP.
	 *
	 * @param string     $ip
	 * @param Lockout_Ip $model
	 *
	 * @return Lockout_Ip
	 */
	protected function record_fail_attempt( $ip, $model ): Lockout_Ip {
		$model->attempt += 1;
		$model->ip = $ip;

		$model = $this->check_meta_data( $model );
		// Cache the time here, so it consumes less memory than query the logs.
		$model->meta['login'][] = time();
		$model->save();

		return $model;
	}

	/**
	 * Log the current event.
	 * We have 3 type of event:
	 *  1. Fail attempt.
	 *  2. Too many fails, get lock.
	 *  3. Login with banned username.
	 *
	 * @param string $ip
	 * @param string $username
	 * @param string $scenario
	 * @param string $message
	 */
	public function log_event( $ip, $username, $scenario, $message = '' ) {
		$model = new Lockout_Log();
		$model->ip = $ip;
		$model->user_agent = isset( $_SERVER['HTTP_USER_AGENT'] )
			? User_Agent::fast_cleaning( $_SERVER['HTTP_USER_AGENT'] )
			: null;
		$model->date = time();
		$model->tried = $username;
		$model->blog_id = get_current_blog_id();

		$ip_to_country = $this->ip_to_country( $ip );

		if ( ! empty( $ip_to_country ) && isset( $ip_to_country['iso'] ) ) {
			$model->country_iso_code = $ip_to_country['iso'];
		}

		switch ( $scenario ) {
			case self::SCENARIO_LOGIN_FAIL:
				$model->type = Lockout_Log::AUTH_FAIL;
				$model->log = sprintf(
				/* translators: %s: Username. */
					esc_html__( 'Failed login attempt with username %s', 'defender-security' ),
					$username
				);
				break;
			case self::SCENARIO_BAN:
				$model->type = Lockout_Log::AUTH_LOCK;
				$model->log = sprintf(
				/* translators: %s: Username. */
					esc_html__( 'Failed login attempt with a ban username %s', 'defender-security' ),
					$username
				);
				break;
			case self::SCENARIO_LOGIN_LOCKOUT:
			default:
				$model->type = Lockout_Log::AUTH_LOCK;
				$model->log = ( '' !== $message )
					? $message
					: __( 'Lockout occurred: Too many failed login attempts', 'defender-security' );
				break;
		}
		$model->save();
		if ( Lockout_Log::AUTH_LOCK === $model->type ) {
			do_action( 'defender_notify', 'firewall-notification', $model );
		}
	}

	/**
	 * Get the max attempt from the list of IPs.
	 *
	 * @since 4.4.2
	 * @return int
	 */
	public function get_max_attempt(): int {
		$attempt = 0;
		$models = Lockout_Ip::get_bulk( '', $this->ip );

		foreach ( $models as $model ) {
			if ( isset( $model->attempt ) && $attempt < $model->attempt ) {
				$attempt = $model->attempt;
			}
		}

		return $attempt;
	}
}
