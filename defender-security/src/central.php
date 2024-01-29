<?php

namespace WP_Defender;

use Calotes\Component\Request;
use Calotes\Component\Response;
use Calotes\Helper\HTTP;
use WP_Defender\Traits\IO;
use WP_Defender\Traits\Permission;

/**
 * This class will act as a central manager, every request must go through this.
 * Also, it should manage the data state of every model too.
 *
 * Class Central
 * @package WP_Defender
 */
class Central extends Component {
	use IO;
	use Permission;

	public const INTERNAL_LOG = 'internal.log';

	/**
	 * This will hold the db data of each module, all data must be getting through this.
	 * @var array
	 */
	protected $states = [];

	/**
	 * This should be constructed only once.
	 */
	public function __construct() {
		$action = defender_base_action();
		add_action( 'wp_ajax_' . $action, [ &$this, 'routing' ] );
		add_action( 'wp_ajax_nopriv_' . $action, [ &$this, 'routing' ] );
	}

	/**
	 * This is a global ajax call, receive all the requests and dispatch to the right controller.
	 */
	public function routing() {
		// This is the intention, we will use it to find the data stored in DI.
		$route = HTTP::get( 'route', false );
		$nonce = HTTP::get( '_def_nonce', false );
		if ( empty( $route ) || empty( $nonce ) ) {
			exit;
		}

		$this->check_opcache();

		$route = wp_unslash( $route );

		if (
			! is_user_logged_in() &&
			$this->is_private_access( $route )
		) {
			$data = [
				'message' => __( 'Your session expired. Please login to continue.', 'defender-security' ),
				'type_notice' => 'session_out',
			];

			if ( $this->is_redirect( $route ) ) {
				$data['redirect'] = wp_login_url( wp_get_referer() );
			}

			wp_send_json_error( $data );
		}

		// Nonce is not valid.
		if ( ! wp_verify_nonce( $nonce, $route ) ) {
			wp_send_json_error(
				[
					'message' => __( 'Invalid API request.', 'defender-security' ),
					'type_notice' => 'invalid_request',
				]
			);
		}

		$key = sprintf( 'controller.%s', $route );

		try {
			$package = wd_di()->get( $key );
			[$class, $method, $is_private] = $package;
			if ( $is_private && ! $this->check_permission() ) {
				wp_send_json_error(
					[
						'message' => __( 'You shall not pass.', 'defender-security' ),
						'type_notice' => 'not_allowed',
					]
				);
			}
			if ( $is_private ) {
				if ( ! wp_next_scheduled( 'defender_hub_sync' ) ) {
					// Sync with HUB on every request it made, but not on public call.
					wp_schedule_single_event( time(), 'defender_hub_sync' );
				}
			}
			$this->execute_intention( $class, $method );
		} catch ( \Exception $e ) {
			$this->log( $e->getMessage(), self::INTERNAL_LOG );
		}
	}

	/**
	 * Execute the method, return should be various base on the method.
	 *
	 * @param string $class_name
	 * @param string $method
	 *
	 * @return Response|void
	 */
	private function execute_intention( $class_name, $method ) {
		$object = wd_di()->get( $class_name );
		if ( is_object( $object ) ) {
			$request = new Request();
			// Because the method is getting params from $_REQUEST directly, we don't need to pass any args, just call.
			// No use reflection method for performance, also this just a simple call.
			// Manipulate the POST as raw data.
			$_POST = $request->get_data();

			return $object->$method( $request );
		} else {
			$this->log( sprintf( 'class not found when executing: %s %s', $class_name, $method ), self::INTERNAL_LOG );
		}
	}

	/**
	 * @param string $method      The function to call.
	 * @param string $class_name  Class name.
	 * @param bool   $is_private  Should this expose for non-auth user.
	 * @param bool   $is_redirect Include redirect URL in response if necessary.
	 *
	 * @return void
	 */
	public function add_route( $method, $class_name, $is_private = true, $is_redirect = false ) {
		$intention = $this->get_intention( $class_name, $method );

		wd_di()->set( sprintf( 'controller.%s', $intention ), [ $class_name, $method, $is_private, $is_redirect ] );
		wd_di()->set( sprintf( 'route.%s', $intention ), $intention );
		wd_di()->set( sprintf( 'nonce.%s', $intention ), wp_create_nonce( $intention ) );
	}

	/**
	 * @param string $method
	 * @param string $class_name
	 *
	 * @return mixed
	 */
	public function get_route( $method, $class_name ) {
		$intention = $this->get_intention( $class_name, $method );

		try {
			return wd_di()->get( sprintf( 'route.%s', $intention ) );
		} catch ( \Exception $e ) {
			$this->log( $e->getMessage(), self::INTERNAL_LOG );
		}
	}

	/**
	 * @param string $method
	 * @param string $class_name
	 *
	 * @return mixed
	 */
	public function get_nonce( $method, $class_name ) {
		$intention = $this->get_intention( $class_name, $method );

		try {
			return wd_di()->get( sprintf( 'nonce.%s', $intention ) );
		} catch ( \Exception $e ) {
			$this->log( $e->getMessage(), self::INTERNAL_LOG );
		}
	}

	/**
	 * Check OPcache is enabled or not.
	 */
	private function check_opcache() {
		if ( $this->is_opcache_save_comments_disabled() ) {
			wp_send_json_error(
				[
					'message' => sprintf(
					/* translators: %s: Name settings. */
						__( '%s is disabled. Please contact your hosting provider to enable it.', 'defender-security' ),
						'<strong>OPcache Save Comments</strong>'
					),
					'type_notice' => 'opcache_disabled',
				]
			);
		}
	}

	/**
	 * Check OPcache is enabled or not.
	 *
	 * @return bool
	 */
	public function is_opcache_save_comments_disabled() {
		// If OPcache is disabled.
		if ( ini_get( 'opcache.enable' ) !== '1' ) {
			return false;
		}

		// If OPcache is enabled and save comments disabled.
		if ( ini_get( 'opcache.save_comments' ) !== '1' ) {
			return true;
		}

		// Any other case.
		return false;
	}

	/**
	 * @return string
	 */
	public function display_opcache_message() {
		return sprintf(
		/* translators: 1. Option settings. 2. Name settings. */
			__( 'We have detected that your %1$s is disabled on your hosting. For Defender to function properly, please contact your hosting provider and ask them to enable %2$s.', 'defender-security' ),
			'<strong>opcache.save_comments</strong>',
			'<strong>OPcache Save Comments</strong>'
		);
	}

	/**
	 * Verify is ajax call is private.
	 * Here private stands for only authenticated user can do ajax call.
	 *
	 * @param string $route Route md5 hash.
	 *
	 * @return bool Return true if the request is private else false.
	 */
	private function is_private_access( $route ) {
		$key = sprintf( 'controller.%s', $route );

		try {
			$package = wd_di()->get( $key );

			return isset( $package[2] ) && $package[2];
		} catch ( \Exception $e ) {
			$this->log( $e->getMessage(), self::INTERNAL_LOG );
		}

		return false;
	}

	/**
	 * Get the intention.
	 *
	 * @param string $class_name
	 * @param string $method
	 *
	 * @since 3.11.0
	 * @return false|string
	 */
	private function get_intention( string $class_name, string $method ) {
		$intention = sprintf( '%s.%s', $class_name, $method );

		if ( ! defined( 'DEFENDER_DEBUG' ) || false === DEFENDER_DEBUG ) {
			$intention = hash( 'md5', $intention );
		}

		return $intention;
	}

	/**
	 * Add redirect URL in response.
	 *
	 * @param string $route Route md5 hash.
	 *
	 * @since 3.11.0
	 * @return bool Return true if redirect URL is required in response else false.
	 */
	private function is_redirect( $route ) {
		$key = sprintf( 'controller.%s', $route );

		try {
			$package = wd_di()->get( $key );

			return isset( $package[3] ) && $package[3];
		} catch ( \Exception $e ) {
			$this->log( $e->getMessage(), self::INTERNAL_LOG );
		}

		return false;
	}
}
