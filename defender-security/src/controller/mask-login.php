<?php

namespace WP_Defender\Controller;

use Calotes\Component\Request;
use Calotes\Helper\HTTP;
use Calotes\Helper\Route;
use WP_Defender\Component\Config\Config_Hub_Helper;
use WP_Defender\Event;
use Calotes\Component\Response;
use WP_Defender\Traits\IO;
use WP_Defender\Traits\Permission;
use WP_Defender\Model\Setting\Mask_Login as Model_Mask_Login;
use WP_Defender\Component\Mask_Login as Component_Mask_Login;
use WP_User;
use WP_Admin_Bar;
use WP_Defender\Component\Blacklist_Lockout;

/**
 * This going to mask the login url & signup url and prevent directly access in those cases:
 * 1. visit wp-login.php & signup.php or any url with those as suffix.
 * However, we will expose the mask url in:
 * 1. Every login & signup links on frontend, if normal user click on the link, they shouldn't get block
 * 2. Every email sends from WP which contains the login URL, should not get block.
 *
 * Instead of detect if the user logged in or not, we should have a hash of user id and salt for cookies,
 * this way when user direct from other source like back from HUB or so, they won't get lockout.
 *
 * The condition for trigger is when user visit the right mask login, then we will generate.
 *
 * Class Mask_Login
 * @package WP_Defender\Controller
 */
class Mask_Login extends Event {
	use IO, Permission;

	/**
	 * Use for cache.
	 * @var Model_Mask_Login
	 */
	protected $model;

	/**
	 * @var Component_Mask_Login
	 */
	protected $service;

	/**
	 * @var array
	 */
	protected $compatibility_notices = [];

	public function __construct() {
		add_filter( 'wp_defender_advanced_tools_data', [ &$this, 'script_data' ] );
		// Internal cache, so we don't need to query many times.
		$this->model = wd_di()->get( Model_Mask_Login::class );
		$this->service = wd_di()->get( Component_Mask_Login::class );
		$this->register_routes();

		if ( $this->get_model()->is_active() ) {
			$auth_component = wd_di()->get( \WP_Defender\Component\Two_Fa::class );
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
			$is_jetpack_sso = $auth_component->is_jetpack_sso();
			$is_tml = $auth_component->is_tml();
			if ( ! $is_jetpack_sso && ! $is_tml ) {
				// Never catch if from cli.
				if ( ! defender_is_wp_cli() ) {
					add_action( 'init', [ &$this, 'before_mask_login_handle' ], 99 );
				}
				// Monitor wp-admin, wp-login.php.
				add_action( 'init', [ &$this, 'handle_login_request' ], 99 );
				add_filter( 'wp_redirect', [ &$this, 'filter_wp_redirect' ], 10 );
				// Filter site_url & network_site_url so people won't get block screen.
				add_filter( 'site_url', [ &$this, 'filter_site_url' ], 100, 2 );
				add_filter( 'network_site_url', [ &$this, 'filter_site_url' ], 100, 2 );
				// If this is enabled, then we should filter all the email links.
				add_filter( 'wp_mail', [ &$this, 'replace_login_url_in_email' ], 10 );
				// For prevent admin redirect.
				remove_action( 'template_redirect', 'wp_redirect_admin_locations' );
				// If Pro site is activated and user email is not defined, we need to update the email to match the new login URL.
				add_filter( 'update_welcome_email', [ &$this, 'update_welcome_email_prosite_case' ], 10, 6 );
				// Change password link for new user.
				add_filter( 'wp_new_user_notification_email', [ &$this, 'change_new_user_notification_email' ], 10, 3 );
				add_filter( 'lostpassword_redirect', [ &$this, 'change_lostpassword_redirect' ], 10 );
				// Log links in email.
				add_filter( 'report_email_logs_link', [ &$this, 'update_report_logs_link' ], 10, 2 );
				if ( class_exists( 'bbPress' ) ) {
					add_filter( 'bbp_redirect_login', [ &$this, 'make_sure_wpadmin_after_login' ], 10, 3 );
				}

				if ( 'flywheel' === \WP_Defender\Component\Security_Tweaks\Servers\Server::get_current_server() ) {
					if ( ! is_user_logged_in() ) {
						add_action( 'login_form_rp', [ $this, 'handle_password_reset' ] );
						add_action( 'login_form_resetpass', [ $this, 'handle_password_reset' ] );
					}
					add_filter( 'retrieve_password_message', [ &$this, 'flywheel_change_password_message' ], 10, 4 );
				} else {
					// Change password link for exist user.
					add_filter( 'retrieve_password_message', [ &$this, 'change_password_message' ], 10, 4 );
				}

				global $pagenow;
				if ( is_network_admin() && 'sites.php' === $pagenow ) {
					// Add 4th parameter $scheme when the plugin will support WP at least v5.8.
					add_filter( 'admin_url', [ $this, 'change_subsites_admin_url' ], 10, 3 );
				}

				if ( is_admin() && 'my-sites.php' === $pagenow ) {
					add_filter( 'myblogs_blog_actions', [ $this, 'update_myblogs_blog_actions' ], 10, 2 );
				}

				if ( is_multisite() ) {
					add_action( 'admin_bar_menu', [ $this, 'update_admin_bar_menu' ], 100 );
				}

				if ( $this->service->is_set_locale( $this->model->mask_url ) ) {
					add_action( 'init', [ $this, 'set_locale' ] );
				}
			} else {
				if ( $is_jetpack_sso ) {
					$this->compatibility_notices[] = __( "We've detected a conflict with Jetpack's Wordpress.com Log In feature. Please disable it and return to this page to continue setup.", 'defender-security' );
				}
				if ( $is_tml ) {
					$this->compatibility_notices[] = __( "We've detected a conflict with Theme my login. Please disable it and return to this page to continue setup.", 'defender-security' );
				}
			}
		}
	}

	/**
	 * For fixing the issue when bbPress enable, after login, users redirect to home.
	 *
	 * @param string $url
	 * @param string $raw_url
	 * @param object $user
	 *
	 * @return string
	 */
	public function make_sure_wpadmin_after_login( string $url, string $raw_url, object $user ): string {
		if ( home_url() === $url ) {
			$url = admin_url();
		}

		return apply_filters( 'defender_redirect_login', $url, $raw_url, $user );
	}

	/**
	 * We need to filter emails and replace the normal login URL with masked one.
	 *
	 * @param array $attrs
	 *
	 * @return array
	 */
	public function replace_login_url_in_email( array $attrs ): array {
		if ( ! is_array( $attrs ) || ! isset( $attrs['message'] ) ) {
			return $attrs;
		}

		$message = $attrs['message'];
		$site_url = str_replace( '/', '\/', HTTP::strips_protocol( site_url() ) );
		$pattern = '/https?:\/\/' . $site_url . '\/wp-login\.php?[^\s]+/';

		if ( preg_match_all( $pattern, $message, $matches ) ) {
			foreach ( $matches as $match ) {
				foreach ( $match as $url ) {
					$query = wp_parse_url( $url, PHP_URL_QUERY );
					$query = $query ?? '';
					parse_str( $query, $queries );
					if ( is_array( $queries ) && count( $queries ) ) {
						$new_url = add_query_arg( $queries, $this->get_model()->get_new_login_url() );
					} else {
						$new_url = $this->get_model()->get_new_login_url();
					}
					$message = str_replace( $url, $new_url, $message );
				}
			}
		}
		$attrs['message'] = $message;

		return $attrs;
	}

	/**
	 * Show login page.
	 *
	 * @return void
	 */
	public function show_login_page(): void {
		global $error, $interim_login, $action, $user_login, $user, $redirect_to;
		require_once ABSPATH . 'wp-login.php';
		die;
	}

	/**
	 * Before Mask Login handling.
	 *
	 * @since 2.8.0
	 * @return void
	 */
	public function before_mask_login_handle(): void {
		// Some plugins for Cron actions clear HTTP_HOST-param.
		if ( ! isset( $_SERVER['HTTP_HOST'] ) ) {
			$_SERVER['HTTP_HOST'] = '';
		}
		$current_url = set_url_scheme( 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'] );
		$login_url = $this->get_model()->get_new_login_url( $this->get_site_url() );

		if (
			! is_user_logged_in() &&
			'' !== $login_url &&
			! $this->service->is_land_on_masked_url( $this->model->mask_url ) &&
			/**
			 * Filter to redirect current URL to Mask Login URL.
			 *
			 * @param bool   $allowed     Should we redirect to Mask Login URL?.
			 * @param string $current_url Current URL to check.
			 *
			 * @since 2.8.0
			 */
			true === apply_filters( 'wpdef_maybe_redirect_to_mask_login_url', false, $current_url )
		) {
			$modified_url = add_query_arg( 'redirect_to', rawurlencode( $current_url ), $login_url );

			wp_redirect( $modified_url );
			die();
		}
	}

	/**
	 * @param string $location
	 *
	 * @since 4.1.0
	 * @return string|void
	 */
	public function protect_unauthorized_login_redirect( string $location ) {
		// Make sure that wp-login.php is never used in site URLs or redirects.
		if ( ! $this->service->is_login_url() ) {
			$redirect_path = trim( (string) parse_url( $location, PHP_URL_PATH ), '/' );
			if ( $redirect_path === $this->get_model()->mask_url ) {
				$this->maybe_lock();
			}
		}
		return $location;
	}

	/**
	 * If it is request to wp-admin, wp-login.php and similar slugs, we block for sure. If no, then follow the wp flow.
	 *
	 * @return void
	 */
	public function handle_login_request() {
		// If the IP is BLC whitelisted, then skip processing URLs other than the Masked Login URL.
		if ( wd_di()->get( Blacklist_Lockout::class )->is_blc_ip_whitelisted() ) {
			if ( $this->service->is_land_on_masked_url( $this->model->mask_url ) ) {
				$this->show_login_page();
			}

			return;
		}

		// Need to check if the current request is for signup, login.
		// If it is not the slug, then we redirect to the 404 redirect, or 403 wp die.
		$requested_path = $this->service->get_request_path();
		$requested_path_without_slash = ltrim( $requested_path, '/' );
		if ( ! $requested_path_without_slash ) {
			return;
		}

		if ( '/' . ltrim( $this->get_model()->mask_url, '/' ) === $requested_path ) {
			// We need to redirect this one to wp-login and open it.
			return $this->show_login_page();
		}
		/**
		 * Allowed if:
		 * it's AJAX,
		 * the user is logged in,
		 * it's an admin post request.
		*/
		if (
			defined( 'DOING_AJAX' )
			|| is_user_logged_in()
			|| $this->is_allowed_path( $requested_path_without_slash )
		) {
			// Do nothing.
			return;
		}

		// If user is not logged in but login cookie is set.
		if ( isset( $_COOKIE[ LOGGED_IN_COOKIE ] ) && ! is_user_logged_in() ) {
			$user_id = wp_validate_auth_cookie( $_COOKIE[ LOGGED_IN_COOKIE ], 'logged_in' );

			if ( $user_id ) {
				// Cookie is valid so login the user.
				wp_set_current_user( $user_id );
				// Return from here because of valid user found.
				return;
			}
		}

		$ticket = HTTP::get( 'ticket', false );
		// Todo: need if express_tickets are not saved?
		if ( false !== $ticket && $this->service->redeem_ticket( $ticket ) ) {
			// Allow to pass.
			return;
		}

		// If current is same then we show the login screen.
		if ( $this->service->is_land_on_masked_url( $this->model->mask_url ) ) {
			return $this->show_login_page();
		}

		// If it's the verification link to change Network Admin Email.
		$is_multisite = is_multisite();
		$haystack = parse_url( $requested_path, PHP_URL_QUERY );
		if (
			$is_multisite && is_string( $haystack )
			&& false !== strpos( $haystack, 'network_admin_hash' )
		) {
			$logs_url = add_query_arg(
				'redirect_to',
				urlencode( $requested_path ),
				$this->get_model()->get_new_login_url()
			);
			wp_safe_redirect( $logs_url );
			die;
		}
		/**
		 * Block if it's:
		 * 1) no MU but there is an attempt to load the 'wp-signup.php' page,
		 * 2) from the list of forbidden slugs.
		*/
		if (
			( ! $is_multisite && 'wp-signup.php' === $requested_path_without_slash )
			|| $this->service->is_on_login_page( $requested_path_without_slash )
		) {
			// If they are here and the flow getting here, then just lock.
			return $this->maybe_lock();
		}
	}

	/**
	 * Store settings into db.
	 *
	 * @param Request $request Request data.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function save_settings( Request $request ): Response {
		$data = $request->get_data_by_model( $this->model );
		$this->model->import( $data );
		if ( $this->model->validate() ) {
			$this->model->save();
			Config_Hub_Helper::set_clear_active_flag();

			return new Response(
				true,
				array_merge(
					[
						'message' => __( 'Your settings have been updated.', 'defender-security' ),
						'auto_close' => true,
					],
					$this->data_frontend()
				)
			);
		}
		$data_frontend = $this->data_frontend();
		$result['message'] = $this->model->get_formatted_errors();
		//Don't hide the error notice if the module is not activated.
		if ( ! $data_frontend['is_active'] ) {
			$result['auto_close'] = false;
		}
		return new Response(
			false,
			// Merge stored data to avoid errors.
			array_merge( $result, $data_frontend )
		);
	}

	/**
	 * Filter every admin/login URL to return the masked one.
	 *
	 * @param string $site_url The complete URL.
	 * @param string $path     The submitted path.
	 *
	 * @return string
	 */
	public function filter_site_url( string $site_url, string $path ): string {
		return $this->alter_url( $site_url, 'site_url' );
	}

	/**
	 * @param string $location
	 *
	 * @return string
	 */
	public function filter_wp_redirect( string $location ): string {
		return $this->alter_url( $location, 'wp_redirect' );
	}

	/**
	 * @param string $current_url
	 * @param string $source
	 *
	 * @return string|void
	 */
	public function alter_url( string $current_url, string $source ): string {
		if ( is_user_logged_in() && false === stripos( $current_url, 'wp-login.php' ) ) {
			// Do nothing.
			return $current_url;
		}

		if ( 'wp_redirect' === $source && ! is_user_logged_in() ) {
			$parsed_url = wp_parse_url( $current_url );

			$parsed_query = [];
			if ( isset( $parsed_url['query'] ) ) {
				wp_parse_str( $parsed_url['query'], $parsed_query );
			}

			if (
				'wp-login.php' === trim( $parsed_url['path'], '/' ) &&
				isset( $parsed_query['checkemail'] ) && 'registered' === $parsed_query['checkemail']
			) {
				return str_replace( 'wp-login.php', $this->model->mask_url, $current_url );
			}
		}

		if (
			'wp_redirect' === $source &&
			! is_user_logged_in() &&
			! wd_di()->get( Blacklist_Lockout::class )->is_blc_ip_whitelisted()
		) {
			return $this->protect_unauthorized_login_redirect( $current_url );
		}

		if ( false !== stripos( $current_url, 'wp-login.php' ) ) {
			// This is URL go to old wp-login.php.
			$query = wp_parse_url( $current_url, PHP_URL_QUERY );
			$query = $query ?? '';
			parse_str( $query, $params );

			if ( isset( $params['login'] ) ) {
				$params['login'] = rawurlencode( $params['login'] );
			}

			return add_query_arg( $params, $this->get_model()->get_new_login_url( $this->get_site_url() ) );
		} else {
			// This case when admin maps a domain into subsite, we need to update the new domain/masked-login into the list.
			if ( ! function_exists( 'get_current_screen' ) ) {
				require_once( ABSPATH . 'wp-admin/includes/screen.php' );
			}
			$screen = get_current_screen();

			if ( ! is_object( $screen ) ) {
				return $current_url;
			}
			if ( 'sites-network' === $screen->id ) {
				// Case URLs inside sites list, need to check those with custom domain cause when it's redirect, it will require re-login.
				$requested_path = $this->service->get_request_path( $current_url );
				if ( '/wp-admin' === $requested_path ) {
					$current_domain = $_SERVER['HTTP_HOST'];
					$sub_domain = parse_url( $current_url, PHP_URL_HOST );
					if ( ! empty( $sub_domain ) && false === stripos( $sub_domain, $current_domain ) ) {
						return $this->get_model()->get_new_login_url( $sub_domain );
					}
				}
			}
			/**
			 * Todo:
			 * add other condition ('my-sites' === $screen->id),
			 * create OTP key and link with the 'otp' arg inside
			 */
		}

		return $current_url;
	}

	/**
	 * Show the wp die screen for lockout, or redirect to defined URL.
	 *
	 * @return void
	 */
	public function maybe_lock(): void {
		$forbidden_message = __( 'This feature is forbidden temporarily for security reason. Try login again.', 'defender-security' );

		if ( 'custom_url' === $this->get_model()->redirect_traffic && strlen( $this->get_model()->redirect_traffic_url ) ) {
			if ( 'url' === $this->get_model()->is_url_or_slug() ) {
				$redirect_url = wp_sanitize_redirect( $this->get_model()->redirect_traffic_url );
				$lp = @parse_url( $redirect_url );

				// Give up if malformed URL.
				if ( false === $lp ) {
					wp_die( esc_html( $forbidden_message ) );
				}
				// If the URL is without scheme, e.g. example.com, then add 'http' protocol at the beginning of the URL.
				if ( ! isset( $lp['scheme'] ) && isset( $lp['path'] ) ) {
					$redirect_url = 'http://' . untrailingslashit( $redirect_url );
				}
				wp_redirect( $redirect_url );
			} else {
				wp_safe_redirect( home_url( $this->get_model()->redirect_traffic_url ) );
			}
			die;
		}

		if ( 'wp_page' === $this->get_model()->redirect_traffic ) {
			$id = $this->get_model()->redirect_traffic_page_id;
			$post = get_post( $id );
			if ( is_object( $post ) ) {
				wp_safe_redirect( get_permalink( $post ) );
				exit;
			}
		}

		// Handle user profile email change request.
		$this->handle_email_change_request();

		wp_die( esc_html( $forbidden_message ) );
	}

	/**
	 * Safe way to get cached model.
	 *
	 * @return Model_Mask_Login
	 */
	private function get_model() {
		if ( is_object( $this->model ) ) {
			return $this->model;
		}

		return new Model_Mask_Login();
	}

	/**
	 * @param array $data
	 *
	 * @return array
	 * @throws \ReflectionException
	 */
	public function script_data( array $data ): array {
		$data['mask_login'] = $this->data_frontend();

		return $data;
	}

	/**
	 * Login redirect.
	 *
	 * @param string $url
	 * @param string $raw_url Raw url
	 * @param object $user User object
	 *
	 * @return string
	 */
	public function redirect_login( $url, $raw_url, $user ) {
		if ( home_url() === $url ) {
			$url = admin_url();
		}

		return apply_filters( 'defender_redirect_login', $url, $raw_url, $user );
	}

	/**
	 * @param null|int $blog_id
	 * @param string   $path
	 * @param null     $scheme
	 *
	 * @return string
	 */
	private function get_site_url( $blog_id = null, $path = '', $scheme = null ) {
		if ( empty( $blog_id ) || ! is_multisite() ) {
			$url = get_option( 'siteurl' );
		} else {
			switch_to_blog( $blog_id );
			$url = get_option( 'siteurl' );
			restore_current_blog();
		}

		$url = set_url_scheme( $url, $scheme );

		if ( $path && is_string( $path ) ) {
			$url .= '/' . ltrim( $path, '/' );
		}

		/**
		 * Filters the list of plugins for which 'site_url' filter should be skipped.
		 *
		 * @since 4.1.0
		 *
		 * @param array $plugins A list of plugin file paths relative to the plugin's directory.
		 */
		$plugins = apply_filters( 'wd_mask_login_skip_site_url_filter', [ 'wp-ultimo/wp-ultimo.php' ] );
		$skip_site_url_filter = false;
		if ( is_array( $plugins ) ) {
			foreach( $plugins as $plugin ) {
				if ( is_plugin_active( $plugin ) || is_plugin_active_for_network( $plugin ) ) {
					$skip_site_url_filter = true;
					break;
				}
			}
		}

		if ( $skip_site_url_filter ) {
			return apply_filters( 'site_url', $url, $path, $scheme, $blog_id );
		} else {
			return $url;
		}
	}

	public function remove_settings() {}

	public function remove_data() {}

	/**
	 * @return array
	 */
	public function to_array(): array {
		$model = new Model_Mask_Login();
		[$routes, $nonces] = Route::export_routes( 'mask_login' );

		return [
			'enabled' => $model->enabled,
			'useable' => $model->is_active(),
			'login_url' => $model->get_new_login_url(),
			'endpoints' => $routes,
			'nonces' => $nonces,
		];
	}

	/**
	 * @return array
	 */
	public function dashboard_widget(): array {
		$model = new Model_Mask_Login();

		return [
			'model' => $model->export(),
			'is_active' => $model->is_active(),
			'is_mask_url_page_post_exists' => $model->is_mask_url_page_post_exists(),
		];
	}

	/**
	 * @return array
	 */
	public function data_frontend(): array {
		// Don't use cache because wrong url is displayed for forbidden slugs.
		$model = new Model_Mask_Login();

		$data = array_merge(
			[
				'model' => $model->export(),
				'is_active' => $model->is_active(),
				'new_login_url' => $model->get_new_login_url(),
				'notices' => $this->compatibility_notices,
				'is_mask_url_empty' => $model->is_mask_url_empty(),
				'is_mask_url_page_post_exists' => $model->is_mask_url_page_post_exists(),
			],
			$this->dump_routes_and_nonces()
		);

		if ( isset( $data['model']['redirect_traffic_page_id'] ) ) {
			$id = $data['model']['redirect_traffic_page_id'];

			$data['redirect_traffic_page_title'] = $id > 0 ? get_the_title( $id ) : '';
			$data['redirect_traffic_page_url'] = $id > 0 ? get_the_permalink( $id ) : '#';
		}

		return $data;
	}

	/**
	 * @param $data
	 *
	 * @return void
	 */
	public function import_data( $data ): void {
		$model = $this->get_model();

		$model->import( $data );
		if ( $model->validate() ) {
			$model->save();
		}
	}

	/**
	 * @param string $welcome_email
	 * @param int $blog_id
	 * @param int $user_id
	 * @param string $password
	 * @param string $title
	 * @param array $meta
	 *
	 * @return string
	 */
	public function update_welcome_email_prosite_case( string $welcome_email, int $blog_id, int $user_id, string $password, string $title, array $meta ): string {
		$url = get_blogaddress_by_id( $blog_id );
		$welcome_email = str_replace(
			$url . 'wp-login.php',
			$this->get_model()->get_new_login_url( rtrim( $url, '/' ) ),
			$welcome_email
		);

		return $welcome_email;
	}

	/**
	 * @param string $logs_url
	 * @param string $email
	 *
	 * @return string
	 */
	public function update_report_logs_link( string $logs_url, string $email ): string {
		return add_query_arg( 'redirect_to', $logs_url, $this->get_model()->get_new_login_url() );
	}

	/**
	 * Change password URL for new user.
	 *
	 * @param array $wp_new_user_notification_email
	 * @param WP_User $user
	 * @param string $blogname
	 *
	 * @return array
	 */
	public function change_new_user_notification_email( array $wp_new_user_notification_email, WP_User $user, string $blogname ): array {
		$wp_new_user_notification_email['message'] = str_replace(
			network_site_url( 'wp-login.php' ),
			$this->get_model()->get_new_login_url( $this->get_site_url() ),
			$wp_new_user_notification_email['message']
		);

		return $wp_new_user_notification_email;
	}

	/**
	 * Change password URL for existed user if the user login has a space, e.g. 'Test user'.
	 * Change via str_replace() without rawurlencode() doesn't work.
	 *
	 * @param string  $message
	 * @param string  $key
	 * @param string  $user_login
	 * @param WP_User $user_data
	 *
	 * @return string
	 */
	public function change_password_message( string $message, string $key, string $user_login, WP_User $user_data ): string {
		if ( false !== strpos( $user_login, ' ' ) ) {
			$message = str_replace(
				network_site_url( "wp-login.php?action=rp&key=$key&login=" . rawurlencode( $user_login ), 'login' ),
				$this->get_model()->get_new_login_url( $this->get_site_url() )
				. "?action=rp&key=$key&login=" . rawurlencode( $user_login ),
				$message
			);
		}

		return $message;
	}

	/**
	 * @param string  $message
	 * @param string  $key
	 * @param string  $user_login
	 * @param WP_User $user_data
	 *
	 * @since 2.5.5
	 *
	 * @return string
	 */
	public function flywheel_change_password_message( string $message, string $key, string $user_login, WP_User $user_data ): string {
		$message = str_replace(
			network_site_url( "wp-login.php?action=rp&key=$key&login=" . rawurlencode( $user_login ), 'login' ),
			$this->get_model()->get_new_login_url( $this->get_site_url() )
			. "?action=rp&key=$key&login=" . rawurlencode( $user_login ) . '&wd-ml-token=' . rawurlencode( $user_login ),
			$message
		);

		return $message;
	}


	/**
	 * Change redirect param of the link 'Lost your password?'.
	 *
	 * @param string $lostpassword_redirect
	 *
	 * @return string
	 */
	public function change_lostpassword_redirect( string $lostpassword_redirect ): string {
		return $this->get_model()->get_new_login_url( $this->get_site_url() ) . '?checkemail=confirm';
	}

	/**
	 * Handle user profile email change request.
	 *
	 * @return void
	 */
	private function handle_email_change_request() {
		// If it is not for admin request.
		if ( ! is_admin() ) {
			return;
		}

		// If `IS_PROFILE_PAGE` constant is defined.
		if ( ! defined( 'IS_PROFILE_PAGE' ) ) {
			return;
		}

		// If request is not for profile page.
		if ( ! IS_PROFILE_PAGE ) {
			return;
		}

		// If query data is not set.
		if ( ! isset( $_GET['newuseremail'] ) ) {
			return;
		}

		global $wpdb;
		$hash = sanitize_text_field( $_GET['newuseremail'] );
		$like = '%' . $wpdb->esc_like( $hash ) . '%';
		$meta_key = $wpdb->get_var(
			$wpdb->prepare( "SELECT meta_key FROM {$wpdb->usermeta} WHERE meta_value LIKE %s", $like )
		);

		// Hash not found.
		if ( '_new_email' !== $meta_key ) {
			return;
		}

		// Everything good, now redirect user to login page.
		$current_url = add_query_arg( $_GET, admin_url( 'profile.php' ) );
		$redirect_url = esc_url( wp_login_url( $current_url ) );
		wp_redirect( $redirect_url );
		die();
	}

	/**
	 * @return array
	 */
	public function export_strings(): array {

		return [
			$this->get_model()->is_active() ? __( 'Active', 'defender-security' ) : __( 'Inactive', 'defender-security' ),
		];
	}

	/**
	 * @param array $config
	 * @param bool  $is_pro
	 *
	 * @return array
	 */
	public function config_strings( array $config, bool $is_pro ): array {

		return [
			$config['enabled'] ? __( 'Active', 'defender-security' ) : __( 'Inactive', 'defender-security' ),
		];
	}

	/**
	 * Support for the password reset page on various hosting.
	 *
	 * @return void
	 */
	public function handle_password_reset(): void {
		// Get the email link.
		if (
			isset( $_GET['action'], $_GET['key'], $_GET['login'], $_GET['wd-ml-token'] )
			&& 'rp' === $_GET['action']
			&& $_GET['login'] === $_GET['wd-ml-token']
		) {
			$key = wp_unslash( $_REQUEST['key'] );
			$login = wp_unslash( $_REQUEST['login'] );
			$user = check_password_reset_key( $key, $login );
			if ( ! is_wp_error( $user ) ) {
				$value = sprintf( '%s:%s', $login, $key );
				set_site_transient( 'wd-rp-' . COOKIEHASH, $value, 2 * MINUTE_IN_SECONDS );
				wp_safe_redirect( remove_query_arg( [ 'key', 'login', 'wd-ml-token' ] ) );
				exit;
			}
		}
		$value = get_site_transient( 'wd-rp-' . COOKIEHASH );
		// Process the data and display the result.
		if (
			isset( $_GET['action'] )
			&& in_array( $_GET['action'], [ 'rp', 'resetpass' ], true )
			&& isset( $value ) && 0 < strpos( $value, ':' )
		) {
			[$login, $key] = explode( ':', wp_unslash( $value ), 2 );
			$user = check_password_reset_key( $key, $login );
			if ( 'resetpass' === $_GET['action'] ) {
				delete_site_transient( 'wd-rp-' . COOKIEHASH );
			}
			if ( ! is_wp_error( $user ) ) {
				$this->render_partial(
					'mask-login/reset',
					[
						'user' => $user,
					]
				);
				exit;
			}
		}
	}

	/**
	 * Check if a path is allowed without login masking.
	 *
	 * @param string $path Path to check.
	 *
	 * @since 2.6.4
	 * @return bool
	 */
	private function is_allowed_path( string $path ): bool {
		// Admin post requests to admin-post.php should be allowed.
		$allowed = 'wp-admin/admin-post.php' === $path && isset( $_REQUEST['action'] ); // phpcs:ignore

		/**
		 * Filter to allow whitelisting paths from login masking.
		 *
		 * @param bool   $allowed Is current path allowed?.
		 * @param string $path    Path to check.
		 *
		 * @since 2.6.4
		 */
		return apply_filters( 'wd_mask_login_is_allowed_path', $allowed, $path );
	}

	/**
	 * An endpoint for fetching Post/Page.
	 *
	 * @param Request $request Request data.
	 *
	 * @since 2.7.1
	 * @defender_route
	 * @return void
	 */
	public function get_posts( Request $request ): void {
		$data = $request->get_data(
			[
				'per_page' => [
					'type' => 'int',
					'sanitize' => 'sanitize_text_field',
				],
				'search' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
			]
		);

		$per_page = $data['per_page'] ?? 50;
		$search = $data['search'] ?? '';

		add_filter( 'posts_where', [ $this, 'posts_where_title' ], 10, 2 );
		$post_query = new \WP_Query(
			[
				'post_type' => [ 'page', 'post' ],
				'posts_per_page' => $per_page,
				'search_by_post_title' => $search,
				'post_status' => 'publish',
				'orderby' => 'title',
				'order' => 'ASC',
			]
		);
		remove_filter( 'posts_where', [ $this, 'posts_where_title' ], 10 );

		$posts_array = $post_query->posts;
		$data = [];
		foreach ( $posts_array as $post ) {
			$data[] = [
				'id' => $post->ID,
				'name' => $post->post_title,
				'url' => get_the_permalink( $post->ID ),
			];
		}

		wp_send_json_success( $data );
	}

	/**
	 * Filter the WHERE clause of the query.
	 *
	 * @param string $where
	 * @param \WP_Query $wp_query
	 *
	 * @since 2.7.1
	 * @return string $where
	 */
	public function posts_where_title( string $where, \WP_Query $wp_query ): string {
		global $wpdb;

		$search_term = $wp_query->get( 'search_by_post_title' );
		if ( ! empty( $search_term ) ) {
			$where .= ' AND ' . $wpdb->posts . '.post_title LIKE \'%' . esc_sql( $wpdb->esc_like( $search_term ) ) . '%\'';
		}

		return $where;
	}

	/**
	 * Update url to masked login url if domain is mapped.
	 *
	 * @param string   $url
	 * @param string   $path
	 * @param int|null $blog_id
	 *
	 * @return string
	 */
	public function change_subsites_admin_url( string $url, string $path, $blog_id ): string {
		if ( empty( $path ) && ! empty( $blog_id ) ) {
			$mask_url = trim( $this->model->mask_url );

			if ( ! empty( $mask_url ) && $this->check_if_domain_is_mapped( $url ) ) {
				$url = str_replace( 'wp-admin', $mask_url, untrailingslashit( $url ) );
			}
		}
		return $url;
	}

	/**
	 * Check if domain is mapped.
	 *
	 * @param string $url
	 *
	 * @return bool
	 */
	public function check_if_domain_is_mapped( string $url ): bool {
		$is_mapped = false;

		if ( ! empty( $url ) ) {
			$url_arr = wp_parse_url( $url );
			$net_url_arr = wp_parse_url( network_site_url() );

			if (
				! empty( $url_arr['host'] ) &&
				! empty( $net_url_arr['host'] ) &&
				$this->get_domain_from_host( $url_arr['host'] ) !== $this->get_domain_from_host( $net_url_arr['host'] )
			) {
				$is_mapped = true;
			}
		}

		return $is_mapped;
	}

	/**
	 * Extract domain from host.
	 *
	 * @param string $host
	 *
	 * @return string
	 */
	public function get_domain_from_host( string $host ): string {
		$host = strtolower( trim( $host ) );

		$count = substr_count( $host, '.' );
		if ( 2 === $count ) {
			if ( strlen( explode( '.', $host )[1] ) > 3 ) {
				$host = explode( '.', $host, 2 )[1];
			}
		} else if ( $count > 2 ) {
			$host = $this->get_domain_from_host( explode( '.', $host, 2 )[1] );
		}

		return $host;
	}

	/**
	 * Update admin bar menu url to masked login url if domain is mapped.
	 *
	 * @param WP_Admin_Bar $admin_bar
	 *
	 * @since 3.4.0
	 * @return void
	 */
	public function update_admin_bar_menu( WP_Admin_Bar $admin_bar ) {
		$mask_url = trim( $this->model->mask_url );
		if ( empty( $mask_url ) ) {
			return;
		}

		$admin_bar_nodes = $admin_bar->get_nodes();
		$needle = '/wp-admin/';
		$length = strlen( $needle );
		foreach ( $admin_bar_nodes as $nodes ) {
			if ( substr( $nodes->href, -$length ) === $needle && $this->check_if_domain_is_mapped( $nodes->href ) ) {
				$href = str_replace( 'wp-admin', $mask_url, untrailingslashit( $nodes->href ) );

				$admin_bar->add_menu(
					[
						'id' => $nodes->id,
						'href' => $href,
					]
				);
			}
		}
	}

	/**
	 * Update my sites action url to masked login url if domain is mapped.
	 *
	 * @param string $actions
	 * @param object $user_blog
	 *
	 * @since 3.4.0
	 * @return string
	 */
	function update_myblogs_blog_actions( string $actions, object $user_blog ): string {
		$mask_url = trim( $this->model->mask_url );

		if ( empty( $mask_url ) ) {
			return $actions;
		}

		$admin_url = get_admin_url( $user_blog->userblog_id );

		if ( $this->check_if_domain_is_mapped( $admin_url ) ) {
			$updated_admin_url = str_replace( 'wp-admin', $mask_url, untrailingslashit( $admin_url ) );
			$actions = str_replace( $admin_url, $updated_admin_url, $actions );
		}

		return $actions;
	}

	/**
	 * Set locale on Mask Login page.
	 *
	 * @since 3.12.0
	 * @return void
	 */
	public function set_locale(): void {
		$this->service->set_locale();
	}

	/**
	 * Enable/disable module.
	 *
	 * @param Request $request
	 *
	 * @since 3.12.0
	 * @return Response
	 * @defender_route
	 */
	public function toggle_module( Request $request ): Response {
		$data = $request->get_data(
			[
				'enabled' => [
					'type' => 'boolean',
				],
			]
		);

		$this->model->enabled = $data['enabled'];
		$this->model->save();

		Config_Hub_Helper::set_clear_active_flag();

		if ( ! $this->model->enabled || ! $this->model->is_mask_url_page_post_exists() ) {
			return new Response(
				true,
				array_merge(
					[
						'message' => __('Your settings have been updated.', 'defender-security'),
						'auto_close' => true,
					],
					$this->data_frontend()
				)
			);
		}

		return new Response(
			false,
			[
				'error' => __('A page already exists at this URL. Please enter a unique URL for your login area.', 'defender-security'),
			]
		);
	}
}
