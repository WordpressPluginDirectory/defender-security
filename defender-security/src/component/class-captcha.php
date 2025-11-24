<?php
/**
 * Handles CAPTCHA functionality.
 *
 * @package WP_Defender\Component
 */

namespace WP_Defender\Component;

use Calotes\Base\Component;
use WP_Defender\Integrations\Buddypress;
use WP_Defender\Integrations\Woocommerce;
use WP_Defender\Model\Setting\Captcha as Captcha_Model;

/**
 * Provides methods to handle CAPTCHA integration, including rendering, validation, and script management.
 */
class Captcha extends Component {

	/**
	 * Default form identifiers for CAPTCHA integration.
	 */
	public const DEFAULT_LOGIN_FORM = 'login',
		DEFAULT_REGISTER_FORM       = 'register',
		DEFAULT_LOST_PASSWORD_FORM  = 'lost_password',
		DEFAULT_COMMENT_FORM        = 'comments';

	/**
	 * The CAPTCHA settings model.
	 *
	 * @var Captcha_Model
	 */
	protected Captcha_Model $model;

	/**
	 * WooCommerce integration instance.
	 *
	 * @var Woocommerce|null
	 */
	private ?Woocommerce $woo;
	/**
	 * BuddyPress integration instance.
	 *
	 * @var Buddypress|null
	 */
	private ?Buddypress $buddypress;

	/**
	 * Captcha constructor.
	 *
	 * @param  Captcha_Model $model  The CAPTCHA settings model.
	 */
	public function __construct( Captcha_Model $model ) {
		$this->model      = $model;
		$this->woo        = wd_di()->get( Woocommerce::class );
		$this->buddypress = wd_di()->get( Buddypress::class );
	}

	/**
	 * Determines if any CAPTCHA location is enabled.
	 *
	 * @param  bool $exist_woo  Whether WooCommerce is active.
	 * @param  bool $exist_bp  Whether BuddyPress is active.
	 *
	 * @return bool True if any location is enabled, false otherwise.
	 */
	public function enable_any_location( $exist_woo, $exist_bp ): bool {
		return $this->model->enable_default_location()
				|| $this->model->check_woo_locations( $exist_woo )
				|| $this->model->check_buddypress_locations( $exist_bp );
	}

	/**
	 * Excludes CAPTCHA for specific requests.
	 *
	 * @return bool
	 */
	public function exclude_captcha_for_requests(): bool {
		if ( $this->is_recaptcha_active_provider() ) {
			return $this->exclude_recaptcha_for_requests();
		} else {
			return $this->exclude_cloudflare_turnstile_for_requests();
		}
	}

	/**
	 * Excludes reCAPTCHA for specific requests.
	 *
	 * @return bool
	 */
	private function exclude_recaptcha_for_requests(): bool {
		$current_request   = defender_get_data_from_request( 'REQUEST_URI', 's' ) ?? '/';
		$excluded_requests = (array) apply_filters( 'wd_recaptcha_excluded_requests', array() );

		return in_array( $current_request, $excluded_requests, true );
	}

	/**
	 * Excludes Cloudflare Turnstile for specific requests.
	 *
	 * @return bool
	 * @since v5.7.0.
	 */
	private function exclude_cloudflare_turnstile_for_requests(): bool {
		$current_request   = defender_get_data_from_request( 'REQUEST_URI', 's' ) ?? '/';
		$excluded_requests = (array) apply_filters( 'wd_cloudflare_turnstile_excluded_requests', array() );

		return in_array( $current_request, $excluded_requests, true );
	}

	/**
	 * Removes duplicate CAPTCHA scripts.
	 *
	 * @return bool|void False if no scripts are registered, or void otherwise.
	 */
	public function remove_duplicate_captcha_scripts() {
		global $wp_scripts;

		if ( ! is_object( $wp_scripts ) ) {
			return false;
		}
		/**
		 * Exclude scripts from Defender and Forminator to display reCAPTCHA.
		 *
		 * @since 5.1.0
		*/
		$excluded_handles = (array) apply_filters(
			$this->is_recaptcha_active_provider() ? 'wd_recaptcha_excluded_handles' : 'wd_turnstile_excluded_handles',
			array(
				'wpdef_captcha_api',
				'forminator-google-recaptcha',
				'forminator-turnstile',
			)
		);
		foreach ( $wp_scripts->registered as $script_name => $args ) {
			$search_pattern = $this->is_recaptcha_active_provider() ? '|google\.com/recaptcha/api\.js|' : '|challenges\.cloudflare\.com/turnstile/v0/api\.js|';
			if ( is_string( $args->src ) && preg_match( $search_pattern, $args->src )
				&& ! in_array( $script_name, $excluded_handles, true )
			) {
				wp_dequeue_script( $script_name );
			}
		}
	}

	/**
	 * Returns a custom error message for reCAPTCHA validation failure.
	 *
	 * @return string The formatted error message.
	 */
	public function error_message(): string {
		$default_values = $this->model->get_default_values();
		if ( $this->is_recaptcha_active_provider() ) {
			$message = '' === $this->model->message ? $default_values['message'] : $this->model->message;
		} else {
			$message = array() !== $this->model->data_turnstile && '' !== $this->model->data_turnstile['message'] ? $this->model->data_turnstile['message'] : $default_values['turnstile_message'];
		}
		return sprintf( '<strong>%s:</strong> %s', esc_html__( 'Error', 'defender-security' ), $message );
	}

	/**
	 * Sends an HTTP POST request to the Google reCAPTCHA API and returns the validation result.
	 *
	 * @param  array $post_body  The POST request body.
	 *
	 * @return bool True if the reCAPTCHA validation is successful, false otherwise.
	 */
	public function captcha_post_request( array $post_body ): bool {
		$args    = array(
			'body'      => $post_body,
			'sslverify' => false,
		);
		$url     = $this->is_recaptcha_active_provider() ? 'https://www.google.com/recaptcha/api/siteverify' : 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
		$request = wp_remote_post( $url, $args );

		if ( is_wp_error( $request ) ) {
			return false;
		}

		$response_body = wp_remote_retrieve_body( $request );
		$response_keys = json_decode( $response_body, true );
		if ( 'v3_recaptcha' === $this->model->active_type ) {
			if (
				$response_keys['success']
				&& isset( $this->model->data_v3_recaptcha['threshold'], $response_keys['score'] )
				&& is_numeric( $this->model->data_v3_recaptcha['threshold'] )
				&& is_numeric( $response_keys['score'] )
			) {
				$is_success = $response_keys['score'] >= (float) $this->model->data_v3_recaptcha['threshold'];
			} else {
				$is_success = false;
			}
		} else {
			$is_success = (bool) $response_keys['success'];
		}

		return $is_success;
	}

	/**
	 * Retrieves the list of default forms where CAPTCHA can be integrated.
	 *
	 * @return array An associative array of form identifiers and their display names.
	 */
	public static function get_forms(): array {
		return array(
			self::DEFAULT_LOGIN_FORM         => esc_html__( 'Login', 'defender-security' ),
			self::DEFAULT_REGISTER_FORM      => esc_html__( 'Register', 'defender-security' ),
			self::DEFAULT_LOST_PASSWORD_FORM => esc_html__( 'Lost Password', 'defender-security' ),
			self::DEFAULT_COMMENT_FORM       => esc_html__( 'Comments', 'defender-security' ),
		);
	}
	/**
	 * Validate the token
	 *
	 * @param string $token The token from the admin-side widget.
	 * @return bool Indicating if validation was successful.
	 */
	public function verify_turnstile_key( string $token ): bool {
		$key    = $this->model->data_turnstile['key'] ?? '';
		$secret = $this->model->data_turnstile['secret'] ?? '';
		// Skip validation only if both secret and site key are empty.
		if ( '' === $secret && '' === $key ) {
			return true;
		}
		// If secret key is provided but site key is not (or vice versa), require both.
		if ( '' === $secret || '' === $key ) {
			return false;
		}
		// If no token provided, validation cannot proceed.
		if ( '' === $token ) {
			return false;
		}
		return $this->captcha_post_request(
			array(
				'secret'   => $this->model->data_turnstile['secret'],
				'response' => $token,
			)
		);
	}

	/**
	 * Check if the Google reCAPTCHA is active provider.
	 *
	 * @return bool
	 */
	public function is_recaptcha_active_provider(): bool {
		return 'recaptcha' === $this->model->provider;
	}

	/**
	 * Skip turnstile check as per current sprint plan.
	 *
	 * @return bool true if validation should skip, false otherwise.
	 */
	public function should_skip_turnstile_check(): bool {
		// Only apply for Turnstile provider.
		if ( $this->is_recaptcha_active_provider() ) {
			return false;
		}

		// Skip if neither WooCommerce nor BuddyPress is active.
		if ( ! $this->woo->is_activated() && ! $this->buddypress->is_activated() ) {
			return false;
		}

		// Skip turnstile check if in WooCommerce or BuddyPress login context.
		return $this->woo->is_wc_login_context() || $this->buddypress->is_login_context();
	}
}
