<?php

namespace WP_Defender\Component\Two_Factor\Providers;

use Calotes\Helper\HTTP;
use WP_Defender\Component\Two_Fa as Two_Fa_Component;
use WP_Defender\Component\Crypt;
use WP_Defender\Component\Two_Factor\Two_Factor_Provider;
use WP_Defender\Extra\Base2n;
use WP_Defender\Traits\IO;
use WP_User;
use WP_Error;

/**
 * Class Totp
 * Note: key 'defenderAuthOn' only for TOTP method.
 *
 * @since 2.8.0
 * @package WP_Defender\Component\Two_Factor\Providers
 */
class Totp extends Two_Factor_Provider {
	use IO;

	/**
	 * 2fa provider slug.
	 *
	 * @var string
	 */
	public static $slug = 'totp';

	/**
	 * @var string
	 */
	public const TOTP_AUTH_KEY = 'defenderAuthOn';

	/**
	 * Used def.key before v3.4.0.
	 *
	 * @var string
	 */
	public const TOTP_SECRET_KEY = 'defenderAuthSecret';

	/**
	 * Use Sodium library since v3.4.0.
	 *
	 * @var string
	 */
	public const TOTP_SODIUM_SECRET_KEY = 'defenderAuthSodiumSecret';

	/**
	 * @var string
	 */
	public const TOTP_FORCE_KEY = 'defenderForceAuth';

	/**
	 * @var int
	 */
	public const TOTP_DIGIT_COUNT = 6;

	/**
	 * @var int
	 */
	public const TOTP_TIME_STEP_SEC = 30;

	/**
	 * @var int
	 */
	public const TOTP_LENGTH = 16;

	/**
	 * RFC 4648 base32 alphabet.
	 * @var string
	 */
	public const TOTP_CHARACTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * @var string
	 */
	public const DEFAULT_CRYPTO = 'sha1';

	/**
	 * 1 = 30 second range for authenticator.
	 * @var int
	*/
	public const TOTP_TIME_STEP_ALLOWANCE = 1;

	protected $label;

	protected $description;

	public function __construct() {
		add_action( 'wd_2fa_init_provider_' . self::$slug, [ &$this, 'init_provider' ] );
		add_action( 'wd_2fa_user_options_' . self::$slug, [ &$this, 'user_options' ] );
	}

	/**
	 * Get the name of the provider.
	 *
	 * @return string
	 */
	public function get_label(): string {
		return __( 'TOTP Authenticator App', 'defender-security' ) . $this->label;
	}

	/**
	 * @return string
	 */
	public function get_login_label(): string {
		return __( 'TOTP Authentication', 'defender-security' );
	}

	/**
	 * @return string
	 */
	public function get_user_label(): string {
		return __( 'TOTP', 'defender-security' );
	}

	/**
	 * Get the desc of the provider.
	 *
	 * @return string
	 */
	public function get_description(): string {
		return $this->description;
	}

	public function authentication_form() {
		?>
		<p class="wpdef-2fa-label"><?php echo $this->get_login_label(); ?></p>
		<p class="wpdef-2fa-text def-otp-text"><?php echo esc_html( $this->get_model()->app_text ); ?></p>
		<input type="text" autofocus value="" autocomplete="off" name="otp" />
		<button class="button button-primary float-r" type="submit"><?php _e( 'Authenticate', 'defender-security' ); ?></button>
		<?php
	}

	/**
	 * @return array
	 */
	public function get_auth_apps(): array {
		return [
			'google-authenticator' => 'Google Authenticator',
			'microsoft-authenticator' => 'Microsoft Authenticator',
			'authy' => 'Authy',
		];
	}

	/**
	 * @param WP_User $user
	 */
	public function init_provider( WP_User $user ) {
		$is_on = $this->is_available_for_user( $user );
		$this->label = $is_on
			? sprintf(
			/* translators: %s: style class */
				__( '<button type="button" class="button reset-totp-keys button-secondary hide-if-no-js" %s>Reset Keys</button>', 'defender-security' ),
				$this->get_component()->is_checked_enabled_provider_by_slug( $user, self::$slug ) ? '' : ' disabled'
			)
			: '';
		$this->description = $is_on
			? __( 'TOTP Authentication method is active for this site', 'defender-security' )
			: __( 'Use an authenticator app to sign in with a separate passcode.', 'defender-security' );
	}

	/**
	 * Display auth method.
	 *
	 * @param WP_User $user
	 */
	public function user_options( WP_User $user ) {
		// Enqueue scripts.
		if ( ! wp_script_is( 'clipboard', 'enqueued' ) ) {
			wp_enqueue_script( 'clipboard' );
		}
		wp_enqueue_script(
			'def-qrcode',
			defender_asset_url( '/assets/js/jquery-qrcode.min.js' ),
			[ 'jquery' ],
			'0.18.0'
		);

		$model = $this->get_model();
		$service = $this->get_component();
		$default_values = $model->get_default_values();
		$is_on = $this->is_available_for_user( $user );
		if ( $is_on ) {
			$this->get_controller()->render_partial(
				'two-fa/providers/totp-enabled',
				[
					'url' => $this->get_url( 'disable_totp' ),
				]
			);
		} else {
			$is_success = true;
			$result = self::get_user_secret( $user->ID );
			if ( is_wp_error( $result ) ) {
				$secret = $result->get_error_message();
				$is_success = false;
			} elseif ( is_bool( $result ) ) {
				// Sometimes we can get a boolean value due to errors with writing to the database. In this case, we need to reset the value.
				delete_user_meta( $user->ID, self::TOTP_SECRET_KEY );
				// Also for new key.
				delete_user_meta( $user->ID, self::TOTP_SODIUM_SECRET_KEY );
				$secret = self::get_user_secret( $user->ID );
			} else {
				$secret = $result;
			}
			$this->get_controller()->render_partial(
				'two-fa/providers/totp-disabled',
				[
					'url' => $this->get_url( 'verify_otp_for_enabling' ),
					'default_message' => $default_values['message'],
					'auth_apps' => $this->get_auth_apps(),
					'user' => $user,
					'secret_key' => $secret,
					'class' => $service->is_checked_enabled_provider_by_slug( $user, self::$slug ) ? '' : 'hidden',
					'is_success' => $is_success,
				]
			);
		}
	}

	/**
	 * Generate a QR code for apps can use. Apps from get_auth_apps().
	 *
	 * @param string $secret_key
	 *
	 * @retun string
	 */
	public static function generate_qr_code( $secret_key ) {
		$settings = new \WP_Defender\Model\Setting\Two_Fa();
		$issuer = rawurlencode( $settings->app_title );
		$user = wp_get_current_user();

		return 'otpauth://totp/' . $issuer . ':' . rawurlencode( $user->user_email )
			. '?secret=' . $secret_key . '&issuer=' . $issuer;
	}

	/**
	 * Whether this 2FA provider is configured and available for the user specified.
	 *
	 * @param WP_User $user WP_User object of the logged-in user.
	 *
	 * @return boolean
	 */
	public function is_available_for_user( WP_User $user ) {
		return (bool) get_user_meta( $user->ID, self::TOTP_AUTH_KEY, true );
	}

	/**
	 * @param WP_User $user
	 *
	 * @return bool|WP_Error
	 */
	public function validate_authentication( WP_User $user ) {
		$otp = HTTP::post( 'otp' );
		if ( empty( $otp ) ) {
			$lockout_message = $this->get_component()->verify_attempt( $user->ID, self::$slug );

			return new WP_Error(
				'opt_fail',
				empty( $lockout_message )
					? __( 'Whoops, the passcode you entered was incorrect or expired.', 'defender-security' )
					: $lockout_message
			);
		}
		$setup_key = self::get_user_secret( $user->ID );
		if ( is_wp_error( $setup_key ) ) {
			return new WP_Error(
				'opt_fail',
				__( 'Whoops, the passcode you entered was incorrect or expired.', 'defender-security' )
			);
		}

		return self::verify_otp( $otp, $user->ID, $setup_key );
	}

	/**
	 * @param int $user_id
	 *
	 * @return string|WP_Error
	 */
	private static function get_user_secret( $user_id ) {
		// First, we check the new 'TOTP_SODIUM_SECRET_KEY' key.
		$data = get_user_meta( $user_id, self::TOTP_SODIUM_SECRET_KEY, true );
		if ( ! empty( $data ) ) {
			return Crypt::get_decrypted_data( $data );
		}
		// Then check the old 'TOTP_SECRET_KEY' key.
		if ( ( new Two_Fa_Component() )->maybe_update( $user_id ) ) {
			// Check a new key again.
			$data = get_user_meta( $user_id, self::TOTP_SODIUM_SECRET_KEY, true );
			if ( ! empty( $data ) && is_string( $data )  ) {
				return Crypt::get_decrypted_data( $data );
			}
		}
		// Finally, generate a new one.
		return defender_generate_random_string( self::TOTP_LENGTH, self::TOTP_CHARACTERS );
	}

	/**
	 * @param int    $user_id
	 * @param string $plaintext
	 *
	 * @return bool|WP_Error
	 */
	public static function save_setup_key( $user_id, $plaintext ) {
		$secret = Crypt::get_encrypted_data( $plaintext );
		if ( is_wp_error( $secret ) ) {
			return $secret;
		}
		update_user_meta( $user_id, self::TOTP_SODIUM_SECRET_KEY, $secret );

		return true;
	}

	/**
	 * Generate an OTP code base on current time.
	 *
	 * @param int    $counter
	 * @param int    $user_id
	 * @param string $setup_key
	 *
	 * @return string|WP_Error
	 */
	private static function generate_otp( $counter, $user_id, $setup_key ) {
		if ( empty( $setup_key ) || ! is_string( $setup_key ) ) {
			$setup_key = self::get_user_secret( $user_id );
			if ( is_wp_error( $setup_key ) ) {
				return $setup_key;
			}
		}
		include_once defender_path( 'src/extra/binary-to-text-php/Base2n.php' );
		$base32 = new Base2n( 5, self::TOTP_CHARACTERS, false, true, true );
		$secret = $base32->decode( $setup_key );
		$input = floor( $counter / self::TOTP_TIME_STEP_SEC );
		// According to https://tools.ietf.org/html/rfc4226#section-5.3, should be 8 bytes value.
		$time = chr( 0 ) . chr( 0 ) . chr( 0 ) . chr( 0 ) . pack( 'N*', $input );
		$hmac = hash_hmac( self::DEFAULT_CRYPTO, $time, $secret, true );
		// Now we have 20 bytes of DEFAULT_CRYPTO, need to short it down. Getting last byte of the hmac.
		$offset = ord( substr( $hmac, - 1 ) ) & 0x0F;
		$four_bytes = substr( $hmac, $offset, 4 );
		// Now convert it into INT.
		$value = unpack( 'N', $four_bytes );
		$value = $value[1];
		// Make sure it always actual like 32 bits.
		$value = $value & 0x7FFFFFFF;
		// Close.
		$code = $value % 10 ** self::TOTP_DIGIT_COUNT;
		// In some case we have the 0 before, so it becomes lesser than TOTP_DIGIT_COUNT, make sure it always right.
		return str_pad( (string) $code, self::TOTP_DIGIT_COUNT, '0', STR_PAD_LEFT );
	}

	/**
	 * Verify the OTP of beyond & after TOTP_TIME_STEP_SEC seconds windows.
	 *
	 * @param string $user_code
	 * @param int    $user_id
	 * @param string $setup_key
	 *
	 * @return bool|WP_Error
	 */
	public static function verify_otp( string $user_code, int $user_id, $setup_key ) {
		if ( strlen( $user_code ) < self::TOTP_DIGIT_COUNT ) {
			return false;
		}
		for ( $i = - self::TOTP_TIME_STEP_ALLOWANCE; $i <= self::TOTP_TIME_STEP_ALLOWANCE; $i ++ ) {
			$counter = 0 === $i ? time() : $i * self::TOTP_TIME_STEP_SEC + time();
			$code = self::generate_otp( $counter, $user_id, $setup_key );
			if ( is_wp_error( $code ) ) {
				return $code;
			}
			if ( Crypt::compare_lines( $user_code, $code ) ) {
				return true;
			}
		}

		return false;
	}
}
