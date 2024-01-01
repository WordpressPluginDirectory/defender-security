<?php

namespace WP_Defender\Controller;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\Server;
use WP_Defender\Controller\Two_Factor as Two_Fa_Controller;
use WP_Defender\Component\Two_Fa as Two_Fa_Component;
use WP_Defender\Component\Webauthn as Webauthn_Component;
use WP_Defender\Component\Two_Factor\Providers\Webauthn as Webauthn_Provider;
use WP_Defender\Controller;
use WP_Defender\Traits\Webauthn as Webauthn_Trait;
use Exception;
use Error;

/**
 * Class Webauthn
 * @package WP_Defender\Controller
 * @since 3.0.0
 */
class Webauthn extends Controller {
	use Webauthn_Trait;

	/**
	 * @var Webauthn_Component
	 */
	protected $service;

	public const ALLOWED_AUTH_TYPES = [ 'platform', 'cross-platform' ];

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->service = wd_di()->get( Webauthn_Component::class );

		if ( $this->service->check_webauthn_requirements() ) {
			// Register a new authenticator.
			add_action( 'wp_ajax_defender_webauthn_create_challenge', [ $this, 'create_challenge' ] );
			add_action( 'wp_ajax_defender_webauthn_verify_challenge', [ $this, 'verify_challenge' ] );
			// Remove authenticator.
			add_action( 'wp_ajax_defender_webauthn_remove_authenticator', [ $this, 'remove_authenticator' ] );
			// Rename authenticator.
			add_action( 'wp_ajax_defender_webauthn_rename_authenticator', [ $this, 'rename_authenticator' ] );
			// Verify user's device.
			add_action( 'wp_ajax_defender_webauthn_get_option', [ $this, 'get_credential_request_option' ] );
			add_action( 'wp_ajax_nopriv_defender_webauthn_get_option', [ $this, 'get_credential_request_option' ] );
			add_action( 'wp_ajax_defender_webauthn_verify_response', [ $this, 'verify_response' ] );
			add_action( 'wp_ajax_nopriv_defender_webauthn_verify_response', [ $this, 'verify_response' ] );
			// Handling requests in the frontend.
			if ( wd_di()->get( Two_Fa_Controller::class )-> woo_integration_enabled() ) {
				add_action( 'wp_ajax_nopriv_defender_webauthn_create_challenge', [ $this, 'create_challenge' ] );
				add_action( 'wp_ajax_nopriv_defender_webauthn_verify_challenge', [ $this, 'verify_challenge' ] );
				add_action( 'wp_ajax_nopriv_defender_webauthn_remove_authenticator', [ $this, 'remove_authenticator' ] );
				add_action( 'wp_ajax_nopriv_defender_webauthn_rename_authenticator', [ $this, 'rename_authenticator' ] );
			}

			// Disable userHandle mismatch notice
			add_action(
				'wp_ajax_defender_webauthn_disable_user_handle_match_failed_notice',
				[ $this, 'disable_user_handle_match_failed_notice' ]
			);
		}
	}

	/**
	 * Get authenticator records for current user.
	 *
	 * @return array
	 */
	public function get_current_user_authenticators(): array {
		$arr = [];
		$user_id = get_current_user_id();
		$user_credentials = $this->service->getCredentials( $user_id );
		if ( ! empty( $user_credentials ) && is_array( $user_credentials ) ) {
			foreach ( $user_credentials as $key => $value ) {
				$arr[] = [
					'key' => $this->base64url_encode( $key ),
					'label' => $value['label'],
					'added' => gmdate( 'Y-m-d', $value['added'] ),
					'auth_type' => $value['authenticator_type'],
				];
			}
		}

		return $arr;
	}

	/**
	 * Get user entity.
	 *
	 * @param int $user_id
	 *
	 * @return false|PublicKeyCredentialUserEntity
	 */
	public function get_user_entity( int $user_id ) {
		if ( $user_id <= 0 ) {
			return false;
		}

		$user = get_user_by( 'id', $user_id );
		if ( ! is_object( $user ) ) {
			return false;
		}

		$user_hash = $this->get_user_hash( $user->user_login );
		$user_avatar = get_avatar_url( $user->user_email, [ 'scheme' => 'https' ] );

		return new PublicKeyCredentialUserEntity(
			$user->user_login,
			$user_hash,
			$user->display_name,
			$user_avatar
		);
	}

	/**
	 * Create challenge.
	 *
	 * @return void
	 */
	public function create_challenge(): void {
		try {
			if ( ! $this->verify_nonce( 'wpdef_webauthn' ) ) {
				throw new Exception( __( 'Bad nonce.', 'defender-security' ) );
			}

			if ( empty( $_GET['type'] ) ) {
				throw new Exception( __( 'Missing field(s).', 'defender-security' ) );
			}

			$user_id = get_current_user_id();
			$user_entity = $this->get_user_entity( $user_id );
			if ( false === $user_entity ) {
				throw new Exception( __( 'User does not exist.', 'defender-security' ) );
			}

			// Get the list of all authenticators associated to a user.
			$credential_sources = $this->service->findAllForUserEntity( $user_entity );

			// Convert the Credential Sources into Public Key Credential Descriptors
			$exclude_credentials = array_map(
				function ( $credential ) {
					return $credential->getPublicKeyCredentialDescriptor();
				},
				$credential_sources
			);

			$auth_type = sanitize_text_field( $_GET['type'] );
			if ( 'platform' === $auth_type ) {
				$authenticator_type = AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM;
			} elseif ( 'cross-platform' === $auth_type ) {
				$authenticator_type = AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM;
			} else {
				$authenticator_type = AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_NO_PREFERENCE;
			}

			// Create authenticator selection.
			$resident_key = false;
			$user_verification = AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_DISCOURAGED;
			$authenticator_selection_criteria = new AuthenticatorSelectionCriteria(
				$authenticator_type,
				$resident_key,
				$user_verification
			);

			$rp_entity = new PublicKeyCredentialRpEntity(
				$this->get_site_name(),
				$this->get_site_domain()
			);
			$server = new Server(
				$rp_entity,
				$this->service,
				null
			);

			$public_key_credential_creation_options = $server->generatePublicKeyCredentialCreationOptions(
				$user_entity,
				PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
				$exclude_credentials,
				$authenticator_selection_criteria
			);

			$client_id = time() . defender_generate_random_string( 24 );

			// set transition for later use.
			$this->set_trans_val( 'pub_key_cco', base64_encode( serialize( $public_key_credential_creation_options ) ), $client_id );

			// Send Challenge.
			$public_key_credential_creation_options = json_decode( wp_json_encode( $public_key_credential_creation_options ), true );
			$public_key_credential_creation_options['clientID'] = $client_id;
			wp_send_json_success( $public_key_credential_creation_options );
		} catch ( Error $error ) {
			wp_send_json_error( $error->getMessage() );
		} catch ( Exception $exception ) {
			wp_send_json_error( $exception->getMessage() );
		}
	}

	/**
	 * Verify challenge.
	 *
	 * @return void
	 */
	public function verify_challenge(): void {
		$client_id = null;
		try {
			if ( ! $this->verify_nonce( 'wpdef_webauthn', 'post' ) ) {
				throw new Exception( __( 'Bad nonce.', 'defender-security' ) );
			}

			if ( empty( $_POST['data'] ) || empty( $_POST['client_id'] ) ) {
				throw new Exception( __( 'Missing field(s).', 'defender-security' ) );
			}

			$psr17_factory = new Psr17Factory();
			$creator = new ServerRequestCreator(
				$psr17_factory,
				$psr17_factory,
				$psr17_factory,
				$psr17_factory
			);

			$server_request = $creator->fromGlobals();

			$rp_entity = new PublicKeyCredentialRpEntity(
				$this->get_site_name(),
				$this->get_site_domain()
			);

			$server = new Server(
				$rp_entity,
				$this->service,
				null
			);

			$response_data = base64_decode( sanitize_text_field( $_POST['data'] ) );
			$client_id = sanitize_text_field( $_POST['client_id'] );
			$pub_key_cco = $this->get_trans_val( 'pub_key_cco', $client_id );
			$pub_key_cco = unserialize( base64_decode( $pub_key_cco ) );

			$public_key_credential_source = $server->loadAndCheckAttestationResponse(
				$response_data,
				$pub_key_cco,
				$server_request
			);

			$this->service->saveCredentialSource( $public_key_credential_source );

			// Delete transient
			$this->delete_trans( 'pub_key_cco', $client_id );

			$response = [];
			$username = $pub_key_cco->getUser()->getName();
			$user = get_user_by( 'login', $username );

			$cred_data = [];
			if ( is_object( $user ) ) {
				$cred_data = $this->service->getCredentials( $user->ID );
			}

			$cred_id = base64_encode( $public_key_credential_source->getPublicKeyCredentialId() );
			if ( isset( $cred_data[ $cred_id ] ) ) {
				$response = [
					'key' => $this->base64url_encode( $cred_id ),
					'label' => ucfirst( $cred_data[ $cred_id ]['label'] ),
					'added' => gmdate( 'Y-m-d', $cred_data[ $cred_id ]['added'] ),
					'auth_type' => $cred_data[ $cred_id ]['authenticator_type'],
				];
			}
			wp_send_json_success( $response );
		} catch ( Error $error ) {
			$this->delete_trans( 'pub_key_cco', $client_id );
			wp_send_json_error( $error->getMessage() );
		} catch ( Exception $exception ) {
			$this->delete_trans( 'pub_key_cco', $client_id );
			wp_send_json_error( $exception->getMessage() );
		}
	}

	/**
	 * Remove authenticator.
	 *
	 * @return void
	 */
	public function remove_authenticator(): void {
		try {
			if ( ! $this->verify_nonce( 'wpdef_webauthn', 'post' ) ) {
				throw new Exception( __( 'Bad nonce.', 'defender-security' ) );
			}

			if ( empty( $_POST['key'] ) ) {
				throw new Exception( __( 'Missing field(s).', 'defender-security' ) );
			}

			$cred_id = sanitize_text_field( $_POST['key'] );
			$cred_id = $this->base64url_decode( $cred_id );
			$user_id = get_current_user_id();
			$option_user_credentials = $this->service->getCredentials( $user_id );

			if ( isset( $option_user_credentials[ $cred_id ] ) ) {
				unset( $option_user_credentials[ $cred_id ] );
				$this->service->setCredentials( $user_id, $option_user_credentials );
				$this->service->removeUserHandleMatchFailed( $user_id, $cred_id );

				if ( 0 === count( $option_user_credentials ) ) {
					$enabled_providers = get_user_meta( $user_id, Two_Fa_Component::ENABLED_PROVIDERS_USER_KEY, true );
					if ( empty( $enabled_providers ) ) {
						$enabled_providers = [];
					}
					$key = array_search( Webauthn_Provider::$slug, $enabled_providers, true );
					if ( false !== $key ) {
						unset( $enabled_providers[ $key ] );
						update_user_meta( $user_id, Two_Fa_Component::ENABLED_PROVIDERS_USER_KEY, $enabled_providers );
					}
				}

				wp_send_json_success( __( 'Authenticator removed.', 'defender-security' ) );
			}

			wp_send_json_error( __( 'Key did not match any registered authenticator.', 'defender-security' ) );
		} catch ( Error $error ) {
			wp_send_json_error( $error->getMessage() );
		} catch ( Exception $exception ) {
			wp_send_json_error( $exception->getMessage() );
		}
	}

	/**
	 * Rename authenticator.
	 *
	 * @return void
	 */
	public function rename_authenticator(): void {
		try {
			if ( ! $this->verify_nonce( 'wpdef_webauthn', 'post' ) ) {
				throw new Exception( __( 'Bad nonce.', 'defender-security' ) );
			}

			if ( empty( $_POST['key'] ) || empty( $_POST['label'] ) ) {
				throw new Exception( __( 'Missing field(s).', 'defender-security' ) );
			}

			$cred_id = sanitize_text_field( $_POST['key'] );
			$cred_id = $this->base64url_decode( $cred_id );
			$new_label = sanitize_text_field( $_POST['label'] );
			$user_id = get_current_user_id();
			$option_user_credentials = $this->service->getCredentials( $user_id );

			if ( isset( $option_user_credentials[ $cred_id ] ) ) {
				$option_user_credentials[ $cred_id ]['label'] = $new_label;
				$this->service->setCredentials( $user_id, $option_user_credentials );

				wp_send_json_success( __( 'Authenticator identifier renamed.', 'defender-security' ) );
			}

			wp_send_json_error( __( 'Key did not match any registered authenticator.', 'defender-security' ) );
		} catch ( Error $error ) {
			wp_send_json_error( $error->getMessage() );
		} catch ( Exception $exception ) {
			wp_send_json_error( $exception->getMessage() );
		}
	}

	/**
	 * Get credential request option.
	 *
	 * @return void
	 */
	public function get_credential_request_option(): void {
		try {
			if ( ! $this->verify_nonce( 'wpdef_webauthn', 'post' ) ) {
				throw new Exception( __( 'Bad nonce.', 'defender-security' ) );
			}

			if ( empty( $_POST['username'] ) ) {
				throw new Exception( __( 'Missing field(s).', 'defender-security' ) );
			}

			$rp_entity = new PublicKeyCredentialRpEntity(
				$this->get_site_name(),
				$this->get_site_domain()
			);

			$server = new Server(
				$rp_entity,
				$this->service,
				null
			);

			$user_entity = false;
			$username = sanitize_text_field( $_POST['username'] );
			$user = get_user_by( 'login', $username );
			if ( is_object( $user ) ) {
				$user_entity = $this->get_user_entity( $user->ID );
			}

			if ( false === $user_entity ) {
				throw new Exception( __( 'User does not exist.', 'defender-security' ) );
			}

			$auth_type = ! empty( $_POST['type'] ) ? sanitize_text_field( $_POST['type'] ): null;
			if ( in_array( $auth_type, self::ALLOWED_AUTH_TYPES ) ) {
				$credential_sources = $this->service->findAllForUserByType( $user->ID, $auth_type );
			} else {
				$credential_sources = $this->service->findAllForUserEntity( $user_entity );
			}

			if ( ! is_array( $credential_sources ) || 0 === count( $credential_sources ) ) {
				throw new Exception( __( 'Please register a device first to authenticate it.', 'defender-security' ), 100 );
			}

			// Convert the Credential Sources into Public Key Credential Descriptors for excluding
			$allowed_credentials = array_map(
				function( $credential ) {
					return $credential->getPublicKeyCredentialDescriptor();
				},
				$credential_sources
			);
			$user_verification = AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_DISCOURAGED;

			$public_key_credential_request_options = $server->generatePublicKeyCredentialRequestOptions(
				$user_verification,
				$allowed_credentials
			);

			// set transition for later use.
			$client_id = time() . defender_generate_random_string( 24 );
			$this->set_trans_val( 'pub_key_cro', base64_encode( serialize( $public_key_credential_request_options ) ), $client_id );

			$public_key_credential_request_options = json_decode( wp_json_encode( $public_key_credential_request_options ), true );
			$public_key_credential_request_options['clientID'] = $client_id;
			wp_send_json_success( $public_key_credential_request_options );
		} catch ( Error $error ) {
			wp_send_json_error( $error->getMessage() );
		} catch ( Exception $exception ) {
			wp_send_json_error(
				[
					'message' => $exception->getMessage(),
					'code' => $exception->getCode(),
				]
			);
		}
	}

	/**
	 * Verify response.
	 *
	 * @param bool $return Either return array or echo json.
	 *
	 * @return array|void
	 */
	public function verify_response( bool $return = false ) {
		$client_id = null;
		try {
			if ( ! $this->verify_nonce( 'wpdef_webauthn', 'post' ) ) {
				throw new Exception( __( 'Bad nonce.', 'defender-security' ) );
			}

			if ( empty( $_POST['data'] ) || empty( $_POST['username'] ) || empty( $_POST['client_id'] ) ) {
				throw new Exception( __( 'Missing field(s).', 'defender-security' ) );
			}

			$user_entity = false;
			$response_data = base64_decode( $_POST['data'] );
			$username = sanitize_text_field( $_POST['username'] );
			$client_id = sanitize_text_field( $_POST['client_id'] );
			$pub_key_cro = unserialize( base64_decode( $this->get_trans_val( 'pub_key_cro', $client_id ) ) );
			$user = get_user_by( 'login', $username );

			if ( is_object( $user ) ) {
				$user_entity = $this->get_user_entity( $user->ID );
			}

			if ( false === $user_entity ) {
				throw new Exception( __( 'User does not exist.', 'defender-security' ) );
			}

			$psr17_factory = new Psr17Factory();
			$creator = new ServerRequestCreator(
				$psr17_factory,
				$psr17_factory,
				$psr17_factory,
				$psr17_factory
			);

			$server_request = $creator->fromGlobals();

			$rp_entity = new PublicKeyCredentialRpEntity(
				$this->get_site_name(),
				$this->get_site_domain()
			);

			$server = new Server(
				$rp_entity,
				$this->service,
				null
			);

			$server->loadAndCheckAssertionResponse(
				$response_data,
				$pub_key_cro,
				$user_entity,
				$server_request
			);

			// Success
			$this->delete_trans( 'pub_key_cro', $client_id );

			$data = __( 'Authenticator verified successfully.', 'defender-security' );
			return defender_maybe_echo_json( $data, true, $return );
		} catch ( Error $error ) {
			$this->delete_trans( 'pub_key_cro', $client_id );
			return defender_maybe_echo_json( $error->getMessage(), false, $return );
		} catch ( Exception $exception ) {
			$data = [ 'message' => $exception->getMessage() ];

			if ( $exception->getMessage() === 'Invalid user handle' ) {
				$user_credentials = $this->service->getCredentials( $user->ID );
				$decoded_response = json_decode( $response_data, true );

				$data['label'] = $user_credentials[ $decoded_response['rawId'] ]['label'];
				$data['key'] = $this->base64url_encode( $decoded_response['rawId'] );

				$this->service->addUserHandleMatchFailed( $user, $decoded_response );
			}

			$this->delete_trans( 'pub_key_cro', $client_id );
			return defender_maybe_echo_json( $data, false, $return );
		}
	}

	/**
	 * Get translation.
	 *
	 * @return array
	 */
	public function get_translations(): array {
		$translations = [
			'registration_start' => __( 'Registering a new authenticator is in process.', 'defender-security' ),
			'authenticator_reg_success' => __( 'Registered new authenticator.', 'defender-security' ),
			'authenticator_reg_failed' => __( 'ERROR: Something went wrong.', 'defender-security' ),
			'multiple_reg_attempt' => __( 'Registration failed! The authenticator you are trying to register is already registered with your account.', 'defender-security' ),
			'authentication_start' => __( 'Authenticating', 'defender-security' ),
			'authenticator_verification_success' => __( 'Authenticated device successfully.', 'defender-security' ),
			'authenticator_verification_failed' => __( 'Authentication verification failed! Please make sure that biometric functionality is configured on your phone.', 'defender-security' ),
			'authenticator_verification_failed_user_handle_mismatch' => __( 'Due to some Biometric Authentication security improvements, the <strong>%s</strong> device will not work. Please delete this device and re-register it.', 'defender-security' ),
			'remove_auth' => __( 'Are you sure you want to remove authenticator?', 'defender-security' ),
			'login_failed' => __( 'ERROR: Verification failed.', 'defender-security' ),
			'login_user_handle_match_failed' => __( 'ERROR: Due to some Biometric Authentication security improvements, some of your registered devices might not work. Please ask your website administrator to reset 2FA for your account. Then navigate to your profile page to check which devices need re-registration.', 'defender-security' ),
			'client_webauthn_notice' => __( 'WebAuth is not supported by your web browser. Please install an updated version, or try another browser.', 'defender-security' ),
			'auth_user_handle_mismatch_notice' => __( 'This device might not work. Please delete the device and re-register it.', 'defender-security' ),
			'user_handle_mismatch_main_notice' => __( 'Due to some biometric authentication security improvements, some of your registered devices might not work. Please click the Authenticate Device button to check which devices you need to delete and re-registered.', 'defender-security' ),
		];

		if ( ( new \WP_Defender\Behavior\WPMUDEV() )->show_support_links() ) {
			$translations['authenticator_verification_failed'] .= defender_support_ticket_text();
		}

		return $translations;
	}

	/**
	 * Disable userHandle mismatch notice.
	 *
	 * @since 3.4.0
	 * @return void
	 */
	public function disable_user_handle_match_failed_notice(): void {
		$this->service->disableUserHandleMatchFailedNotice( get_current_user_id() );
		wp_send_json_success( __( 'Notice disabled!', 'defender-security' ) );
	}

	/**
	 * Remove data.
	 *
	 * @return void
	 */
	public function remove_data(): void {
		global $wpdb;
		$sql = $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE %s;", "%{$this->option_prefix}%" );
		$wpdb->query( $sql );
	}

	/**
	 * Export strings.
	 *
	 * @return array
	 */
	public function export_strings(): array {
		return [];
	}

	/**
	 * @return array
	 */
	public function to_array(): array {
		return [];
	}

	/**
	 * @param array $data
	 *
	 * @return void
	 */
	public function import_data( $data ): void {}

	/**
	 * @return void
	 */
	public function remove_settings(): void {}

	/**
	 * @return array
	 */
	public function data_frontend(): array {
		return [];
	}
}
