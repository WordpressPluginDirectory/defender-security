<?php

namespace WP_Defender\Controller;

use Calotes\Component\Request;
use Calotes\Component\Response;
use Calotes\Helper\HTTP;
use WP_Defender\Component\Config\Config_Hub_Helper;
use WP_Defender\Event;
use WP_Defender\Traits\Formats;
use WP_Defender\Traits\User;
use WP_Defender\Model\Notification as Model_Notification;

class Notification extends Event {
	use User, Formats;

	/**
	 * @var string
	 */
	public const SLUG_SUBSCRIBE = 'defender_listen_user_subscribe';

	/**
	 * @var string
	 */
	public const SLUG_UNSUBSCRIBE = 'defender_listen_user_unsubscribe';

	public $slug = 'wdf-notification';

	/**
	 * @var \WP_Defender\Component\Notification
	 */
	protected $service;

	public function __construct() {
		$this->register_page(
			esc_html__( 'Notifications', 'defender-security' ),
			$this->slug,
			[
				&$this,
				'main_view',
			],
			$this->parent_slug
		);
		$this->register_routes();
		$this->service = wd_di()->get( \WP_Defender\Component\Notification::class );
		add_action( 'defender_enqueue_assets', [ &$this, 'enqueue_assets' ] );
		// We use custom ajax endpoint here as the nonce would fail with other user.
		add_action( 'wp_ajax_' . self::SLUG_SUBSCRIBE, [ &$this, 'verify_subscriber' ] );
		add_action( 'wp_ajax_nopriv_' . self::SLUG_SUBSCRIBE, [ &$this, 'verify_subscriber' ] );
		add_action( 'wp_ajax_' . self::SLUG_UNSUBSCRIBE, [ &$this, 'unsubscribe_and_send_email' ] );
		add_action( 'wp_ajax_nopriv_' . self::SLUG_UNSUBSCRIBE, [ &$this, 'unsubscribe_and_send_email' ] );
		add_action( 'defender_notify', [ &$this, 'send_notify' ], 10, 2 );
		// We will schedule the time to send reports.
		if ( ! wp_next_scheduled( 'wdf_maybe_send_report' ) ) {
			$timestamp = gmmktime( gmdate( 'H' ), 0, 0 );
			wp_schedule_event( $timestamp, 'thirty_minutes', 'wdf_maybe_send_report' );
		}
		add_action( 'wdf_maybe_send_report', [ &$this, 'report_sender' ] );
		add_action( 'admin_notices', [ &$this, 'show_actions_with_subscription' ] );
	}

	/**
	 * For users who have subscribed or unsubscribed confirmation.
	 *
	 * @return null|void
	 */
	public function show_actions_with_subscription() {
		if ( ! defined( 'IS_PROFILE_PAGE' ) || false === constant( 'IS_PROFILE_PAGE' ) ) {
			return null;
		}
		$slug = isset( $_GET['slug'] ) ? sanitize_text_field( $_GET['slug'] ) : false;
		if ( empty( $slug ) ) {
			return null;
		}
		$m = $this->service->find_module_by_slug( $slug );
		if ( ! is_object( $m ) ) {
			return null;
		}
		$context = isset( $_GET['context'] ) ? sanitize_text_field( $_GET['context'] ) : false;
		if ( 'subscribed' === $context ) {
			$unsubscribe_link = $this->service->create_unsubscribe_url( $m->slug, $this->get_current_user_email() );
			$strings = sprintf(
			/* translators: 1. Module title. 2. Unsubscribed link. */
				__( 'You are now subscribed to receive %1$s. Made a mistake? <a href="%2$s">Unsubscribe</a>', 'defender-security' ),
				'<strong>' . $m->title . '</strong>',
				$unsubscribe_link
			);
		} elseif ( 'unsubscribe' === $context ) {
			$strings = sprintf(
			/* translators: %s: Module title. */
				__( 'You are now unsubscribed from %s.', 'defender-security' ),
				'<strong>' . $m->title . '</strong>'
			);
		} else {
			return null;
		}
		?>
		<div class="notice notice-success" style="position:relative;">
			<p><?php echo $strings; ?></p>
			<a href="<?php echo get_edit_profile_url(); ?>" class="notice-dismiss" style="text-decoration: none">
				<span class="screen-reader-text"><?php _e( 'Dismiss this notice.', 'defender-security' ); ?></span>
			</a>
		</div>
		<?php
	}

	/**
	 * Trigger report check signals.
	 */
	public function report_sender() {
		$this->service->maybe_dispatch_report();
	}

	public function main_view() {
		$this->render( 'main' );
	}

	/**
	 * Dispatch notification.
	 *
	 * @param string $slug
	 * @param object $args
	 */
	public function send_notify( $slug, $args ) {
		$this->service->dispatch_notification( $slug, $args );
	}

	/**
	 * @param Request $request
	 *
	 * @defender_route
	 * @return Response
	 */
	public function validate_email( Request $request ): Response {
		$data = $request->get_data(
			[
				'email' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
			]
		);
		$email = $data['email'] ?? false;
		if ( filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
			return new Response(
				true,
				[
					'error' => false,
					'avatar' => get_avatar_url( $data['email'] ),
				]
			);
		} else {
			return new Response( false, [ 'error' => __( 'Invalid email address.', 'defender-security' ) ] );
		}
	}

	/**
	 * Unsubscribe process.
	 */
	public function unsubscribe_and_send_email() {
		$slug = HTTP::get( 'slug', '' );
		$hash = HTTP::get( 'hash', '' );
		$slug = sanitize_text_field( $slug );
		if ( empty( $slug ) || empty( $hash ) ) {
			wp_die( __( 'You shall not pass.', 'defender-security' ) );
		}
		$m = $this->service->find_module_by_slug( $slug );
		if ( ! is_object( $m ) ) {
			wp_die( __( 'You shall not pass.', 'defender-security' ) );
		}
		$inhouse = false;
		foreach ( $m->in_house_recipients as &$recipient ) {
			$email = $recipient['email'];
			if ( hash_equals( $hash, hash( 'sha256', $email . AUTH_SALT ) ) ) {
				// We skip even an un-logged user, because the admin can change the user's access without notice.
				if ( is_user_logged_in() ) {
					if ( $email !== $this->get_current_user_email() ) {
						wp_die( __( 'Invalid request.', 'defender-security' ) );
					}
					$inhouse = true;
				}
				$recipient['status'] = Model_Notification::USER_SUBSCRIBE_CANCELED;
				$m->save();
				// Send email.
				$this->service->send_unsubscribe_email( $m, $email, $inhouse, $recipient['name'] );
				break;
			}
		}

		if ( false === $inhouse ) {
			// No match on in-house, check the outhouse list.
			foreach ( $m->out_house_recipients as &$recipient ) {
				$email = $recipient['email'];
				if ( hash_equals( $hash, hash( 'sha256', $email . AUTH_SALT ) ) ) {
					$recipient['status'] = Model_Notification::USER_SUBSCRIBE_CANCELED;
					$m->save();
					$this->service->send_unsubscribe_email( $m, $email, $inhouse, $recipient['name'] );
				}
			}
		}
		if ( $inhouse ) {
			wp_redirect(
				add_query_arg(
					[
						'slug' => $slug,
						'context' => 'unsubscribe',
					],
					get_edit_profile_url()
				)
			);
		} else {
			wp_redirect( get_home_url() );
		}
		exit;
	}

	/**
	 * An endpoint for saving single config from frontend.
	 *
	 * @param Request $request
	 *
	 * @defender_route
	 * @return Response
	 */
	public function save( Request $request ): Response {
		$raw_data = $request->get_data();
		$slug = sanitize_textarea_field( $raw_data['slug'] );
		$model = $this->service->find_module_by_slug( $slug );

		if ( ! is_object( $model ) ) {
			return new Response( false, [ 'message' => __( 'Invalid data.', 'defender-security' ) ] );
		}
		$data = $request->get_data_by_model( $model );
		// Check config-values.
		$data['configs'] = $model->type_casting( $data['configs'] );

		$model->import( $data );
		$model->status = Model_Notification::STATUS_ACTIVE;
		if ( $model->validate() ) {
			if ( 0 === $model->last_sent ) {
				// This means that the notification or report never sent, we will use the moment that it get activate.
				$model->last_sent = time();
			}
			$model->save();
			$this->service->send_subscription_confirm_email( $model );
			Config_Hub_Helper::set_clear_active_flag();
			// Track.
			if ( $this->is_tracking_active() ) {
				$track_data = [ 'Notification type' => $raw_data['title'] ];
				// For reports. Separated check for 'Security Recommendations - Notification'.
				if ( 'report' === $raw_data['type'] ) {
					$track_data['Notification schedule'] = ucfirst( $data['frequency'] );
				} elseif ( 'tweak-reminder' === $raw_data['slug'] ) {
					$track_data['Notification schedule'] = ucfirst( $data['configs']['reminder'] );
				}
				$this->track_feature( 'def_notification_activated', $track_data );
			}

			return new Response(
				true,
				array_merge(
					[
						'message' => __(
							'You have activated the notification successfully. Note, recipients will need to confirm their subscriptions to begin receiving notifications.',
							'defender-security'
						),
					],
					$this->data_frontend()
				)
			);
		}

		return new Response( false, [ 'message' => $model->get_formatted_errors() ] );
	}

	/**
	 * Bulk update and save changes.
	 *
	 * @param Request $request
	 *
	 * @defender_route
	 * @return Response
	 */
	public function save_bulk( Request $request ): Response {
		$data = $request->get_data(
			[
				'reports' => [
					'type' => 'array',
					'sanitize' => 'sanitize_textarea_field',
				],
				'notifications' => [
					'type' => 'array',
					'sanitize' => 'sanitize_textarea_field',
				],
			]
		);
		$this->save_reports( $data['reports'] );
		$this->save_notifications( $data['notifications'] );
		Config_Hub_Helper::set_clear_active_flag();

		return new Response(
			true,
			array_merge(
				$this->data_frontend(),
				[
					'message' => __(
						'Your settings have been updated successfully. Any new recipients will receive an email to confirm their subscription.',
						'defender-security'
					),
				]
			)
		);
	}

	/**
	 * Process bulk reports saving.
	 *
	 * @param array $data
	 */
	private function save_reports( $data ) {
		foreach ( $data['configs'] as $datum ) {
			$slug = $datum['slug'];
			$model = $this->service->find_module_by_slug( $slug );
			if ( ! is_object( $model ) ) {
				continue;
			}

			$import = [
				// Saving after Bulk-Update must always change the status to Active.
				'status' => Model_Notification::STATUS_ACTIVE,
				'configs' => $model->type_casting( $datum ),
				'in_house_recipients' => $data['in_house_recipients'],
				'out_house_recipients' => $data['out_house_recipients'],
			];
			// @since 2.7.0.
			if ( \WP_Defender\Model\Notification\Malware_Report::SLUG !== $slug ) {
				$import['frequency'] = $data['frequency'];
				$import['day_n'] = $data['day_n'];
				$import['day'] = $data['day'];
				$import['time'] = $data['time'];
			}
			foreach ( $import['out_house_recipients'] as $key => $val ) {
				if ( ! filter_var( $val['email'], FILTER_VALIDATE_EMAIL ) ) {
					unset( $import['out_house_recipients'][ $key ] );
				}
			}
			$model->import( $import );
			if ( $model->validate() ) {
				if ( 0 === $model->last_sent ) {
					$model->last_sent = time();
				}
				$model->save();
				$this->service->send_subscription_confirm_email( $model );
				// Track.
				if ( $this->is_tracking_active() ) {
					$track_data = [
						'Notification type' => $model->title,
						'Notification schedule' => 'tweak-reminder' === $slug
							? ucfirst( $data['configs']['reminder'] )
							: ucfirst( $data['frequency'] ),
					];
					$this->track_feature( 'def_notification_activated', $track_data );
				}
			}
		}
	}

	/**
	 * @param array $data
	 *
	 * @throws \DI\DependencyException
	 * @throws \DI\NotFoundException
	 * @throws \ReflectionException
	 */
	private function save_notifications( $data ) {
		foreach ( $data['configs'] as $datum ) {
			$slug = $datum['slug'];
			$model = $this->service->find_module_by_slug( $slug );
			if ( ! is_object( $model ) ) {
				continue;
			}
			$import = [
				// Saving after Bulk-Update must always change the status to Active.
				'status' => Model_Notification::STATUS_ACTIVE,
				'configs' => $model->type_casting( $datum ),
				'in_house_recipients' => $data['in_house_recipients'],
				'out_house_recipients' => $data['out_house_recipients'],
			];
			foreach ( $import['out_house_recipients'] as $key => $val ) {
				if ( ! filter_var( $val['email'], FILTER_VALIDATE_EMAIL ) ) {
					unset( $import['out_house_recipients'][ $key ] );
				}
			}
			$model->import( $import );
			if ( $model->validate() ) {
				if ( 0 === $model->last_sent ) {
					$model->last_sent = time();
				}
				$model->save();
				$this->service->send_subscription_confirm_email( $model );
				// Track.
				if ( $this->is_tracking_active() ) {
					$this->track_feature( 'def_notification_activated', [ 'Notification type' => $model->title ] );
				}
			}
		}
	}

	/**
	 * Bulk activate.
	 *
	 * @param Request $request
	 *
	 * @defender_route
	 * @return Response
	 * @throws \Exception
	 */
	public function bulk_activate( Request $request ): Response {
		$data = $request->get_data(
			[
				'slugs' => [
					'type' => 'array',
					'sanitize' => 'sanitize_text_field',
				],
			]
		);
		$slugs = $data['slugs'];
		if ( empty( $slugs ) ) {
			return new Response( false, [] );
		}

		foreach ( $slugs as $slug ) {
			$model = $this->service->find_module_by_slug( $slug );
			if ( is_object( $model ) ) {
				$model->status = Model_Notification::STATUS_ACTIVE;
				if ( 0 === $model->last_sent ) {
					// This means that the notification or report never sent, we will use the moment that it get activate.
					$model->last_sent = time();
				}
				$model->save();
			}
		}

		return new Response(
			true,
			array_merge(
				[
					'message' => 'You have activated the notification successfully. Note, recipients will need to confirm their subscriptions to begin receiving notifications.',
				],
				$this->data_frontend()
			)
		);
	}

	/**
	 * @param Request $request
	 *
	 * @defender_route
	 * @return Response
	 */
	public function bulk_deactivate( Request $request ): Response {
		$data = $request->get_data(
			[
				'slugs' => [
					'type' => 'array',
					'sanitize' => 'sanitize_text_field',
				],
			]
		);
		$slugs = $data['slugs'];
		if ( empty( $slugs ) ) {
			return new Response( false, [] );
		}

		foreach ( $slugs as $slug ) {
			$model = $this->service->find_module_by_slug( $slug );
			if ( is_object( $model ) ) {
				$model->status = Model_Notification::STATUS_DISABLED;
				$model->save();
			}
		}

		return new Response(
			true,
			array_merge(
				[ 'message' => __( 'You have deactivated the notifications successfully.', 'defender-security' ) ],
				$this->data_frontend()
			)
		);
	}

	/**
	 * @param Request $request
	 *
	 * @defender_route
	 * @return Response
	 */
	public function disable( Request $request ): Response {
		$data = $request->get_data(
			[
				'slug' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
			]
		);

		$slug = $data['slug'];
		$model = $this->service->find_module_by_slug( $slug );
		if ( ! is_object( $model ) ) {
			return new Response( false, [ 'message' => __( 'Invalid data.', 'defender-security' ) ] );
		}

		$model->status = Model_Notification::STATUS_DISABLED;
		$model->save();

		return new Response(
			true,
			array_merge(
				$this->data_frontend(),
				[
					'message' => __( 'You have deactivated the notification successfully.', 'defender-security' ),
				]
			)
		);
	}

	/**
	 * This is a receiver to process subscribe confirmation from email.
	 */
	public function verify_subscriber() {
		$hash = HTTP::get( 'hash', '' );
		$slug = HTTP::get( 'uid', '' );
		$inhouse = HTTP::get( 'inhouse', 0 );
		if ( $inhouse && ! is_user_logged_in() ) {
			// This is in-house, so we need to redirect.
			auth_redirect();
		}
		if ( empty( $hash ) || empty( $slug ) ) {
			wp_die( __( 'You shall not pass.', 'defender-security' ) );
		}
		$m = $this->service->find_module_by_slug( $slug );
		if ( ! is_object( $m ) ) {
			wp_die( __( 'You shall not pass.', 'defender-security' ) );
		}
		if ( $inhouse ) {
			$processed = false;
			foreach ( $m->in_house_recipients as &$recipient ) {
				if ( Model_Notification::USER_SUBSCRIBED === $recipient['status'] ) {
					continue;
				}

				$email = $recipient['email'];
				$name = $recipient['name'];
				if ( hash_equals( $hash, hash( 'sha256', $email . AUTH_SALT ) )
					&& $email === $this->get_current_user_email() ) {
					$recipient['status'] = Model_Notification::USER_SUBSCRIBED;
					$this->service->send_subscribed_email( $email, $m, $name );
					$processed = true;
				}
			}
		} else {
			foreach ( $m->out_house_recipients as &$recipient ) {
				if ( Model_Notification::USER_SUBSCRIBED === $recipient['status'] ) {
					continue;
				}

				$email = $recipient['email'];
				$name = $recipient['name'];
				if ( hash_equals( $hash, hash( 'sha256', $email . AUTH_SALT ) ) ) {
					$recipient['status'] = Model_Notification::USER_SUBSCRIBED;
					$this->service->send_subscribed_email( $email, $m, $name );
				}
			}
		}
		$m->save();
		if ( $inhouse ) {
			if ( $processed ) {
				wp_redirect(
					add_query_arg(
						[
							'slug' => $m->slug,
							'context' => 'subscribed',
						],
						get_edit_profile_url()
					)
				);
			} else {
				wp_redirect( home_url() );
			}
		} else {
			wp_redirect( home_url() );
		}
		exit;
	}

	/**
	 * Enqueue assets & output data.
	 */
	public function enqueue_assets() {
		if ( ! $this->is_page_active() ) {
			return;
		}
		wp_localize_script(
			'def-notification',
			'notification',
			array_merge( $this->data_frontend(), $this->dump_routes_and_nonces() )
		);
		wp_enqueue_script( 'def-momentjs', defender_asset_url( '/assets/js/vendor/moment/moment.min.js' ) );
		wp_enqueue_script( 'def-notification' );
		$this->enqueue_main_assets();
		wp_enqueue_style(
			'def-select2',
			defender_asset_url( '/assets/css/select2.min.css' )
		);
	}

	/**
	 * An endpoint for fetching users pool.
	 *
	 * @param Request $request Request data.
	 *
	 * @defender_route
	 */
	public function get_users( Request $request ) {
		$data = $request->get_data(
			[
				'paged' => [
					'type' => 'int',
					'sanitize' => 'sanitize_text_field',
				],
				'search' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
				'exclude' => [
					'type' => 'array',
				],
				'module' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
				'user_role_filter' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
				'user_sort' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
			]
		);
		$paged = 1;
		$exclude = $data['exclude'] ?? [];
		$username = $data['search'] ?? '';
		$slug = $data['module'] ?? null;
		$role = '';

		if (
			isset( $data['user_role_filter'] ) &&
			'all' !== $data['user_role_filter']
		) {
			$role = $data['user_role_filter'];
		}

		$order_by = 'ID';
		$order = 'DESC';
		if ( isset( $data['user_sort'] ) ) {
			switch ( $data['user_sort'] ) {
				case 'recent':
					$order_by = 'registered';
					$order = 'DESC';
					break;
				case 'alpha_asc':
					$order_by = 'display_name';
					$order = 'ASC';
					break;
				case 'alpha_desc':
				default:
					$order_by = 'display_name';
					$order = 'DESC';
					break;
			}
		}

		if ( strlen( $username ) ) {
			$username = "*$username*";
		}

		$users = $this->service->get_users_pool(
			$exclude,
			$role,
			$username,
			$order_by,
			$order,
			10,
			$paged
		);

		if ( ! is_null( $slug ) ) {
			$notification = $this->service->find_module_by_slug( $slug );
			if ( is_object( $notification ) ) {
				foreach ( $notification->in_house_recipients as $recipient ) {
					foreach ( $users as &$user ) {
						if ( $user['email'] === $recipient['email'] ) {
							$user['status'] = $recipient['status'];
						}
					}
				}
			}
		}

		wp_send_json_success( $users );
	}

	public function remove_settings() {
		foreach ( $this->service->get_modules_as_objects() as $module ) {
			$module->delete();
		}
	}

	public function remove_data() {}

	public function to_array() {}

	/**
	 * All the variables that we will show on frontend, both in the main page, or dashboard widget.
	 *
	 * @return array
	 */
	public function data_frontend(): array {
		return [
			'notifications' => $this->service->get_modules(),
			'inactive_notifications' => $this->service->get_inactive_modules(),
			'active_count' => $this->service->count_active(),
			'next_run' => $this->service->get_next_run(),
			'misc' => [
				'days_of_week' => $this->get_days_of_week(),
				'times_of_day' => $this->get_times(),
				'timezone_text' => sprintf(
				/* translators: 1. Timezone. 2. Time. */
					__(
						'Your timezone is set to %1$s, so your current time is %2$s.',
						'defender-security'
					),
					'<strong>' . wp_timezone_string() . '</strong>',
					'<strong>' . date( 'H:i', current_time( 'timestamp' ) ) . '</strong>'// phpcs:ignore
				),
				'default_recipient' => $this->get_default_recipient(),
			],
		];
	}

	/**
	 * Import the data of other source into this, it can be when HUB trigger the import, or user apply a preset.
	 *
	 * @param array $data
	 */
	public function import_data( $data ) {}

	/**
	 * @return array
	 */
	public function export_strings(): array {
		$modules = wd_di()->get( Notification::class )->service->get_modules_as_objects();
		$strings = [];
		foreach ( $modules as $module ) {
			/* translators: %s - module title, %s - module status */
			$string = __( '%1$s: %2$s', 'defender-security' );
			if ( 'notification' === $module->type ) {
				$string = sprintf(
					$string,
					$module->title,
					Model_Notification::STATUS_ACTIVE === $module->status ? __( 'Enabled', 'defender-security' ) : __( 'Disabled', 'defender-security' )
				);
			} else {
				$string = sprintf(
					$string,
					$module->title,
					Model_Notification::STATUS_ACTIVE === $module->status ? $module->to_string() : __( 'Disabled', 'defender-security' )
				);
			}
			$strings[] = $string;
		}

		return $strings;
	}

	/**
	 * Resend invite email.
	 *
	 * @param Request $request
	 *
	 * @defender_route
	 * @return Response
	 */
	public function resend_invite_email( Request $request ): Response {
		$data = $request->get_data(
			[
				'slug' => [
					'type' => 'string',
					'sanitize' => 'sanitize_textarea_field',
				],
				'email' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
				'id' => [
					'type' => 'integer',
				],
				'name' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
			]
		);

		$model = $this->service->find_module_by_slug( $data['slug'] );

		if ( ! is_object( $model ) ) {
			return new Response( false, [ 'message' => __( 'Module not found.', 'defender-security' ) ] );
		}

		$subscriber = [
			'email' => $data['email'],
			'name' => $data['name'],
		];

		if ( ! empty( $data['id'] ) ) {
			$subscriber['id'] = $data['id'];
		}
		// Resend invite email now.
		$sent = $this->service->send_email( $subscriber, $model );

		if ( $sent ) {
			return new Response( true, [ 'message' => __( 'Invitation sent successfully.', 'defender-security' ) ] );
		}

		return new Response(
			false, [
				'message' => __( 'Sorry! We could not send the invitation, Please try again later.', 'defender-security' ),
			]
		);
	}

	/**
	 * Get user roles with count.
	 *
	 * @defender_route
	 */
	public function get_user_roles() {
		$user_roles = $this->service->get_user_roles();

		wp_send_json_success( $user_roles );
	}
}
