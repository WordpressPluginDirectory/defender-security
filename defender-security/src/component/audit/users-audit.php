<?php

namespace WP_Defender\Component\Audit;

use WP_Defender\Traits\User;
use WP_Defender\Model\Audit_Log;

class Users_Audit extends Audit_Event {
	use User;

	public const ACTION_LOGIN = 'login', ACTION_LOGOUT = 'logout', ACTION_REGISTERED = 'registered',
		ACTION_LOST_PASS = 'lost_password', ACTION_RESET_PASS = 'reset_password';

	public const CONTEXT_SESSION = 'session', CONTEXT_USERS = 'users', CONTEXT_PROFILE = 'profile';

	public function get_hooks(): array {

		return [
			'wp_login_failed' => [
				'args' => [ 'username' ],
				'text' => sprintf(
				/* translators: 1: Blog name, 2: Username */
					esc_html__( '%1$s User login fail. Username: %2$s', 'defender-security' ),
					'{{blog_name}}',
					'{{username}}'
				),
				'event_type' => Audit_Log::EVENT_TYPE_USER,
				'context' => self::CONTEXT_SESSION,
				'action_type' => self::ACTION_LOGIN,
			],
			'wp_login' => [
				'args' => [ 'userlogin', 'user' ],
				'text' => sprintf(
				/* translators: 1: Blog name, 2: Username */
					esc_html__( '%1$s User login success: %2$s', 'defender-security' ),
					'{{blog_name}}',
					'{{userlogin}}'
				),
				'event_type' => Audit_Log::EVENT_TYPE_USER,
				'context' => self::CONTEXT_SESSION,
				'action_type' => self::ACTION_LOGIN,
			],
			'wpmu_2fa_login' => [
				'args' => [ 'user_id', '2fa_slug' ],
				'text' => sprintf(
				/* translators: 1: Blog name, 2: 2fa method slug, 3: Username. */
					esc_html__( '%1$s 2fa with %2$s method login success for user: %3$s', 'defender-security' ),
					'{{blog_name}}',
					'{{2fa_slug}}',
					'{{username}}'
				),
				'event_type' => Audit_Log::EVENT_TYPE_USER,
				'context' => self::CONTEXT_SESSION,
				'action_type' => self::ACTION_LOGIN,
				'program_args' => [
					'username' => [
						'callable' => 'get_user_by',
						'params' => [
							'id',
							'{{user_id}}',
						],
						'result_property' => 'user_login',
					],
				],
			],
			'wp_logout' => [
				'args' => [ 'user_id' ],
				'text' => sprintf(
				/* translators: 1: Blog name, 2: Username */
					esc_html__( '%1$s User logout success: %2$s', 'defender-security' ),
					'{{blog_name}}',
					'{{username}}'
				),
				'event_type' => Audit_Log::EVENT_TYPE_USER,
				'action_type' => self::ACTION_LOGOUT,
				'context' => self::CONTEXT_SESSION,
				'program_args' => [
					'username' => [
						'callable' => 'get_user_by',
						'params' => [
							'id',
							'{{user_id}}',
						],
						'result_property' => 'user_login',
					],
				],
			],
			'user_register' => [
				'args' => [ 'user_id' ],
				'text' => is_admin()
					? sprintf(
					/* translators: 1: Blog name, 2: Source of action. For e.g. Hub or a logged-in user, 3: Username, 4: User role */
						esc_html__( '%1$s %2$s added a new user: Username: %3$s, Role: %4$s', 'defender-security' ),
						'{{blog_name}}',
						'{{wp_user}}',
						'{{username}}',
						'{{user_role}}'
					)
					: sprintf(
					/* translators: 1: Blog name, 2: Username, 3: User role */
						esc_html__( '%1$s A new user registered: Username: %2$s, Role: %3$s', 'defender-security' ),
						'{{blog_name}}',
						'{{username}}',
						'{{user_role}}'
					),
				'event_type' => Audit_Log::EVENT_TYPE_USER,
				'context' => self::CONTEXT_USERS,
				'action_type' => self::ACTION_REGISTERED,
				'program_args' => [
					'username' => [
						'callable' => 'get_user_by',
						'params' => [
							'id',
							'{{user_id}}',
						],
						'result_property' => 'user_login',
					],
					'user_role' => [
						'callable' => [ self::class, 'get_user_role' ],
						'params' => [
							'{{user_id}}',
						],
					],
				],
			],
			'delete_user' => [
				'args' => [ 'user_id' ],
				'text' => sprintf(
				/* translators: 1: Blog name, 2: Source of action. For e.g. Hub or a logged-in user, 3: User ID, 4: Username */
					esc_html__( '%1$s %2$s deleted a user: ID: %3$s, username: %4$s', 'defender-security' ),
					'{{blog_name}}',
					'{{wp_user}}',
					'{{user_id}}',
					'{{username}}'
				),
				'context' => self::CONTEXT_USERS,
				'action_type' => self::ACTION_DELETED,
				'event_type' => Audit_Log::EVENT_TYPE_USER,
				'program_args' => [
					'username' => [
						'callable' => 'get_user_by',
						'params' => [
							'id',
							'{{user_id}}',
						],
						'result_property' => 'user_login',
					],
				],
			],
			'remove_user_from_blog' => [
				'args' => [ 'user_id', 'blog_id' ],
				'context' => self::CONTEXT_USERS,
				'action_type' => self::ACTION_DELETED,
				'event_type' => Audit_Log::EVENT_TYPE_USER,
				'callback' => [ self::class, 'remove_user_from_blog_callback' ],
			],
			'wpmu_delete_user' => [
				'args' => [ 'user_id' ],
				'text' => sprintf(
				/* translators: 1: Blog name, 2: Source of action. For e.g. Hub or a logged-in user, 3: User ID, 4: Username */
					esc_html__( '%1$s %2$s deleted a user: ID: %3$s, username: %4$s', 'defender-security' ),
					'{{blog_name}}',
					'{{wp_user}}',
					'{{user_id}}',
					'{{username}}'
				),
				'context' => self::CONTEXT_USERS,
				'action_type' => self::ACTION_DELETED,
				'event_type' => Audit_Log::EVENT_TYPE_USER,
				'program_args' => [
					'username' => [
						'callable' => 'get_user_by',
						'params' => [
							'id',
							'{{user_id}}',
						],
						'result_property' => 'user_login',
					],
				],
			],
			'profile_update' => [
				'args' => [ 'user_id', 'old_user_data' ],
				'action_type' => self::ACTION_UPDATED,
				'event_type' => Audit_Log::EVENT_TYPE_USER,
				'context' => self::CONTEXT_PROFILE,
				'callback' => [ self::class, 'profile_update_callback' ],
			],
			'retrieve_password' => [
				'args' => [ 'username' ],
				'text' => sprintf(
				/* translators: 1: Blog name, 2: Username */
					esc_html__( '%1$s Password requested to reset for user: %2$s', 'defender-security' ),
					'{{blog_name}}',
					'{{username}}'
				),
				'action_type' => self::ACTION_LOST_PASS,
				'event_type' => Audit_Log::EVENT_TYPE_USER,
				'context' => self::CONTEXT_PROFILE,
				'program_args' => [
					'user' => [
						'callable' => 'get_user_by',
						'params' => [
							'login',
							'{{username}}',
						],
					],
				],
			],
			'after_password_reset' => [
				'args' => [ 'user' ],
				'text' => sprintf(
				/* translators: 1: Blog name, 2: Username. */
					esc_html__( '%1$s Password reset for user: %2$s', 'defender-security' ),
					'{{blog_name}}',
					'{{user_login}}'
				),
				'event_type' => Audit_Log::EVENT_TYPE_USER,
				'action_type' => self::ACTION_RESET_PASS,
				'context' => self::CONTEXT_PROFILE,
				'custom_args' => [
					'user_login' => '{{user->user_login}}',
				],
			],
			'set_user_role' => [
				'args' => [ 'user_ID', 'new_role', 'old_role' ],
				'text' => sprintf(
				/* translators: 1: Blog name, 2: Source of action. For e.g. Hub or a logged-in user, 3: Username, 4: Old user role, 5: New user role */
					__( "%1\$s %2\$s changed user %3\$s's role from %4\$s to %5\$s", 'defender-security' ),
					'{{blog_name}}',
					'{{wp_user}}',
					'{{username}}',
					'{{from_role}}',
					'{{new_role}}'
				),
				'action_type' => self::ACTION_UPDATED,
				'event_type' => Audit_Log::EVENT_TYPE_USER,
				'context' => self::CONTEXT_PROFILE,
				'custom_args' => [
					'from_role' => '{{old_role->0}}',
				],
				'program_args' => [
					'username' => [
						'callable' => 'get_user_by',
						'params' => [
							'id',
							'{{user_ID}}',
						],
						'result_property' => 'user_login',
					],
				],
				'false_when' => [
					[
						'{{old_role}}',
						[],
						'==',
					],
				],
			],
		];
	}

	/**
	 * Log when user is removed from a blog.
	 *
	 * @return bool|array
	 */
	public function remove_user_from_blog_callback() {
		if ( self::is_create_user_action() ) {
			return false;
		}

		$args = func_get_args();
		$user_id = $args[1]['user_id'];
		$blog_id = $args[1]['blog_id'];
		$user = get_user_by( 'id', $user_id );
		$username = $user->user_login ?? '';
		$current_user_display = $this->get_user_display( get_current_user_id() );
		$blog_name = is_multisite() ? '[' . get_bloginfo( 'name' ) . ']' : '';

		return [
			sprintf(
			/* translators: 1: Blog name, 2: User's display name, 3: User ID, 4: Username, 5: Blog ID */
				esc_html__( '%1$s %2$s removed a user: ID: %3$s, username: %4$s from blog %5$s', 'defender-security' ),
				$blog_name,
				$current_user_display,
				$user_id,
				$username,
				$blog_id
			),
			self::ACTION_DELETED,
		];
	}

	/**
	 * @return bool|array
	 */
	public function profile_update_callback() {
		if ( self::is_create_user_action() ) {
			return false;
		}

		$args = func_get_args();
		$user_id = $args[1]['user_id'];
		$current_user = get_user_by( 'id', $user_id );
		$blog_name = is_multisite() ? '[' . get_bloginfo( 'name' ) . ']' : '';
		$current_user_id = get_current_user_id();

		if ( $current_user_id === $user_id ) {

			return [
				sprintf(
				/* translators: 1: Blog name, 2: User's nicename */
					esc_html__( '%1$s User %2$s updated his/her profile', 'defender-security' ),
					$blog_name,
					$current_user->user_nicename
				),
				self::ACTION_UPDATED,
			];
		} elseif ( 0 !== $current_user_id ) {

			return [
				sprintf(
				/* translators: 1: Blog name, 2: User's display name, 3: User's nicename */
					__( "%1\$s %2\$s updated user %3\$s's profile information", 'defender-security' ),
					$blog_name,
					$this->get_user_display( $current_user_id ),
					$current_user->user_nicename
				),
				self::ACTION_UPDATED,
			];
		}
	}

	/**
	 * @return array
	 */
	public function dictionary(): array {
		return [
			self::ACTION_LOST_PASS => esc_html__( 'lost password', 'defender-security' ),
			self::ACTION_REGISTERED => esc_html__( 'registered', 'defender-security' ),
			self::ACTION_LOGIN => esc_html__( 'login', 'defender-security' ),
			self::ACTION_LOGOUT => esc_html__( 'logout', 'defender-security' ),
			self::ACTION_RESET_PASS => esc_html__( 'password reset', 'defender-security' ),
		];
	}

	/**
	 * @param int $user_id
	 *
	 * @return string
	 */
	public static function get_user_role( $user_id ): string {
		$user = get_user_by( 'id', $user_id );
		if ( $user instanceof \WP_User ) {
			$_this = new self();

			return $_this->get_first_user_role( $user );
		} else {
			return '';
		}
	}

	/**
	 * Check if it is a create new user request.
	 *
	 * @since 2.8.0
	 * @retun bool
	 */
	public static function is_create_user_action(): bool {
		$action = ! empty( $_POST['action'] ) ? sanitize_text_field( $_POST['action'] ) : false; // phpcs:ignore
		if ( 'createuser' === $action ) {
			return true;
		}

		return false;
	}
}
