<?php

namespace WP_Defender\Component\Audit;

use Calotes\Helper\Array_Cache;
use WP_Defender\Traits\User;
use WP_Defender\Model\Audit_Log;

class Post_Audit extends Audit_Event {
	use User;

	/**
	 * Exclude events.
	 *
	 * @return array
	 * @since 3.9.0
	 */
	protected function exclude_events() {
		// Share excluded post types, e.g. from Hummingbird.
		$public_events = (array) apply_filters( 'wd_audit_excluded_post_types', [ 'wphb_minify_group' ] );
		$excluded_post_types = [
			// From Defender.
			'wdscan_result',
			'wdf_scan',
			'wd_iplockout_log',
			'wd_ip_lockout',
			'wdf_scan_item',
			// Default types.
			'nav_menu_item',
			'revision',
		];

		return array_unique( array_merge( $excluded_post_types, $public_events ) );
	}

	/**
	 * We will add a hook, for updated event, and cache that event content.
	 * Later we weill use the hook save post, to determine this is insert new post or update the cache will be
	 * the array of various post, as we don't want data be excluded. This way we can get more control.
	 */
	public function __construct() {
		add_action( 'post_updated', [ &$this, 'cache_post_updated' ], 10, 3 );
	}

	public function cache_post_updated( $post_id, $after, $before ) {
		Array_Cache::append(
			'post_updated',
			[
				'post_id' => $post_id,
				'after' => $after,
				'before' => $before,
			],
			'audit'
		);
	}

	/**
	 * @return array
	 */
	public function get_hooks(): array {
		return [
			'save_post' => [
				'args' => [ 'post_ID', 'post', 'is_updated' ],
				'callback' => [ self::class, 'post_updated_callback' ],
				'event_type' => Audit_Log::EVENT_TYPE_CONTENT,
				'action_type' => self::ACTION_UPDATED,
			],
			'transition_post_status' => [
				'args' => [ 'new_status', 'old_status', 'post' ],
				'event_type' => Audit_Log::EVENT_TYPE_CONTENT,
				'action_type' => self::ACTION_UPDATED,
				'false_when' => [
					[
						'{{post->post_status}}',
						[
							'inherit',
							'new',
							'auto-draft',
							'trash',
						],
					],
					[
						'{{post->post_type}}',
						$this->exclude_events(),
					],
					[
						'{{new_status}}',
						'{{old_status}}',
					],
					[
						'{{old_status}}',
						[
							'trash',
							'new',
						],
					],
				],
				'text' => [
					[
						sprintf(
						/* translators: 1: Blog name, 2: Source of action. For e.g. Hub or a logged-in user, 3: Post type, 4: Post title */
							__( '%1$s %2$s published %3$s "%4$s"', 'defender-security' ),
							'{{blog_name}}',
							'{{wp_user}}',
							'{{post_type_label}}',
							'{{post_title}}'
						),
						'{{new_status}}',
						'publish',
						'==',
					],
					[
						sprintf(
						/* translators: 1: Blog name, 2: Source of action. For e.g. Hub or a logged-in user, 3: Post type, 4: Post title */
							__( '%1$s %2$s pending %3$s "%4$s"', 'defender-security' ),
							'{{blog_name}}',
							'{{wp_user}}',
							'{{post_type_label}}',
							'{{post_title}}'
						),
						'{{new_status}}',
						'pending',
						'==',
					],
					[
						sprintf(
						/* translators: 1: Blog name, 2: Source of action. For e.g. Hub or a logged-in user, 3: Post type, 4: Post title */
							__( '%1$s %2$s drafted %3$s "%4$s"', 'defender-security' ),
							'{{blog_name}}',
							'{{wp_user}}',
							'{{post_type_label}}',
							'{{post_title}}'
						),
						'{{new_status}}',
						'draft',
						'==',
					],
					[
						sprintf(
						/* translators: 1: Blog name, 2: Source of action. For e.g. Hub or a logged-in user, 3: Post type, 4: Post title, 5: Old status, 6: New status */
							__( '%1$s %2$s changed %3$s "%4$s" status from %5$s to %6$s', 'defender-security' ),
							'{{blog_name}}',
							'{{wp_user}}',
							'{{post_type_label}}',
							'{{post_title}}',
							'{{old_status}}',
							'{{new_status}}'
						),
						'{{new_status}}',
						'{{new_status}}',
						'==',
					],
				],
				'program_args' => [
					'post_type_label' => [
						'callable' => 'get_post_type_object',
						'params' => [ '{{post->post_type}}' ],
						'result_property' => 'labels->singular_name',
					],
				],
				'custom_args' => [
					'post_title' => '{{post->post_title}}',
				],
				'context' => '{{post_type_label}}',
			],
			'delete_post' => [
				'args' => [ 'post_ID' ],
				'event_type' => Audit_Log::EVENT_TYPE_CONTENT,
				'action_type' => self::ACTION_DELETED,
				'text' => sprintf(
				/* translators: 1: Blog name, 2: Source of action. For e.g. Hub or a logged-in user, 3: Post type, 4: Post title */
					__( '%1$s %2$s deleted %3$s "%4$s"', 'defender-security' ),
					'{{blog_name}}',
					'{{wp_user}}',
					'{{post_type_label}}',
					'{{post_title}}'
				),
				'program_args' => [
					'post' => [
						'callable' => 'get_post',
						'params' => [ '{{post_ID}}' ],
					],
					'post_type_label' => [
						'callable' => 'get_post_type_object',
						'params' => [ '{{post->post_type}}' ],
						'result_property' => 'labels->singular_name',
					],
					'post_title' => [
						'callable' => 'get_post',
						'params' => [ '{{post_ID}}' ],
						'result_property' => 'post_title',
					],
				],
				'context' => '{{post_type_label}}',
				'false_when' => [
					[
						'{{post->post_type}}',
						array_merge(
							[ 'attachment' ],
							$this->exclude_events()
						),
					],
					[
						'{{post_type_label}}',
						'',
					],
				],
			],
			'untrashed_post' => [
				'args' => [ 'post_ID' ],
				'action_type' => self::ACTION_RESTORED,
				'event_type' => Audit_Log::EVENT_TYPE_CONTENT,
				'text' => sprintf(
				/* translators: 1: Blog name, 2: Source of action. For e.g. Hub or a logged-in user, 3: Post type, 4: Post title */
					__( '%1$s %2$s untrashed %3$s "%4$s"', 'defender-security' ),
					'{{blog_name}}',
					'{{wp_user}}',
					'{{post_type_label}}',
					'{{post_title}}'
				),
				'program_args' => [
					'post' => [
						'callable' => 'get_post',
						'params' => [ '{{post_ID}}' ],
					],
					'post_type_label' => [
						'callable' => 'get_post_type_object',
						'params' => [ '{{post->post_type}}' ],
						'result_property' => 'labels->singular_name',
					],
					'post_title' => [
						'callable' => 'get_post',
						'params' => [ '{{post_ID}}' ],
						'result_property' => 'post_title',
					],
				],
				'context' => '{{post_type_label}}',
			],
			'trashed_post' => [
				'args' => [ 'post_ID' ],
				'action_type' => self::ACTION_TRASHED,
				'event_type' => Audit_Log::EVENT_TYPE_CONTENT,
				'text' => sprintf(
				/* translators: 1: Blog name, 2: Source of action. For e.g. Hub or a logged-in user, 3: Post type, 4: Post title */
					__( '%1$s %2$s trashed %3$s "%4$s"', 'defender-security' ),
					'{{blog_name}}',
					'{{wp_user}}',
					'{{post_type_label}}',
					'{{post_title}}'
				),
				'program_args' => [
					'post' => [
						'callable' => 'get_post',
						'params' => [ '{{post_ID}}' ],
					],
					'post_type_label' => [
						'callable' => 'get_post_type_object',
						'params' => [ '{{post->post_type}}' ],
						'result_property' => 'labels->singular_name',
					],
					'post_title' => [
						'callable' => 'get_post',
						'params' => [ '{{post_ID}}' ],
						'result_property' => 'post_title',
					],
				],
				'context' => '{{post_type_label}}',
			],
		];
	}

	/**
	 * @return bool|array
	*/
	public function post_updated_callback() {
		if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
			return false;
		}

		$args = func_get_args();
		$post = $args[1]['post'];

		if ( in_array( $post->post_status, [ 'trash', 'auto-draft' ], true ) ) {
			// Usually, wp adds :trash to the post name, so this case we just return.
			return false;
		}

		if ( in_array( $post->post_type, $this->exclude_events(), true ) ) {
			return false;
		}

		$post_type = get_post_type_object( $post->post_type );
		if ( ! is_object( $post_type ) ) {
			return false;
		}

		$is_updated = $args[1]['is_updated'];
		$post_before = null;
		$cached = Array_Cache::get( 'post_updated', 'audit', [] );
		foreach ( $cached as $post_arr ) {
			if ( $post->ID === $post_arr['post_id'] ) {
				$post_before = $post_arr['before'];
				break;
			}
		}

		$blog_name = is_multisite() ? '[' . get_bloginfo( 'name' ) . ']' : '';
		if ( true === $is_updated ) {
			if ( ! is_null( $post_before ) ) {
				$post_after = $post->to_array();
				$post_before = $post_before->to_array();

				// Status transitions are handled via other hooks.
				if ( $post_before['post_status'] !== $post_after['post_status'] ) {
					return false;
				}

				// Unset the date modified, and post status, as we got another hook for that.
				unset( $post_after['post_modified'] );
				unset( $post_after['post_modified_gmt'] );
				unset( $post_after['post_status'] );
				unset( $post_before['post_modified'] );
				unset( $post_before['post_modified_gmt'] );
				unset( $post_before['post_status'] );
				if ( serialize( $post_before ) !== serialize( $post_after ) ) {
					$item_changed_count = count( self::array_recursive_diff( $post_before, $post_after ) );
					if ( $post_before['post_title'] !== $post_after['post_title'] && 1 === $item_changed_count ) {
						$text = sprintf(
							/* translators: 1: Blog name, 2: User's display name, 3: Post type, 4: Post ID, 5: Old post title, 6: New post title */
							__( '%1$s %2$s updated %3$s ID %4$d, title from "%5$s" to "%6$s"', 'defender-security' ),
							$blog_name,
							$this->get_user_display( get_current_user_id() ),
							$post_type->labels->singular_name,
							$post_after['ID'],
							$post_before['post_title'],
							$post_after['post_title']
						);
					} elseif ( $post_before['post_name'] !== $post_after['post_name'] && 1 === $item_changed_count ) {
						$text = sprintf(
							/* translators: 1: Blog name, 2: User's display name, 3: Post type, 4: Post ID, 5: Old post slug, 6: New post slug */
							__( '%1$s %2$s updated %3$s ID %4$d, slug from "%5$s" to "%6$s"', 'defender-security' ),
							$blog_name,
							$this->get_user_display( get_current_user_id() ),
							$post_type->labels->singular_name,
							$post_after['ID'],
							$post_before['post_name'],
							$post_after['post_name']
						);
					} elseif ( $post_before['post_author'] !== $post_after['post_author'] && 1 === $item_changed_count ) {
						$text = sprintf(
							/* translators: 1: Blog name, 2: User's display name, 3: Post type, 4: Post ID, 5: Old author name, 6: New author name */
							__( '%1$s %2$s updated %3$s ID %4$d, author from "%5$s" to "%6$s"', 'defender-security' ),
							$blog_name,
							$this->get_user_display( get_current_user_id() ),
							$post_type->labels->singular_name,
							$post_after['ID'],
							$this->get_user_display( $post_before['post_author'] ),
							$this->get_user_display( $post_after['post_author'] )
						);
					} else {
						$text = sprintf(
							/* translators: 1: Blog name, 2: User's display name, 3: Post type, 4: Post title */
							__( '%1$s %2$s updated %3$s "%4$s"', 'defender-security' ),
							$blog_name,
							$this->get_user_display( get_current_user_id() ),
							$post_type->labels->singular_name,
							$post_after['post_title']
						);
					}

					return [
						$text,
						$post_type->labels->singular_name,
					];
				}
			}
		} else {
			if ( is_null( $post_before ) ) {
				$text = sprintf(
				/* translators: 1: Blog name, 2: User's display name, 3: Post type, 4: Post title */
					__( '%1$s %2$s added new %3$s "%4$s"', 'defender-security' ),
					$blog_name,
					$this->get_user_display( get_current_user_id() ),
					$post_type->labels->singular_name,
					$post->post_title
				);

				return [
					$text,
					$post_type->labels->singular_name,
				];
			}
		}

		return false;
	}

	public function dictionary(): array {
		return [];
	}
}
