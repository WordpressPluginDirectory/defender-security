<?php

namespace WP_Defender\Component\Audit;

use WP_Defender\Traits\User;
use WP_Defender\Model\Audit_Log;

class Media_Audit extends Audit_Event {
	use User;

	public const ACTION_UPLOADED = 'uploaded';

	public function get_hooks(): array {
		return [
			'add_attachment' => [
				'args' => [ 'post_ID' ],
				'event_type' => Audit_Log::EVENT_TYPE_MEDIA,
				'action_type' => self::ACTION_UPLOADED,
				'text' => sprintf(
				/* translators: 1: Blog name, 2: Source of action. For e.g. Hub or a logged-in user, 3: File path */
					__( '%1$s %2$s uploaded a file: "%3$s" to Media Library', 'defender-security' ),
					'{{blog_name}}',
					'{{wp_user}}',
					'{{file_path}}'
				),
				'program_args' => [
					'file_path' => [
						'callable' => 'get_post_meta',
						'params' => [
							'{{post_ID}}',
							'_wp_attached_file',
							true,
						],
					],
					'mime_type' => [
						'callable' => [ self::class, 'get_mime_type' ],
						'params' => [
							'{{post_ID}}',
						],
					],
				],
				'context' => '{{mime_type}}',
			],
			'attachment_updated' => [
				'args' => [ 'post_ID' ],
				'action_type' => self::ACTION_UPDATED,
				'event_type' => Audit_Log::EVENT_TYPE_MEDIA,
				'text' => sprintf(
				/* translators: 1: Blog name, 2: Source of action. For e.g. Hub or a logged-in user, 3: File path */
					__( '%1$s %2$s updated a file: "%3$s" from Media Library', 'defender-security' ),
					'{{blog_name}}',
					'{{wp_user}}',
					'{{file_path}}'
				),
				'program_args' => [
					'file_path' => [
						'callable' => 'get_post_meta',
						'params' => [
							'{{post_ID}}',
							'_wp_attached_file',
							true,
						],
					],
					'mime_type' => [
						'callable' => [ self::class, 'get_mime_type' ],
						'params' => [
							'{{post_ID}}',
						],
					],
				],
				'context' => '{{mime_type}}',
			],
			'delete_attachment' => [
				'args' => [ 'post_ID' ],
				'action_type' => self::ACTION_DELETED,
				'event_type' => Audit_Log::EVENT_TYPE_MEDIA,
				'text' => sprintf(
				/* translators: 1: Blog name, 2: Source of action. For e.g. Hub or a logged-in user, 3: File path */
					__( '%1$s %2$s deleted a file: "%3$s" from Media Library', 'defender-security' ),
					'{{blog_name}}',
					'{{wp_user}}',
					'{{file_path}}'
				),
				'program_args' => [
					'file_path' => [
						'callable' => 'get_post_meta',
						'params' => [
							'{{post_ID}}',
							'_wp_attached_file',
							true,
						],
					],
					'mime_type' => [
						'callable' => [ self::class, 'get_mime_type' ],
						'params' => [
							'{{post_ID}}',
						],
					],
				],
				'context' => '{{mime_type}}',
			],
		];
	}

	public function dictionary(): array {
		return [
			self::ACTION_UPLOADED => esc_html__( 'Uploaded', 'defender-security' ),
		];
	}

	public function get_mime_type( $post_ID ) {
		$file_path = get_post_meta( $post_ID, '_wp_attached_file', true );

		return pathinfo( $file_path, PATHINFO_EXTENSION );
	}
}
