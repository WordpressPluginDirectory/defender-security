<?php

namespace WP_Defender;

use WP_Defender\Behavior\WPMUDEV;
use \WP_Defender\Component\Firewall;

if ( ! defined( 'ABSPATH' ) ) {
	die();
}

/**
 * Class Admin
 *
 * @since 2.4
 */
class Admin {

	/**
	 * @var bool
	 */
	public $is_pro;

	public function __construct() {
		$this->is_pro = ( new WPMUDEV() )->is_pro();
		add_action( 'wp_ajax_defender_ip_detection_notice_dismiss', [ $this, 'dismiss_notice' ] );
		add_action( 'wp_ajax_defender_ip_detection_switch_to_xff', [ $this, 'switch_to_xff' ] );
	}

	/**
	 * WP_DEFENDER_PRO sometimes doesn't match $this->is_pro, e.g. WPMU DEV Dashboard plugin is deactivated.
	 *
	 * @return bool.
	 */
	public function is_wp_org_version(): bool {
		return ! $this->is_pro && ( defined( 'WP_DEFENDER_PRO' ) && ! WP_DEFENDER_PRO );
	}

	/**
	 * Init admin actions.
	 */
	public function init() {
		// Display plugin links.
		add_filter( 'network_admin_plugin_action_links_' . DEFENDER_PLUGIN_BASENAME, [ $this, 'settings_link' ] );
		add_filter( 'plugin_action_links_' . DEFENDER_PLUGIN_BASENAME, [ $this, 'settings_link' ] );
		add_filter( 'plugin_row_meta', [ $this, 'plugin_row_meta' ], 10, 3 );
		// Only for plugin pages and actions are only for wp.org members.
		if ( $this->is_wp_org_version() ) {
			wd_di()->get( \WP_Defender\Component\Rate::class )->init();
			add_action( 'admin_init', [ $this, 'register_free_modules' ], 20 );
			// @since 4.4.0.
			add_action( 'wpdef_fixed_scan_issue', [ $this, 'after_scan_fix' ] );
			// For submenu callout.
			add_action( 'admin_head', [ $this, 'retarget_submenu_callout' ] );

			$message = __( 'Upgrade For 80% Off!', 'defender-security' );
			add_submenu_page(
				'wp-defender',
				$message,
				'<strong id="wpdef_menu_callout" style="color: #FECF2F; font-weight: 700;">' . $message . '</strong>',
				is_multisite() ? 'manage_network_options' : 'manage_options',
				'wdf-upsell',
				[ $this, 'menu_nope' ]
			);
		}
		// Display IP detection notice.
		if ( is_multisite() ) {
			add_action( 'network_admin_notices', [ &$this, 'admin_notices' ] );
		} else {
			add_action( 'admin_notices', [ &$this, 'admin_notices' ] );
		}
	}

	/**
	 * The method is a stub without content.
	*/
	private function menu_nope(): void {}

	public function retarget_submenu_callout(): void {
		$href = $this->get_link( 'upsell', 'defender_submenu_upsell' );
		echo "<script type='text/javascript'>
jQuery(document).ready(function($) {
	$('#wpdef_menu_callout').closest('a').attr('target', '_blank').attr('rel', 'noopener noreferrer').attr('href', '" . $href . "');
});
</script>";
	}

	/**
	 * Fired when the scan issue is fixed.
	 *
	 * @return void
	*/
	public function after_scan_fix(): void {
		\WP_Defender\Component\Rate::run_counter_of_fixed_scans();
	}

	/**
	 * Return URL link.
	 *
	 * @param string $link_for Accepts: 'docs', 'plugin', 'rate' and etc.
	 * @param string $campaign Utm campaign tag to be used in link. Default: ''.
	 * @param string $adv_path Advanced path. Default: ''.
	 *
	 * @return string
	 */
	public function get_link( $link_for, $campaign = '', $adv_path = '' ): string {
		$domain = 'https://wpmudev.com';
		$wp_org = 'https://wordpress.org';
		$utm_tags = "?utm_source=defender&utm_medium=plugin&utm_campaign={$campaign}";
		switch ( $link_for ) {
			case 'docs':
				$link = "{$domain}/docs/wpmu-dev-plugins/defender/{$utm_tags}";
				break;
			case 'plugin':
				$link = "{$domain}/project/wp-defender/{$utm_tags}";
				break;
			case 'rate':
				$link = "{$wp_org}/support/plugin/defender-security/reviews/#new-post";
				break;
			case 'support':
				$link = $this->is_pro ? "{$domain}/get-support/" : "{$wp_org}/support/plugin/defender-security/";
				break;
			case 'roadmap':
				$link = "{$domain}/roadmap/";
				break;
			case 'pro_link':
				$link = "{$domain}/$adv_path";
				break;
			case 'upsell':
				$link = "{$domain}/project/wp-defender/{$utm_tags}";
				break;
			default:
				$link = '';
				break;
		}

		return $link;
	}

	/**
	 * Adds a settings link on plugin page.
	 *
	 * @param array $links Current links.
	 *
	 * @return array
	 */
	public function settings_link( $links ): array {
		$action_links = [];
		$wpmu_dev = new WPMUDEV();
		// Dashboard-link.
		$action_links['dashboard'] = '<a href="' . network_admin_url( 'admin.php?page=wp-defender' ) . '" aria-label="' . esc_attr( __( 'Go to Defender Dashboard', 'defender-security' ) ) . '">' . esc_html__( 'Dashboard', 'defender-security' ) . '</a>';
		// Documentation-link.
		$action_links['docs'] = '<a target="_blank" href="' . $this->get_link( 'docs', 'defender_pluginlist_docs' ) . '" aria-label="' . esc_attr( __( 'Docs', 'defender-security' ) ) . '">' . esc_html__( 'Docs', 'defender-security' ) . '</a>';
		if ( ! $wpmu_dev->is_member() ) {
			if ( WP_DEFENDER_PRO_PATH !== DEFENDER_PLUGIN_BASENAME ) {
				$action_links['upgrade'] = '<a style="color: #8D00B1;" target="_blank" href="' . $this->get_link( 'plugin', 'defender_pluginlist_upgrade' ) . '" aria-label="' . esc_attr( __( 'Upgrade to Defender Pro', 'defender-security' ) ) . '">' . esc_html__( 'Upgrade For 80% Off!', 'defender-security' ) . '</a>';
			} elseif ( ! $wpmu_dev->is_hosted_site_connected_to_tfh() ) {
				$action_links['renew'] = '<a style="color: #8D00B1;" target="_blank" href="' . $this->get_link( 'plugin', 'defender_pluginlist_renew' ) . '" aria-label="' . esc_attr( __( 'Renew Your Membership', 'defender-security' ) ) . '">' . esc_html__( 'Renew Membership', 'defender-security' ) . '</a>';
			}
		}

		return array_merge( $action_links, $links );
	}

	/**
	 * Show row meta on the plugin screen.
	 *
	 * @param string[] $links       Plugin Row Meta.
	 * @param string   $file        Plugin Base file.
	 * @param array    $plugin_data Plugin data.
	 *
	 * @return array
	 */
	public function plugin_row_meta( $links, $file, $plugin_data ): array {
		$row_meta = [];
		if ( ! defined( 'DEFENDER_PLUGIN_BASENAME' ) || DEFENDER_PLUGIN_BASENAME !== $file ) {
			return $links;
		}

		// Change AuthorURI link.
		if ( isset( $links[1] ) ) {
			$author_uri = $this->is_pro ? 'https://wpmudev.com/' : 'https://profiles.wordpress.org/wpmudev/';
			$author_uri = sprintf(
				'<a href="%s" target="_blank">%s</a>',
				$author_uri,
				__( 'WPMU DEV', 'defender-security' )
			);
			$links[1] = sprintf(
				/* translators: %s: Author URI. */
				__( 'By %s', 'defender-security' ),
				$author_uri
			);
		}

		if ( ! $this->is_pro ) {
			// Change AuthorURI link.
			if ( isset( $links[2] ) && false === strpos( $links[2], 'target="_blank"' ) ) {
				if ( ! isset( $plugin_data['slug'] ) && $plugin_data['Name'] ) {
					$links[2] = sprintf(
						'<a href="%s" class="thickbox open-plugin-details-modal" aria-label="%s" data-title="%s">%s</a>',
						esc_url(
							network_admin_url(
								'plugin-install.php?tab=plugin-information&plugin=defender-security' .
								'&TB_iframe=true&width=600&height=550'
							)
						),
						/* translators: %s: Plugin name. */
						esc_attr( sprintf( __( 'More information about %s', 'defender-security' ), $plugin_data['Name'] ) ),
						esc_attr( $plugin_data['Name'] ),
						__( 'View details', 'defender-security' )
					);
				} else {
					$links[2] = str_replace( 'href=', 'target="_blank" href=', $links[2] );
				}
			}
			$row_meta['rate'] = '<a href="' . esc_url( $this->get_link( 'rate' ) ) . '" aria-label="' . esc_attr__( 'Rate Defender', 'defender-security' ) . '" target="_blank">' . esc_html__( 'Rate Defender', 'defender-security' ) . '</a>';
			$row_meta['support'] = '<a href="' . esc_url( $this->get_link( 'support' ) ) . '" aria-label="' . esc_attr__( 'Support', 'defender-security' ) . '" target="_blank">' . esc_html__( 'Support', 'defender-security' ) . '</a>';
		} else {
			// Change 'Visit plugins' link to 'View details'.
			if ( isset( $links[2] ) && false !== strpos( $links[2], 'project/wp-defender' ) ) {
				$links[2] = sprintf(
					'<a href="%s" target="_blank">%s</a>',
					esc_url( $this->get_link( 'pro_link', '', 'project/wp-defender/' ) ),
					__( 'View details', 'defender-security' )
				);
			}
			$row_meta['support'] = '<a href="' . esc_url( $this->get_link( 'support' ) ) . '" aria-label="' . esc_attr__( 'Premium Support', 'defender-security' ) . '" target="_blank">' . esc_html__( 'Premium Support', 'defender-security' ) . '</a>';
		}
		$row_meta['roadmap'] = '<a href="' . esc_url( $this->get_link( 'roadmap' ) ) . '" aria-label="' . esc_attr__( 'Roadmap', 'defender-security' ) . '" target="_blank">' . esc_html__( 'Roadmap', 'defender-security' ) . '</a>';

		return array_merge( $links, $row_meta );
	}

	/**
	 * Register sub-modules.
	 */
	public function register_free_modules() {
		if (
			! file_exists( defender_path( 'extra/free-dashboard/module.php' ) )
			|| ! file_exists( defender_path( 'extra/recommended-plugins-notice/notice.php' ) )
		) {
			return;
		}
		/* @noinspection PhpIncludeInspection */
		require_once defender_path( 'extra/free-dashboard/module.php' );
		/* @noinspection PhpIncludeInspection */
		require_once defender_path( 'extra/recommended-plugins-notice/notice.php' );

		// Register the current plugin.
		do_action(
			'wdev_register_plugin',
			/* 1             Plugin ID */ DEFENDER_PLUGIN_BASENAME,
			/* 2          Plugin Title */ 'Defender',
			/* 3 https://wordpress.org */ '/plugins/defender-security/',
			/* 4      Email Button CTA */ __( 'Get Fast!', 'defender-security' )
		);

		// Recommended plugin notice.
		do_action(
			'wpmudev-recommended-plugins-register-notice',
			DEFENDER_PLUGIN_BASENAME, // Plugin basename
			'Defender', // Plugin Name
			[
				'toplevel_page_wp-defender',
				'toplevel_page_wp-defender-network',
			],
			[ 'after', '.sui-wrap .sui-header' ]
		);
	}

	/**
	 * Display IP detection notices for if user site is behind proxy, e.g. Cloudflare or something else.
	 *
	 * @return void
	 */
	public function admin_notices(): void {
		$is_show = '';
		if ( Firewall::is_cf_notice_ready() ) {
			$is_show = 'cf';
			$class_notice = 'notice-info';
			$header = __( 'Cloudflare Usage Detected: Switched to CF-Connecting-IP for Better Compatibility', 'defender-security' );
		} elseif ( Firewall::is_xff_notice_ready() ) {
			$is_show = 'xff';
			$class_notice = 'notice-warning';
			$header = __( 'Improve IP Detection : We suggest Switching to X-Forward-For IP Detection Method', 'defender-security' );
		}
		// Hide if there is no slug.
		if ( '' === $is_show ) {
			return;
		}
		?>
		<div class="defender_ip_detection_notice notice <?php echo esc_attr( $class_notice ); ?> is-dismissible"
			data-nonce="<?php echo esc_attr( wp_create_nonce( 'defender_ip_detection_notice_dismiss' ) ); ?>"
			data-prop="notice-for-<?php echo esc_attr( $is_show ); ?>">
			<h3 style="margin-bottom:0;">
				<?php echo esc_html( $header ); ?>
			</h3>
			<?php if ( 'cf' === $is_show ) { ?>
				<p style="color: #72777C; line-height: 22px;">
					<?php
					/* translators: %s: Link. */
						printf(
						__( 'We have switched to using the CF-Connecting-IP HTTP header for IP detection, offering enhanced compatibility for users behind Cloudflare Proxy. If you wish to change this setting, you can do so from <a href="%s">here</a>.', 'defender-security' ),
						esc_url( network_admin_url( 'admin.php?page=wdf-ip-lockout&view=settings#detect-ip-addresses' ) )
					);
					?>
				</p>
				<p>
				<button type="button" class="button button-primary button-large defender_ip_detection_action_hide"
					data-prop="defender_ip_detection_notice_success"><?php esc_html_e( 'Ok, I understand', 'defender-security' ); ?>
				</button>
				</p>
			<?php } elseif ( 'xff' === $is_show ) { ?>
				<p style="color: #72777C; line-height: 22px;">
					<?php
					/* translators: %s: Link. */
						printf(
						__( 'Based on your server configuration, we recommend switching to the X-Forwarded-For method for accurate IP detection and to prevent firewall blocks. Easily modify your settings <a href="%s">here</a>.', 'defender-security' ),
						esc_url( network_admin_url( 'admin.php?page=wdf-ip-lockout&view=settings#detect-ip-addresses' ) )
					);
					?>
				</p>
				<p>
					<button type="button" class="button button-primary button-large" id="defender_ip_detection_action_switch"
						data-prop="defender_ip_detection_notice_success"><?php esc_html_e( 'Switch to X-Forwarded-For', 'defender-security' ); ?></button>
					<a href="#" class="defender_ip_detection_action_hide"
						style="margin-left: 11px; line-height: 16px; text-decoration: none;"
						data-prop="defender_ip_detection_notice_dismiss"><?php esc_html_e( 'Dismiss', 'defender-security' ); ?></a>
				</p>
			<?php } ?>
		</div>
		<script type="text/javascript">
			//Switch.
			jQuery('#defender_ip_detection_action_switch').on('click', function (e) {
				e.preventDefault();
				var $notice = jQuery(e.currentTarget).closest('.defender_ip_detection_notice'),
					ajaxUrl = '<?php echo admin_url( 'admin-ajax.php' ); ?>';

				jQuery.post(
					ajaxUrl,
					{
						action: 'defender_ip_detection_switch_to_xff',
						_ajax_nonce: $notice.data('nonce')
					}
				).always(function () {
					$notice.hide();
				});
			});
			//Hide.
			jQuery('body').on('click', '.defender_ip_detection_notice .notice-dismiss, .defender_ip_detection_action_hide', function (e) {
				e.preventDefault();
				var $notice = jQuery(e.currentTarget).closest('.defender_ip_detection_notice'),
					ajaxUrl = '<?php echo admin_url( 'admin-ajax.php' ); ?>';

				jQuery.post(
					ajaxUrl,
					{
						action: 'defender_ip_detection_notice_dismiss',
						prop: $notice.data('prop'),
						_ajax_nonce: $notice.data('nonce')
					}
				).always(function () {
					$notice.hide();
				});
			});
		</script>
		<?php
	}

	/**
	 * Dismiss notice.
	 *
	 * @return void
	 */
	public function dismiss_notice(): void {
		if (
			! current_user_can( 'manage_options' ) ||
			! check_ajax_referer( 'defender_ip_detection_notice_dismiss' )
		) {
			wp_send_json_error(
				[ 'message' => __( 'Invalid request, you are not allowed to do that action.', 'defender-security' ) ]
			);
		}

		$notice_type = ! empty( $_POST['prop'] ) ? sanitize_text_field( $_POST['prop'] ) : false;
		if ( 'notice-for-cf' === $notice_type ) {
			update_site_option( Firewall::IP_DETECTION_CF_DISMISS_SLUG, true );
			wp_send_json_success();
		} elseif( 'notice-for-xff' === $notice_type  ) {
			update_site_option( Firewall::IP_DETECTION_XFF_DISMISS_SLUG, true );
			wp_send_json_success();
		} else {
			wp_send_json_error(
				[ 'message' => __( 'Invalid request, allowed data not provided.', 'defender-security' ) ]
			);
		}
	}

	/**
	 * Switch to XFF option.
	 *
	 * @return void
	 */
	public function switch_to_xff(): void {
		if (
			! current_user_can( 'manage_options' ) ||
			! check_ajax_referer( 'defender_ip_detection_notice_dismiss' )
		) {
			wp_send_json_error(
				[ 'message' => __( 'Invalid request, you are not allowed to do that action.', 'defender-security' ) ]
			);
		}
		//Change model's data.
		$model_firewall = wd_di()->get( \WP_Defender\Model\Setting\Firewall::class );
		$model_firewall->http_ip_header = 'HTTP_X_FORWARDED_FOR';
		$xff_ip = sanitize_text_field( $_SERVER['HTTP_X_FORWARDED_FOR'] );
		if ( empty( $model_firewall->trusted_proxies_ip ) ) {
			$model_firewall->trusted_proxies_ip = $xff_ip;
		} else {
			// Todo: improve the code using a separate method. This will be useful when the user switches between different proxy headeres (IP detection options).
			$separator = "\r\n";
			// Check if the XFF header contains multiple IPs.
			$xff_ip = str_replace( [ ',', ' ,' ], $separator, $xff_ip );
			$model_firewall->trusted_proxies_ip = $model_firewall->trusted_proxies_ip . $separator . $xff_ip;
		}
		$model_firewall->save();
		//Save Dismiss slug.
		update_site_option( Firewall::IP_DETECTION_XFF_DISMISS_SLUG, true );
		wp_send_json_success();
	}
}
