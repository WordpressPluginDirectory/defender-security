<?php

namespace WP_Defender;

use WP_Defender\Behavior\WPMUDEV;

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
			add_action( 'wpdef_fixed_scan_issue', [ $this, 'after_scan_fix' ], 10, 2 );
			// For submenu callout.
			add_action( 'admin_head', [ $this, 'retarget_submenu_callout' ] );

			$message = __( 'Upgrade For 80% Off!', 'defender-security' );
			add_submenu_page(
				'wp-defender',
				$message,
				"<strong id=\"wpdef_menu_callout\" style=\"color: #FECF2F; font-weight: 700;\">" . $message . "</strong>",
				is_multisite() ? 'manage_network_options' : 'manage_options',
				'wdf-upsell',
				[ $this, 'menu_nope' ]
			);
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
	 * @param string $issue_type Scan issue type, e.g. plugin_integrity, malware or vulnerability.
	 * @param string $action     Scan action, e.g. delete or resolve.
	*/
	public function after_scan_fix( string $issue_type, string $action ): void {
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
				__( 'By %s', 'defender-security' ), $author_uri
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
		require_once( defender_path( 'extra/free-dashboard/module.php' ) );
		/* @noinspection PhpIncludeInspection */
		require_once( defender_path( 'extra/recommended-plugins-notice/notice.php' ) );

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
}
