<?php

namespace WP_Defender\Controller;

use Calotes\Component\Request;
use Calotes\Component\Response;
use Calotes\Helper\HTTP;
use Calotes\Helper\Route;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Event;
use WP_Defender\Traits\Formats;
use WP_Defender\Traits\IO;
use WP_Defender\Component\Feature_Modal;
use WP_Defender\Component\IP\Global_IP as Global_IP_Component;
use WP_Defender\Component\Config\Config_Hub_Helper;

/**
 * This class will use to create a main admin page.
 *
 * Class Dashboard
 * @package WP_Defender\Controller
 * @method bool is_pro
 */
class Dashboard extends Event {
	use IO, Formats;

	public $slug = 'wp-defender';

	public function __construct() {
		$this->attach_behavior( WPMUDEV::class, WPMUDEV::class );
		$this->add_main_page();
		$this->register_routes();
		add_action( 'defender_enqueue_assets', [ &$this, 'enqueue_assets' ] );
		add_filter( 'custom_menu_order', '__return_true' );
		add_filter( 'menu_order', [ &$this, 'menu_order' ] );
		add_action( 'admin_init', [ &$this, 'maybe_redirect_notification_request' ], 99 );
	}

	/**
	 * Because we move the notifications on separate modules, so links from HUB should be redirected to correct URL.
	 *
	 * @return void|null
	 */
	public function maybe_redirect_notification_request() {
		$page = HTTP::get( 'page' );
		if ( ! in_array( $page, [ 'wdf-scan', 'wdf-ip-lockout', 'wdf-hardener', 'wdf-logging' ], true ) ) {
			return;
		}
		$view = HTTP::get( 'view' );
		if ( in_array( $view, [ 'reporting', 'notification', 'report' ], true ) ) {
			wp_redirect( network_admin_url( 'admin.php?page=wdf-notification' ) );
			exit;
		}
	}

	/**
	 * Filter out the defender menu for changing text.
	 *
	 * @param $menu_order
	 *
	 * @return mixed
	 */
	public function menu_order( $menu_order ) {
		global $submenu;
		if ( isset( $submenu['wp-defender'] ) ) {
			$defender_menu = $submenu['wp-defender'];
			$defender_menu[0][0] = esc_html__( 'Dashboard', 'defender-security' );
			$defender_menu = array_values( $defender_menu );
			$submenu['wp-defender'] = $defender_menu;
		}

		global $menu;
		// Get the total scanning active issues.
		$count = wd_di()->get( \WP_Defender\Component\Scan::class )->indicator_issue_count();

		$indicator = $count > 0
			? ' <span class="update-plugins wd-issue-indicator-sidebar"><span class="plugin-count">' . $count . '</span></span>'
			: null;
		foreach ( $menu as $k => $item ) {
			if ( 'wp-defender' === $item[2] ) {
				$menu[ $k ][0] .= $indicator;
			}
		}

		return $menu_order;
	}

	protected function add_main_page() {
		$this->register_page(
			$this->get_menu_title(),
			$this->parent_slug,
			[
				&$this,
				'main_view',
			],
			null,
			$this->get_menu_icon()
		);
	}

	public function main_view() {
		$this->render( 'main' );
	}

	/**
	 * Enqueue assets & output data.
	 */
	public function enqueue_assets() {
		if ( ! $this->is_page_active() ) {
			return;
		}
		wp_localize_script( 'def-dashboard', 'dashboard', array_merge( $this->data_frontend(), $this->dump_routes_and_nonces() ) );
		wp_enqueue_script( 'def-dashboard' );
		$this->enqueue_main_assets();
	}

	/**
	 * @param Request $request
	 *
	 * @return Response
	 * @defender_route
	 */
	public function hide_new_features( Request $request ): Response {
		$data = $request->get_data(
			[
				'intention' => [
					'type' => 'string',
					'sanitize' => 'sanitize_text_field',
				],
			]
		);
		$intention = $data['intention'] ?? false;
		if ( 'welcome_modal' === $intention ) {
			Feature_Modal::delete_modal_key();
		}

		return new Response( true, [] );
	}

	/**
	 * Activate Global IP submodule with the enabled Autosync option.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function activate_global_ip(): Response {
		// Hide the modal.
		Feature_Modal::delete_modal_key();
		// Changes for Global IP.
		$model = wd_di()->get( \WP_Defender\Model\Setting\Global_Ip_Lockout::class );
		$model->enabled = true;
		$model->blocklist_autosync = true;
		$model->save();
		// Clear Global IP reminder
		wd_di()->get( Global_IP_Component::class )->delete_dashboard_notice_reminder();
		// Changes for Hub.
		Config_Hub_Helper::set_clear_active_flag();

		return new Response( true, [
			'redirect' => network_admin_url( 'admin.php?page=wdf-ip-lockout&view=global-ip' ),
			'interval' => 1,
		] );
	}

	/**
	 * Remove Global IP notice reminder.
	 *
	 * @return Response
	 * @defender_route
	 */
	public function remove_global_ip_notice_reminder(): Response {
		wd_di()->get( Global_IP_Component::class )->delete_dashboard_notice_reminder();

		return new Response( true, [] );
	}

	public function remove_settings() {
		wd_di()->get( Feature_Modal::class )->upgrade_site_options();
	}

	public function remove_data() {}

	/**
	 * @return array
	 */
	public function data_frontend(): array {
		[$endpoints, $nonces] = Route::export_routes( 'dashboard' );
		$firewall = wd_di()->get( Firewall::class );

		return array_merge(
			wd_di()->get( Feature_Modal::class )->get_dashboard_modals( true ),
			[
				'scan' => wd_di()->get( Scan::class )->data_frontend(),
				'firewall' => $firewall->data_frontend(),
				'waf' => wd_di()->get( WAF::class )->data_frontend(),
				'audit' => wd_di()->get( Audit_Logging::class )->data_frontend(),
				'blacklist' => [
					'nonces' => $nonces,
					'endpoints' => $endpoints,
				],
				'blocklist_monitor' => wd_di()->get( Blocklist_Monitor::class )->data_frontend(),
				'two_fa' => wd_di()->get( Two_Factor::class )->data_frontend(),
				'advanced_tools' => [
					'mask_login' => wd_di()->get( Mask_Login::class )->dashboard_widget(),
					'security_headers' => wd_di()->get( Security_Headers::class )->dashboard_widget(),
					'pwned_passwords' => wd_di()->get( Password_Protection::class )->dashboard_widget(),
					'recaptcha' => wd_di()->get( Recaptcha::class )->dashboard_widget(),
				],
				'security_tweaks' => wd_di()->get( Security_Tweaks::class )->data_frontend(),
				'tutorials' => wd_di()->get( Tutorial::class )->data_frontend(),
				'notifications' => wd_di()->get( Notification::class )->data_frontend(),
				'settings' => wd_di()->get( Main_Setting::class )->data_frontend(),
				'countries' => $firewall->dashboard_widget(),
				'global_ip' => wd_di()->get( Global_Ip::class )->data_frontend(),
			]
		);
	}

	public function to_array() {}

	public function import_data( $data ) {}

	/**
	 * @return array
	 */
	public function export_strings(): array {
		return [];
	}
}
