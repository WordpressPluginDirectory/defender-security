<?php
/**
 * Handle common bootstrap functionalities.
 *
 * @package WP_Defender
 */

namespace WP_Defender\Traits;

use Calotes\DB\Mapper;
use Calotes\Helper\Array_Cache;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Component\Cli;
use WP_Defender\Controller\Advanced_Tools;
use WP_Defender\Controller\Dashboard;
use WP_Defender\Controller\Audit_Logging;
use WP_Defender\Controller\Firewall;
use WP_Defender\Controller\HUB;
use WP_Defender\Controller\Mask_Login;
use WP_Defender\Controller\Notification;
use WP_Defender\Controller\Onboard;
use WP_Defender\Controller\Password_Protection;
use WP_Defender\Controller\Recaptcha;
use WP_Defender\Controller\Scan;
use WP_Defender\Controller\Security_Headers;
use WP_Defender\Controller\Security_Tweaks;
use WP_Defender\Controller\Two_Factor;
use WP_Defender\Controller\Main_Setting;
use WP_Defender\Controller\WAF;
use WP_Defender\Controller\Tutorial;
use WP_Defender\Controller\Blocklist_Monitor;
use WP_Defender\Controller\Password_Reset;
use WP_Defender\Controller\Webauthn;
use WP_Defender\Controller\Quarantine;
use WP_Defender\Controller\Data_Tracking;

/**
 * Traits to handle common (pro & free) bootstrap functionalities.
 */
trait Defender_Bootstrap {

	private $quarantine_table = 'defender_quarantine';

	private $scan_item_table = 'defender_scan_item';

	/**
	 * Check is all quarantine dependent table is having storage engine InnoDB.
	 *
	 * @return bool True if all dependent table is InnoDB else false.
	 */
	private function is_quarantine_dependent_tables_innodb(): bool {
		global $wpdb;

		$tables = [ $wpdb->users, $wpdb->base_prefix . $this->scan_item_table ];
		$total_table = count( $tables );

		$tables_placeholder = implode( ',', array_fill( 0, $total_table, '%s' ) );
		$prepared_values = array_merge(
			[
				$total_table,
				$wpdb->dbname,
				'innodb',
			],
			$tables
		);

		$sql = <<<SQL
			SELECT
				COUNT(`ENGINE`) = %d
			FROM   information_schema.TABLES
			WHERE
				TABLE_SCHEMA = '%s'
				AND `ENGINE` = '%s'
				AND TABLE_NAME IN ( $tables_placeholder );
SQL;

		$prepared_statement = $wpdb->prepare(
			$sql,
			$prepared_values
		);

		return $wpdb->get_var( $prepared_statement ) === '1';
	}

	public function create_table_quarantine() {
		global $wpdb;

		if ( ! $this->table_exists( $this->quarantine_table ) ) {
			$quarantine_table = $wpdb->base_prefix . $this->quarantine_table;
			$scan_item_table = $wpdb->base_prefix . $this->scan_item_table;
			$charset_collate = $wpdb->get_charset_collate();

			if ( $this->is_quarantine_dependent_tables_innodb() ) {
				$sql = <<<SQL
					CREATE TABLE IF NOT EXISTs `{$quarantine_table}` (
						`id` bigint unsigned NOT NULL AUTO_INCREMENT,
						`defender_scan_item_id` int UNSIGNED DEFAULT NULL,
						`file_hash` char(53) NOT NULL,
						`file_full_path` text NOT NULL,
						`file_original_name` tinytext NOT NULL,
						`file_extension` varchar(16) DEFAULT NULL,
						`file_mime_type` varchar(64) DEFAULT NULL,
						`file_rw_permission` smallint UNSIGNED,
						`file_owner` varchar(255) DEFAULT NULL,
						`file_group` varchar(255) DEFAULT NULL,
						`file_version` varchar(32) DEFAULT NULL,
						`file_category` tinyint UNSIGNED DEFAULT 0,
						`file_modified_time` datetime NOT NULL,
						`source_slug` varchar(255) NOT NULL,
						`created_time` datetime NOT NULL,
						`created_by` bigint UNSIGNED DEFAULT NULL,
						PRIMARY KEY (`id`),
						CONSTRAINT `fk_defender_scan_item`
							FOREIGN KEY (`defender_scan_item_id`) REFERENCES {$scan_item_table}(`id`)
							ON UPDATE CASCADE ON DELETE SET NULL,
						CONSTRAINT `fk_created_by`
							FOREIGN KEY (`created_by`) REFERENCES {$wpdb->users}(`id`)
							ON UPDATE CASCADE ON DELETE SET NULL
					) {$charset_collate};
SQL;
			} else {
				$sql = <<<SQL
					CREATE TABLE IF NOT EXISTs `{$quarantine_table}` (
						`id` bigint unsigned NOT NULL AUTO_INCREMENT,
						`defender_scan_item_id` int UNSIGNED DEFAULT NULL,
						`file_hash` char(53) NOT NULL,
						`file_full_path` text NOT NULL,
						`file_original_name` tinytext NOT NULL,
						`file_extension` varchar(16) DEFAULT NULL,
						`file_mime_type` varchar(64) DEFAULT NULL,
						`file_rw_permission` smallint UNSIGNED,
						`file_owner` varchar(255) DEFAULT NULL,
						`file_group` varchar(255) DEFAULT NULL,
						`file_version` varchar(32) DEFAULT NULL,
						`file_category` tinyint UNSIGNED DEFAULT 0,
						`file_modified_time` datetime NOT NULL,
						`source_slug` varchar(255) NOT NULL,
						`created_time` datetime NOT NULL,
						`created_by` bigint UNSIGNED DEFAULT NULL,
						PRIMARY KEY (`id`),
						KEY `defender_scan_item_id` (`defender_scan_item_id`),
						KEY `created_by` (`created_by`)
					) {$charset_collate};
SQL;
			}

			$wpdb->query( $sql );
		}
	}

	/**
	 * Activation.
	 */
	private function activation_hook_common(): void {
		$this->create_database_tables();
		$this->on_activation();
		// Create a file with a random key if it doesn't exist.
		( new \WP_Defender\Component\Crypt() )->create_key_file();
		// If this is a plugin reactivatin, then track it. No need the check by 'wd_nofresh_install' key because the option is disabled by default.
		$settings = wd_di()->get( Main_Setting::class );
		$settings->set_intention( 'Reactivation' );
		$settings->track_opt( true );
	}

	/**
	 * Deactivation.
	 */
	public function deactivation_hook(): void {
		wp_clear_scheduled_hook( 'firewall_clean_up_logs' );
		wp_clear_scheduled_hook( 'audit_sync_events' );
		wp_clear_scheduled_hook( 'audit_clean_up_logs' );
		wp_clear_scheduled_hook( 'wdf_maybe_send_report' );
		wp_clear_scheduled_hook( 'wp_defender_clear_logs' );
		wp_clear_scheduled_hook( 'wpdef_sec_key_gen' );
		wp_clear_scheduled_hook( 'wpdef_clear_scan_logs' );
		wp_clear_scheduled_hook( 'wpdef_log_rotational_delete' );
		wp_clear_scheduled_hook( 'wpdef_update_geoip' );
		wp_clear_scheduled_hook( 'wpdef_fetch_global_ip_list' );
		wp_clear_scheduled_hook( 'wpdef_quarantine_delete_expired' );
		wp_clear_scheduled_hook( 'wpdef_firewall_clean_up_lockout' );

		// Remove old legacy cron jobs if they exist.
		wp_clear_scheduled_hook( 'lockoutReportCron' );
		wp_clear_scheduled_hook( 'auditReportCron' );
		wp_clear_scheduled_hook( 'cleanUpOldLog' );
		wp_clear_scheduled_hook( 'scanReportCron' );
		wp_clear_scheduled_hook( 'tweaksSendNotification' );
	}

	/**
	 * Creates Defender's tables.
	 * @since 2.7.1 No use dbDelta because PHP v8.1 triggers an error when calling query "DESCRIBE {$table};" if the table doesn't exist.
	 */
	protected function create_database_tables(): void {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();
		// Hide errors.
		$wpdb->hide_errors();
		// Email log table.
		if ( ! $this->table_exists( 'defender_email_log' ) ) {
			$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}defender_email_log (
 `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
 `timestamp` int NOT NULL,
 `source` varchar(255) NOT NULL,
 `to` varchar(255) NOT NULL,
 PRIMARY KEY  (`id`),
 KEY `source` (`source`)
) $charset_collate;";
			$wpdb->query( $sql );
		}
		// Audit log table. Though our data mainly store on API side, we will need a table for caching.
		if ( ! $this->table_exists( 'defender_audit_log' ) ) {
			$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}defender_audit_log (
 `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
 `timestamp` int NOT NULL,
 `event_type` varchar(255) NOT NULL,
 `action_type` varchar(255) NOT NULL,
 `site_url` varchar(255) NOT NULL,
 `user_id` int NOT NULL,
 `context` varchar(255) NOT NULL,
 `ip` varchar(45) NOT NULL,
 `msg` varchar(255) NOT NULL,
 `blog_id` int NOT NULL,
 `synced` int NOT NULL,
 `ttl` int NOT NULL,
 PRIMARY KEY  (`id`),
 KEY `event_type` (`event_type`),
 KEY `action_type` (`action_type`),
 KEY `user_id` (`user_id`),
 KEY `context` (`context`),
 KEY `ip` (`ip`)
) $charset_collate;";
			$wpdb->query( $sql );
		}
		// Scan item table.
		if ( ! $this->table_exists( 'defender_scan_item' ) ) {
			$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}defender_scan_item (
 `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
 `parent_id` int NOT NULL,
 `type` varchar(255) NOT NULL,
 `status` varchar(255) NOT NULL,
 `raw_data` text NOT NULL,
 PRIMARY KEY  (`id`),
 KEY `type` (`type`),
 KEY `status` (`status`)
) $charset_collate;";
			$wpdb->query( $sql );
		}
		// Scan table.
		if ( ! $this->table_exists( 'defender_scan' ) ) {
			$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}defender_scan (
 `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
 `percent` float NOT NULL,
 `total_tasks` tinyint(4) NOT NULL,
 `task_checkpoint` varchar(255) NOT NULL,
 `status` varchar(255) NOT NULL,
 `date_start` datetime NOT NULL,
 `date_end` datetime NOT NULL,
 `is_automation` bool NOT NULL,
 PRIMARY KEY  (`id`)
) $charset_collate;";
			$wpdb->query( $sql );
		}
		// Lockout log table.
		if ( ! $this->table_exists( 'defender_lockout_log' ) ) {
			$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}defender_lockout_log (
 `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
 `log` text,
 `ip` varchar(45) DEFAULT NULL,
 `date` int(11) DEFAULT NULL,
 `type` varchar(16) DEFAULT NULL,
 `user_agent` varchar(255) DEFAULT NULL,
 `blog_id` int(11) DEFAULT NULL,
 `tried` varchar(255),
 `country_iso_code` char(2) DEFAULT NULL,
 PRIMARY KEY  (`id`),
 KEY `ip` (`ip`),
 KEY `type` (`type`),
 KEY `tried` (`tried`),
 KEY `country_iso_code` (`country_iso_code`)
) $charset_collate;";
			$wpdb->query( $sql );
		}
		// Lockout table.
		if ( ! $this->table_exists( 'defender_lockout' ) ) {
			$sql = "CREATE TABLE IF NOT EXISTS {$wpdb->base_prefix}defender_lockout (
 `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
 `ip` varchar(45) DEFAULT NULL,
 `status` varchar(16) DEFAULT NULL,
 `lockout_message` text,
 `release_time` int(11) DEFAULT NULL,
 `lock_time` int(11) DEFAULT NULL,
 `lock_time_404` int(11) DEFAULT NULL,
 `attempt` int(11) DEFAULT NULL,
 `attempt_404` int(11) DEFAULT NULL,
 `meta` text,
 PRIMARY KEY  (`id`),
 KEY `ip` (`ip`),
 KEY `status` (`status`),
 KEY `attempt` (`attempt`),
 KEY `attempt_404` (`attempt_404`)
) $charset_collate;";
			$wpdb->query( $sql );
		}

		if ( class_exists( 'WP_Defender\Controller\Quarantine' ) ) {
			$this->create_table_quarantine();
		}
	}

	private function init_modules_common(): void {
		// Init main ORM.
		Array_Cache::set( 'orm', new Mapper() );
		/**
		 * Display Onboarding if:
		 * it's a fresh install and there were no requests from the Hub before,
		 * after Reset Settings.
		 *
		 * @var HUB
		 */
		$hub_class = wd_di()->get( HUB::class );
		$hub_class->set_onboarding_status( $this->maybe_show_onboarding() );
		if ( $hub_class->get_onboarding_status() && ! defender_is_wp_cli() ) {
			// If it's cli we should start this normally.
			Array_Cache::set( 'onboard', wd_di()->get( Onboard::class ) );
		} else {
			// Initialize the main controllers of every module.
			wd_di()->get( Dashboard::class );
		}
		wd_di()->get( Security_Tweaks::class );
		wd_di()->get( Scan::class );
		wd_di()->get( Audit_Logging::class );
		wd_di()->get( Firewall::class );
		wd_di()->get( WAF::class );
		wd_di()->get( Two_Factor::class );
		wd_di()->get( Advanced_Tools::class );
		wd_di()->get( Mask_Login::class );
		wd_di()->get( Security_Headers::class );
		wd_di()->get( Recaptcha::class );
		wd_di()->get( Notification::class );
		wd_di()->get( Main_Setting::class );
		wd_di()->get( Tutorial::class );
		wd_di()->get( Blocklist_Monitor::class );
		wd_di()->get( Password_Protection::class );
		wd_di()->get( Password_Reset::class );
		wd_di()->get( Webauthn::class );

		if ( class_exists( 'WP_Defender\Controller\Quarantine' ) ) {
			wd_di()->get( Quarantine::class );
		}
		wd_di()->get( Data_Tracking::class );
	}

	/**
	 * @return bool
	 */
	private function maybe_show_onboarding(): bool {
		// First we need to check if the site is newly create.
		global $wpdb;
		if ( ! is_multisite() ) {
			$res = $wpdb->get_var( "SELECT option_value FROM $wpdb->options WHERE option_name = 'wp_defender_shown_activator'" );
		} else {
			$sql = $wpdb->prepare(
				"SELECT meta_value FROM $wpdb->sitemeta WHERE meta_key = 'wp_defender_shown_activator' AND site_id = %d",
				get_current_network_id()
			);
			$res = $wpdb->get_var( $sql );
		}
		// Get '1' for direct SQL request if Onboarding was already.
		if ( empty( $res ) ) {
			return true;
		}

		return false;
	}

	/**
	 * @param string $classes
	 *
	 * @return string
	 */
	public function add_sui_to_body( string $classes ): string {
		if ( ! is_defender_page() ) {
			return $classes;
		}
		$classes .= sprintf( ' sui-%s ', DEFENDER_SUI );

		return $classes;
	}

	private function register_styles(): void {
		wp_enqueue_style( 'defender-menu', WP_DEFENDER_BASE_URL . 'assets/css/defender-icon.css' );

		$css_files = [
			'defender' => WP_DEFENDER_BASE_URL . 'assets/css/styles.css',
		];

		foreach ( $css_files as $slug => $file ) {
			wp_register_style( $slug, $file, [], DEFENDER_VERSION );
		}
	}

	private function register_scripts(): void {
		$base_url = WP_DEFENDER_BASE_URL;
		$dependencies = [ 'def-vue', 'defender', 'wp-i18n' ];
		$js_files = [
			'wpmudev-sui' => [
				$base_url . 'assets/js/shared-ui.js',
			],
			'defender' => [
				$base_url . 'assets/js/scripts.js',
			],
			'def-vue' => [
				$base_url . 'assets/js/vendor/vue.runtime.min.js',
			],
			'def-dashboard' => [
				$base_url . 'assets/app/dashboard.js',
				$dependencies,
			],
			'def-securitytweaks' => [
				$base_url . 'assets/app/security-tweak.js',
				array_merge( $dependencies, [ 'clipboard', 'wpmudev-sui' ] ),
			],
			'def-scan' => [
				$base_url . 'assets/app/scan.js',
				array_merge( $dependencies, [ 'clipboard', 'wpmudev-sui' ] ),
			],
			'def-audit' => [
				$base_url . 'assets/app/audit.js',
				$dependencies,
			],
			'def-iplockout' => [
				$base_url . 'assets/app/ip-lockout.js',
				array_merge( $dependencies, [ 'wpmudev-sui' ] ),
			],
			'def-advancedtools' => [
				$base_url . 'assets/app/advanced-tools.js',
				$dependencies,
			],
			'def-settings' => [
				$base_url . 'assets/app/settings.js',
				$dependencies,
			],
			'def-2fa' => [
				$base_url . 'assets/app/two-fa.js',
				$dependencies,
			],
			'def-notification' => [
				$base_url . 'assets/app/notification.js',
				$dependencies,
			],
			'def-waf' => [
				$base_url . 'assets/app/waf.js',
				$dependencies,
			],
			'def-onboard' => [
				$base_url . 'assets/app/onboard.js',
				$dependencies,
			],
			'def-tutorial' => [
				$base_url . 'assets/app/tutorial.js',
				$dependencies,
			],
		];

		foreach ( $js_files as $slug => $file ) {
			if ( isset( $file[1] ) ) {
				wp_register_script( $slug, $file[0], $file[1], DEFENDER_VERSION, true );
			} else {
				wp_register_script( $slug, $file[0], [ 'jquery' ], DEFENDER_VERSION, true );
			}
		}
	}

	private function localize_script(): void {
		$wpmu_dev = new WPMUDEV();
		global $wp_defender_central;

		$misc = [];

		/**
		 * @var Data_Tracking
		 */
		$data_tracking = wd_di()->get( Data_Tracking::class );
		$is_tracking = $data_tracking->show_tracking_modal();
		if ( $is_tracking ) {
			$misc = $data_tracking->get_tracking_modal();
		}
		$misc['high_contrast'] = defender_high_contrast();

		wp_localize_script(
			'def-vue',
			'defender',
			[
				'whitelabel' => defender_white_label_status(),
				'misc' => $misc,
				'home_url' => network_home_url(),
				'site_url' => network_site_url(),
				'admin_url' => network_admin_url(),
				'defender_url' => WP_DEFENDER_BASE_URL,
				'is_free' => $wpmu_dev->is_pro() ? 0 : 1,
				'is_membership' => true,
				'is_whitelabel' => $wpmu_dev->is_whitelabel_enabled() ? 'enabled' : 'disabled',
				'wpmu_dev_url_action' => $wpmu_dev->hide_wpmu_dev_urls() ? 'hide' : 'show',
				'opcache_save_comments' => $wp_defender_central->is_opcache_save_comments_disabled() ? 'disabled' : 'enabled',
				'opcache_message' => $wp_defender_central->display_opcache_message(),
				'wpmudev_url' => 'https://wpmudev.com/docs/wpmu-dev-plugins/defender/',
				'wpmudev_support_ticket_text' => defender_support_ticket_text(),
				'wpmudev_api_base_url' => $wpmu_dev->get_api_base_url(),
				'upgrade_title' => __( 'UPGRADE TO PRO', 'defender-security' ),
				'tracking_modal' => $is_tracking ? 'show' : 'hide',
			]
		);

		wp_localize_script( 'defender', 'defenderGetText', defender_gettext_translations() );
	}

	/**
	 * Register all core assets.
	 */
	public function register_assets(): void {
		$this->register_styles();
		$this->register_scripts();
		$this->localize_script();

		do_action( 'defender_enqueue_assets' );
	}

	/**
	 * Check to exist table.
	 *
	 * @param string $table_name
	 *
	 * @return bool
	 */
	private function table_exists( $table_name ): bool {
		global $wpdb;
		// Full table name.
		$table_name = $wpdb->base_prefix . $table_name;

		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) ) === $table_name;
	}

	/**
	 * Check and create tables if its aren't existed.
	 */
	public function check_if_table_exists(): void {
		$this->create_database_tables();
	}

	/**
	 * Trigger mandatory actions on activation.
	 */
	private function on_activation(): void {
		add_action(
			'admin_init',
			function() {
				/**
				 * @var Security_Tweaks
				 */
				$security_tweaks = wd_di()->get( Security_Tweaks::class );
				$security_tweaks->get_security_key()->cron_schedule();
			}
		);
	}

	/**
	 * @param array $schedules
	 *
	 * @return array
	 */
	public function cron_schedules( array $schedules ): array {
		return defender_cron_schedules( $schedules );
	}

	public function includes(): void {
		// Initialize modules.
		add_action(
			'init',
			function() {
				add_filter( 'cron_schedules', [ $this, 'cron_schedules' ] );
				$this->init_modules();
			},
			8
		);
		// Register routes.
		add_action(
			'init',
			function () {
				require_once WP_DEFENDER_DIR . 'src/routes.php';
			},
			9
		);
		// Include admin class. Don't use is_admin().
		add_action( 'admin_init', [ ( new \WP_Defender\Admin() ), 'init' ] );
		// Add WP-CLI commands.
		if ( defender_is_wp_cli() ) {
			\WP_CLI::add_command( 'defender', Cli::class );
		}
		// Rotational logger initialization.
		add_action( 'init', [ ( new \WP_Defender\Component\Logger\Rotation_Logger() ), 'init' ], 99 );
		// Handle plugin deactivation.
		add_action( 'deactivated_plugin', [ ( new HUB() ), 'intercept_deactivate' ] );
	}
}
