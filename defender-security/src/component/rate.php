<?php

namespace WP_Defender\Component;

/**
 * Class Rate.
 *
 * @since 4.4.0
 * @package WP_Defender\Component
 */
class Rate extends \Calotes\Base\Component {

	/**
	 * @var string
	 */
	public const URL_PLUGIN_NEW_REVIEW_VCS = 'https://wordpress.org/support/plugin/defender-security/reviews/#new-post';

	/**
	 * @var int
	 */
	public const NUMBER_COMPLETED_SCANS = 25;

	/**
	 * @var int
	 */
	public const NUMBER_FIXED_SCANS = 5;

	/**
	 * @var string
	 */
	public const SLUG_COMPLETED_SCANS = 'defender_counter_completed_scans';

	/**
	 * @var string
	 */
	public const SLUG_FIXED_SCAN_ISSUES = 'defender_counter_fixed_scan_issues';

	/**
	 * @var string
	 */
	public const SLUG_FOR_BUTTON_RATE = 'defender_rating_success';

	/**
	 * @var string
	 */
	public const SLUG_FOR_BUTTON_THANKS = 'defender_days_rating_later_dismiss';

	/**
	 * @var string
	 */
	public const SLUG_FREE_INSTALL_DATE = 'defender_free_install_date';

	/**
	 * @var string
	 */
	public $button_rate;

	/**
	 * @var string
	 */
	public $button_later;

	public function __construct() {
		$this->button_rate = __( 'Rate Defender', 'defender-security' );
		$this->button_later = __( 'Maybe later', 'defender-security' );
		add_action( 'wp_ajax_defender_dismiss_notification', [ $this, 'dismiss_notice' ] );
	}

	/**
	 * @param string $slug
	 *
	 * @return int
	 */
	protected static function get_count_scans( $slug ): int {
		$scan_count = get_site_option( $slug, false );

		return empty( $scan_count ) ? 0 : (int) $scan_count;
	}

	/**
	 * Count completed scans.
	*/
	public static function run_counter_of_completed_scans(): void {
		$scan_count = self::get_count_scans( self::SLUG_COMPLETED_SCANS );
		if ( $scan_count < self::NUMBER_COMPLETED_SCANS ) {
			update_site_option( self::SLUG_COMPLETED_SCANS, ++$scan_count );
		}
	}

	/**
	 * Count fixed scans.
	*/
	public static function run_counter_of_fixed_scans(): void {
		$scan_count = self::get_count_scans( self::SLUG_FIXED_SCAN_ISSUES );
		if ( $scan_count < self::NUMBER_FIXED_SCANS ) {
			update_site_option( self::SLUG_FIXED_SCAN_ISSUES, ++$scan_count );
		}
	}

	/**
	 * Display specific Scan notice.
	 *
	 * @return array
	 */
	public static function what_scan_notice_display(): array {
		if ( self::get_count_scans( self::SLUG_COMPLETED_SCANS ) >= self::NUMBER_COMPLETED_SCANS ) {
			return [
				'slug' => 'completed_scans',
				'text' => sprintf(
					/* translators: %d - Number of completed scans. */
					__( 'You\'ve completed %d malware scans - that\'s a lot of scans! We are happy to be a part of helping you secure your site and we would appreciate it if you dropped us a rating on wp.org to help us spread the word and boost our motivation.', 'defender-security' ),
					self::NUMBER_COMPLETED_SCANS
				),
			];
		} elseif ( self::get_count_scans( self::SLUG_FIXED_SCAN_ISSUES ) >= self::NUMBER_FIXED_SCANS ) {
			return [
				'slug' => 'fixed_scans',
				'text' => sprintf(
					/* translators: %d - Number of completed scans. */
					__( 'You\'ve successfully resolved %d malware scan issues! We are happy to be a part of helping you secure your site, and we would appreciate it if you dropped us a rating on wp.org to help us spread the word and boost our motivation.', 'defender-security' ),
					self::NUMBER_FIXED_SCANS
				),
			];
		}

		return [
			'slug' => '',
			'text' => '',
		];
	}

	/**
	 * Remove data of all prompts.
	*/
	public static function clean_up(): void {
		delete_site_option( self::SLUG_COMPLETED_SCANS );
		delete_site_option( self::SLUG_FIXED_SCAN_ISSUES );
		delete_site_option( self::SLUG_FREE_INSTALL_DATE );
		delete_site_option( self::SLUG_FOR_BUTTON_RATE );
		delete_site_option( self::SLUG_FOR_BUTTON_THANKS );
	}

	/**
	 * Reset counter of all prompts.
	*/
	public static function reset_counters(): void {
		update_site_option( self::SLUG_COMPLETED_SCANS, 0 );
		update_site_option( self::SLUG_FIXED_SCAN_ISSUES, 0 );
	}

	/**
	 * Initializing actions.
	 */
	public function init(): void {
		if ( is_defender_page() ) {
			$is_multisite = is_multisite();
			if ( ! $is_multisite ) {
				add_action( 'admin_notices', [ $this, 'show_notice_general_request' ] );
			} elseif ( $is_multisite && is_main_site() ) {
				add_action( 'network_admin_notices', [ $this, 'show_notice_general_request' ] );
			}
		}
	}

	/**
	 * Have there already been clicks on the Rate notices?
	 *
	 * @return bool
	 */
	public static function was_rate_request(): bool {
		if ( get_site_option( self::SLUG_FOR_BUTTON_RATE, apply_filters( 'wd_display_rating', false ) ) ) {
			return true;
		}
		if ( get_site_option( self::SLUG_FOR_BUTTON_THANKS, apply_filters( 'wd_dismiss_rating', false ) ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Show the general rating notice after countless hours developing.
	 */
	public function show_notice_general_request() {
		if ( self::was_rate_request() ) {
			return;
		}
		// Return if the condition is met on the Scan page.
		if (
			'wdf-scan' === defender_get_current_page()
			&& (
				self::get_count_scans( self::SLUG_COMPLETED_SCANS ) >= self::NUMBER_COMPLETED_SCANS
				|| self::get_count_scans( self::SLUG_FIXED_SCAN_ISSUES ) >= self::NUMBER_FIXED_SCANS
			)
		) {
			return;
		}
		// Return if the condition is met on the Tweaks page.
		$tweak_arr = wd_di()->get( \WP_Defender\Model\Setting\Security_Tweaks::class )->get_tweak_types();
		$total_tweaks = $tweak_arr['count_fixed'] + $tweak_arr['count_ignored'] + $tweak_arr['count_issues'];
		if (
			'wdf-hardener' === defender_get_current_page()
			&& $tweak_arr['count_fixed'] === $total_tweaks
		) {
			return;
		}

		// Check by the installation date.
		$install_date = (int) get_site_option( self::SLUG_FREE_INSTALL_DATE, false );
		if ( $install_date && current_time( 'timestamp' ) > strtotime( '+7 days', $install_date ) ) { ?>
			<div id="defender-free-usage-notice"
				class="defender-rating-notice notice notice-info"
				data-nonce="<?php echo esc_attr( wp_create_nonce( 'defender_dismiss_notification' ) ); ?>">

				<p style="color: #72777C; line-height: 22px;"><?php esc_html_e( 'We\'ve spent countless hours developing Defender and making it free for you to use. We would really appreciate it if you dropped us a quick rating!', 'defender-security' ); ?></p>

				<p>
					<button type="button" class="button button-primary button-large"
						data-prop="defender_rating_success"><?php echo esc_html( $this->button_rate ); ?></button>
					<a href="#" class="dismiss"
						style="margin-left: 11px; color: #555; line-height: 16px; font-weight: 500; text-decoration: none;"
						data-prop="defender_days_rating_later_dismiss"><?php echo esc_html( $this->button_later ); ?></a>
				</p>
			</div>
			<?php
		}
		?>

		<script type="text/javascript">
			jQuery('.defender-rating-notice a, .defender-rating-notice button').on('click', function (e) {
				e.preventDefault();

				var $notice = jQuery(e.currentTarget).closest('.defender-rating-notice'),
					prop = jQuery(this).data('prop'),
					ajaxUrl = '<?php echo admin_url( 'admin-ajax.php' ); ?>';

				if ('defender_rating_success' === prop) {
					window.open('<?php echo self::URL_PLUGIN_NEW_REVIEW_VCS; ?>', '_blank');
				}

				jQuery.post(
					ajaxUrl,
					{
						action: 'defender_dismiss_notification',
						prop: prop,
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
	 */
	public function dismiss_notice() {
		if ( ! current_user_can( 'manage_options' ) || ! check_ajax_referer( 'defender_dismiss_notification' ) ) {
			wp_send_json_error(
				[ 'message' => __( 'Invalid request, you are not allowed to do that action.', 'defender-security' ) ]
			);
		}

		$notification_name = ! empty( $_POST['prop'] ) ? sanitize_text_field( $_POST['prop'] ) : false;
		if ( false === $notification_name ) {
			wp_send_json_error(
				[ 'message' => __( 'Invalid request, allowed data not provided.', 'defender-security' ) ]
			);
		}
		update_site_option( $notification_name, true );

		wp_send_json_success();
	}
}
