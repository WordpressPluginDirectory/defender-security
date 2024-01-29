<?php

namespace WP_Defender\Model\Notification;

use WP_Defender\Controller\Firewall;
use WP_Defender\Model\Lockout_Log;

/**
 * Class Firewall_Report.
 * @package WP_Defender\Model\Notification
 */
class Firewall_Report extends \WP_Defender\Model\Notification {
	protected $table = 'wd_lockout_report';

	public const SLUG = 'firewall-report';

	protected function before_load(): void {
		$default = [
			'slug' => self::SLUG,
			'title' => __( 'Firewall - Reporting', 'defender-security' ),
			'status' => self::STATUS_DISABLED,
			'description' => __( 'Configure Defender to automatically email you a lockout report for this website.', 'defender-security' ),
			// @since 3.0.0 Fix 'Guest'-line.
			'in_house_recipients' => is_user_logged_in() ? [ $this->get_default_user() ] : [],
			'out_house_recipients' => [],
			'type' => 'report',
			'dry_run' => false,
			'frequency' => 'weekly',
			'day' => 'sunday',
			'day_n' => '1',
			'time' => '4:00',
			'configs' => [],
		];
		$this->import( $default );
	}

	public function send() {
		$service = wd_di()->get( \WP_Defender\Component\Notification::class );
		foreach ( $this->in_house_recipients as $recipient ) {
			if ( self::USER_SUBSCRIBED !== $recipient['status'] ) {
				continue;
			}
			$this->send_to_user( $recipient['name'], $recipient['email'], $service );
		}
		foreach ( $this->out_house_recipients as $recipient ) {
			if ( self::USER_SUBSCRIBED !== $recipient['status'] ) {
				continue;
			}
			$this->send_to_user( $recipient['name'], $recipient['email'], $service );
		}
		$this->last_sent = $this->est_timestamp;
		$this->est_timestamp = $this->get_next_run()->getTimestamp();
		$this->save();
	}

	/**
	 * @param string $name
	 * @param string $email
	 * @param object $service
	 */
	private function send_to_user( $name, $email, $service ) {
		$site_url = network_site_url();
		$mail_object = wd_di()->get( \WP_Defender\Component\Mail::class );
		$plugin_label = $mail_object->get_sender_name( self::SLUG );
		$subject = sprintf(
		/* translators: 1. Plugin label. 2. Site URL. */
			__( '%1$s Lockouts Report for %2$s', 'defender-security' ),
			$plugin_label,
			$site_url
		);
		// Frequency.
		if ( 'daily' === $this->frequency ) {
			$time_unit = __( 'in the past 24 hours', 'defender-security' );
			$interval = '-24 hours';
		} elseif ( 'weekly' === $this->frequency ) {
			$time_unit = __( 'in the past week', 'defender-security' );
			$interval = '-7 days';
		} else {
			$time_unit = __( 'in the month', 'defender-security' );
			$interval = '-30 days';
		}
		// Number of lockouts.
		$count_lockouts = [
			'404' => Lockout_Log::count(
				strtotime( $interval ),
				time(),
				[
					Lockout_Log::LOCKOUT_404,
				]
			),
			'login' => Lockout_Log::count(
				strtotime( $interval ),
				time(),
				[
					Lockout_Log::AUTH_LOCK,
				]
			),
			'ua' => Lockout_Log::count(
				strtotime( $interval ),
				time(),
				[
					Lockout_Log::LOCKOUT_UA,
				]
			),
		];

		$firewall = wd_di()->get( Firewall::class );
		$logs_url = network_admin_url( 'admin.php?page=wdf-ip-lockout&view=logs' );
		// Need for activated Mask Login feature.
		$logs_url = apply_filters( 'report_email_logs_link', $logs_url, $email );
		$content_body = $firewall->render_partial(
			'email/firewall-report',
			[
				'name' => $name,
				'count_total' => (int) $count_lockouts['404'] + (int) $count_lockouts['login'] + (int) $count_lockouts['ua'],
				'time_unit' => $time_unit,
				'logs_url' => $logs_url,
				'site_url' => $site_url,
				'count_lockouts' => $count_lockouts,
			],
			false
		);
		$unsubscribe_link = $service->create_unsubscribe_url( $this->slug, $email );
		$content = $firewall->render_partial(
			'email/index',
			[
				'title' => __( 'Firewall', 'defender-security' ),
				'content_body' => $content_body,
				'unsubscribe_link' => $unsubscribe_link,
			],
			false
		);

		$headers = $mail_object->get_headers(
			defender_noreply_email( 'wd_lockout_noreply_email' ),
			self::SLUG
		);

		$ret = wp_mail( $email, $subject, $content, $headers );
		if ( $ret ) {
			$this->save_log( $email );
		}
	}

	/**
	 * Define settings labels.
	 *
	 * @return array
	 */
	public function labels(): array {
		return [
			'report' => __( 'Firewall - Reporting', 'defender-security' ),
			'day' => __( 'Day of', 'defender-security' ),
			'day_n' => __( 'Day of', 'defender-security' ),
			'report_time' => __( 'Time of day', 'defender-security' ),
			'report_frequency' => __( 'Frequency', 'defender-security' ),
			'report_subscribers' => __( 'Recipients', 'defender-security' ),
		];
	}

	/**
	 * Additional converting rules.
	 *
	 * @param array $configs
	 *
	 * @return array
	 * @since 3.1.0
	 */
	public function type_casting( $configs ): array {
		return $configs;
	}
}
