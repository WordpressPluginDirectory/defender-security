<?php

namespace WP_Defender\Behavior\Scan;

use Calotes\Base\Component;
use Calotes\Base\File;
use WP_Defender\Behavior\WPMUDEV;
use WP_Defender\Component\Timer;
use WP_Defender\Model\Scan;
use WP_Defender\Model\Setting\Scan as Scan_Settings;
use WP_Defender\Traits\IO;

/**
 * We will gather core files & content files, for using in core integrity.
 *
 * Class Gather_Fact
 * @package WP_Defender\Behavior\Scan
 */
class Gather_Fact extends Component {
	use IO;

	public const CACHE_CORE = 'wdfcore', CACHE_CONTENT = 'wdfcontent';

	/**
	 * @var Scan|null
	 */
	private ?Scan $scan;

	/**
	 * @var WPMUDEV|null
	 */
	private ?WPMUDEV $wpmudev;

	/**
	 * @var Scan_Settings|null
	 */
	private ?Scan_Settings $settings;

	public function __construct( WPMUDEV $wpmudev, Scan $scan, Scan_Settings $scan_settings ) {
		$this->wpmudev  = $wpmudev;
		$this->scan     = $scan;
		$this->settings = $scan_settings;
	}

	/**
	 * Gather core files & content files.
	 *
	 * @return bool
	 */
	public function gather_info(): bool {
		$timer       = new Timer();
		$model       = $this->scan;
		$need_to_run = empty( $model->task_checkpoint ) ? 'get_core_files' : 'get_content_files';
		if ( 'get_core_files' === $need_to_run ) {
			if ( $this->settings->integrity_check && $this->settings->check_core ) {
				$this->get_core_files();
			}
			$model->calculate_percent( 50, 1 );
		} else {
			$this->get_content_files();
			$model->calculate_percent( 100, 1 );
		}
		$this->log( sprintf( '%s in %d', $need_to_run, $timer->get_difference() ), 'scan.log' );
		$model->task_checkpoint = $need_to_run;
		$model->save();

		return 'get_content_files' === $need_to_run;
	}

	/**
	 * @return array
	 */
	private function get_core_files(): array {
		$cache = get_site_option( self::CACHE_CORE, false );
		if ( is_array( $cache ) ) {
			return $cache;
		}
		$abs_path = defender_replace_line( ABSPATH );
		$core = new File(
			$abs_path,
			true,
			false,
			[
				'dir' => [
					$abs_path . 'wp-admin',
					$abs_path . WPINC,
				],
			],
			[],
			true,
			true
		);

		$outside = new File(
			$abs_path,
			true,
			true,
			[],
			[
				'dir' => [
					$abs_path . 'wp-content',
					$abs_path . 'wp-admin',
					$abs_path . 'wp-includes',
				],
				'filename' => [
					'wp-config.php',
				],
			],
			false,
			true
		);

		$files = array_merge( $core->get_dir_tree(), $outside->get_dir_tree() );
		$files = array_filter( $files );
		$this->log( sprintf( 'Core: %s', count( $files ) ), 'scan.log' );
		update_site_option( self::CACHE_CORE, $files );

		return $files;
	}

	/**
	 * Return every php files inside wp-content.
	 *
	 * @return array|void
	 */
	private function get_content_files() {
		$cache = get_site_option( self::CACHE_CONTENT, false );
		if ( is_array( $cache ) ) {
			return $cache;
		}
		$content = new File(
			WP_CONTENT_DIR,
			true,
			false,
			[
				'ext' => [ 'php' ],
			],
			[],
			true,
			true,
			$this->settings->filesize
		);

		$files = $content->get_dir_tree();
		$files = array_filter( $files );
		$files[] = defender_wp_config_path();
		$this->log( sprintf( 'Content: %s', count( $files ) ), 'scan.log' );
		update_site_option( self::CACHE_CONTENT, $files );
	}
}
