<?php

namespace Calotes\Base;

/**
 * This class use for:
 *  1. Register admin page.
 *  2. Register sub page.
 *  3. Help to queue scripts & output script data for frontend.
 *  4. Render frontend view.
 *
 * Class Controller
 *
 * @package Calotes\Base
 */
class Controller extends Component {
	protected $slug;
	protected $layout = null;

	/**
	 * A helper to quickly create a page or subpage.
	 *
	 * @param string      $title
	 * @param string      $slug
	 * @param callable    $callback
	 * @param null|string $icon
	 * @param null|string $parent_slug
	 * @param string      $menu_title
	 */
	public function register_page( $title, $slug, $callback, $parent_slug = null, $icon = null, $menu_title = '' ) {
		$hook = is_multisite() ? 'network_admin_menu' : 'admin_menu';
		$menu_title = '' !== $menu_title ? $menu_title : $title;
		$function = function () use ( $title, $slug, $callback, $parent_slug, $icon, $menu_title ) {
			$cap = is_multisite() ? 'manage_network_options' : 'manage_options';
			if ( null === $parent_slug ) {
				$page_hook = add_menu_page( $title, $menu_title, $cap, $slug, $callback, $icon );
			} else {
				$page_hook = add_submenu_page( $parent_slug, $title, $menu_title, $cap, $slug, $callback );
			}
			add_action( 'load-' . $page_hook, [ $this, 'trigger_load_action' ] );
		};

		add_action( $hook, $function );
	}

	public function trigger_load_action() {
		$redirect_slug = 'wp-defender';
		if (
			$redirect_slug !== $this->slug
			&& true !== (bool) get_site_option( 'wp_defender_shown_activator' )
		) {
			// Redirect to the Onboard page only on single sites or network admin.
			wp_safe_redirect( network_admin_url( 'admin.php?page=' . $redirect_slug ) );
			exit;
		}
	}

	/**
	 * @param string|array $view_file
	 * @param array        $params
	 * @param bool         $output
	 *
	 * @return bool|string|void
	 */
	public function render( $view_file, $params = [], $output = true ) {
		$stop_further = $this->check_has_server_error();

		if ( $stop_further ) {
			return false;
		}

		$base_path = $this->get_base_path();
		$view = new View( $base_path . 'view' );
		// Assign controller to this.
		if ( ! isset( $params['controller'] ) ) {
			$params['controller'] = $this;
		}
		if ( is_array( $view_file ) ) {
			$content = '';
			foreach ( $view_file as $vf ) {
				$content .= $view->render( $vf, $params );
			}
		} else {
			$content = $view->render( $view_file, $params );
		}

		if ( ! empty( $this->layout ) ) {
			$template = new View( $base_path . 'view' . DIRECTORY_SEPARATOR . 'layouts' );
			$content = $template->render(
				$this->layout,
				array_merge(
					$params,
					[
						'controller' => $this,
						'contents' => $content,
					]
				)
			);
		}
		if ( false === $output ) {
			return $content;
		}

		echo $content;
	}

	/**
	 * This will guess the called class path, and return the base.
	 *
	 * @return bool|string
	 */
	private function get_base_path() {
		$reflector = new \ReflectionClass( get_called_class() );
		$base_path = dirname( $reflector->getFileName(), 2 );

		if ( is_dir( $base_path . DIRECTORY_SEPARATOR . 'controller' )
			&& is_dir( $base_path . DIRECTORY_SEPARATOR . 'view' )
		) {
			return $base_path . DIRECTORY_SEPARATOR;
		}

		return false;
	}

	/**
	 * @param $view_file
	 * @param array $params
	 * @param bool  $output
	 *
	 * @return string
	 */
	public function render_partial( $view_file, $params = [], $output = true ) {
		$base_path = $this->get_base_path();

		if ( ! isset( $params['controller'] ) ) {
			$params['controller'] = $this;
		}

		$view = new View( $base_path . 'view' );
		if ( is_array( $view_file ) ) {
			$content = '';
			foreach ( $view_file as $vf ) {
				$content .= $view->render( $vf, $params );
			}
		} else {
			$content = $view->render( $view_file, $params );
		}
		if ( true === $output ) {
			echo $content;
		}

		return $content;
	}

	/**
	 * Check for has server not found error.
	 *
	 * @return bool
	 */
	private function check_has_server_error(): bool {
		global $defender_server_not_supported;

		if ( is_wp_error( $defender_server_not_supported ) ) {
			$html = '<div class="sui-wrap"><div class="sui-notice sui-notice-info">';
			$html .= '<div class="sui-notice-content">';
			$html .= '<div class="sui-notice-message">';
			$html .= '<p>' . $defender_server_not_supported->get_error_message() . '</p>';
			$html .= '</div></div></div></div>';

			echo $html;

			return true;
		}

		return false;
	}
}
