<?php
/**
 * Author: Hoang Ngo
 */

namespace Calotes\Base;

class View extends Component {

	/**
	 * @var array
	 */
	public $blocks = [];

	/**
	 * @var array
	 */
	public $params = [];

	/**
	 * The template file in which this view should be rendered.
	 *
	 * @var null
	 */
	public $layout = null;

	/**
	 * The file contains content of this view, relative path.
	 *
	 * @var null
	 */
	public $view_file = null;

	/**
	 * The folder contains view files, absolute path.
	 *
	 * @var null
	 */
	private $_base_path = null;

	public function __construct( $base_path ) {
		$this->_base_path = $base_path;
	}

	/**
	 * Render a view file. This will be used to render a whole page.
	 * If a layout is defined, then we will render layout + view.
	 *
	 * @param $view
	 * @param array $params
	 *
	 * @return string
	 */
	public function render( $view, $params = [] ) {
		$view_file = $this->_base_path . DIRECTORY_SEPARATOR . $view . '.php';
		if ( is_file( $view_file ) ) {
			$content = $this->render_php_file( $view_file, $params );

			return $content;
		}

		return '';
	}

	/**
	 * @param $file
	 * @param array $params
	 *
	 * @return string
	 */
	private function render_php_file( $file, $params = [] ) {
		ob_start();
		ob_implicit_flush( false );
		extract( $params, EXTR_OVERWRITE );// phpcs:ignore
		require $file;

		return ob_get_clean();
	}
}
