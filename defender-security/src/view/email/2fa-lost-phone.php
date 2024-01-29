<?php
/**
 * @var \WP_Defender\Integrations\Dashboard_Whitelabel
 */
$dashboard_whitelabel = wd_di()->get( \WP_Defender\Integrations\Dashboard_Whitelabel::class );
$can_whitelabel = $dashboard_whitelabel->can_whitelabel();

$style = "color: #1A1A1A;
	font-family: Roboto, Arial, sans-serif;
	font-size: 16px;
	font-weight: normal;
	line-height: 24px;
	text-align: left;
	word-wrap: normal;" . (
	! $can_whitelabel || ( $dashboard_whitelabel->is_change_footer() && $dashboard_whitelabel->is_set_footer_text() )
	? 'margin: 0 0 30px;'
	: 'margin: 0px;'
);

$body = nl2br( esc_html( $body ) );
?>

<p style="<?php echo $style; ?>">
	<?php echo $body; ?>
</p>
