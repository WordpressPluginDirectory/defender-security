<p style="-webkit-font-smoothing:antialiased;color:#1a1a1a;font-size:16px;font-weight: normal;line-height:24px;font-smoothing:antialiased;margin:0 0 30px;padding:0;text-align:left">
	<?php
	/* translators: %s: Name. */
	printf( __( "Hi %s,", 'defender-security' ), esc_html( $name ) );
	?>
</p>
<p style="color: #1a1a1a;font-size:16px;font-weight:normal;line-height:24px;margin:0;padding: 0 0 45px;text-align: left;">
	<?php
	/* translators: %s: Site URL. */
	printf( __( "No events were logged for %s during the report period.", 'defender-security' ), esc_url( $site_url ) );
	?>
</p>
