<p style="color: #1A1A1A; font-family: Roboto, Arial, sans-serif; font-size: 16px; font-weight: normal; line-height: 24px; margin: 0; padding: 0 0 28px; text-align: left; word-wrap: normal;">
	<?php
	/* translators: %s: Name. */
	printf( __( "Hi %s", 'defender-security' ), esc_html( $name ) );
	?>,
</p>
<p style="color: #1A1A1A; font-family: Roboto, Arial, sans-serif; font-size: 16px; font-weight: normal; line-height: 24px; margin: 0; padding: 0 0 24px; text-align: left;">
	<?php echo $text; ?>
</p>
<p style="font-family: Roboto, Arial, sans-serif; font-size: 16px; font-weight: normal; line-height: 24px; margin: 0; padding: 0 0 24px; text-align: center;">
	<?php printf( '<a class="button view-full" href="%s">' . __( 'View Full Logs', 'defender-security' ) . '</a>', esc_url( $logs_url ) ); ?>
</p>
