<?php
get_header();
?>

<main id="primary" class="site-main pt-24 min-h-screen">
	<div class="max-w-7xl mx-auto px-4 py-12">
		<?php
		if ( have_posts() ) :
			while ( have_posts() ) :
				the_post();
				the_content();
			endwhile;
		endif;
		?>
	</div>
</main>

<?php
get_footer();
