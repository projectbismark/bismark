<?php
	// Check duration
	$duration = $_GET['duration'];
	if ($duration == 0 || $duration >= 60)
		$duration=10;
	
	// Set time variables
	$start = time();
	$end = $start + $duration;

	// Generate payload 
	do { 
		$countdown = $end - time(); 
		printf("|%u|", $countdown);
	} while($countdown > 0);
?>
