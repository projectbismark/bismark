<?php
	// Check duration
	$duration = $_GET['duration'];
	if ($duration <= 1)
		$duration = 2;
	if ($duration >= 60)
		$duration = 60;
	
	// Compute max transfer size
	$rate = $_GET['kbps'] / 8;
	$bytes = $rate * 1000 * $duration;
	$size = 1460;

	// Set time variables
	$start = time();
	$end = $start + $duration;

	// Create payload pattern
	$str = "";
	for ($i=0;$i<=$size;$i++)
		$str = sprintf("%s%c", $str, (48 + $i) % 78);

	// Generate payload
	$bytes_left = $bytes;
	do { 
		$countdown = $end - time(); 
		$bytes_left -= $size; 
		printf("%s", $str);
	} while($countdown > 0 && $bytes_left > 0);
?>
