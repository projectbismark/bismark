<?php
	// Check duration
	$duration = $_GET['duration'];
	if ($duration <= 1)
		$duration = 2;
	if ($duration >= 60)
		$duration = 60;
	
	// Check size
	$rate = $_GET['mbps'];
	if ($rate <= 12)
		$size = 1;
	else if ($rate <= 50)
		$size = intval(($rate / 8) + 1);
	else if ($rate <= 128)
		$size = intval($rate / 6.4);
	else if ($rate <= 256)
		$size = intval(($rate / 6.4) + ($rate/256));
	else if ($rate <= 512)
		$size = intval(($rate / 5.9) + ($rate/256)^2);



	// Set time variables
	$start = time();
	$end = $start + $duration;

	// Create payload pattern
	$str = "";
	for ($i=0;$i<=$size;$i++)
		$str = sprintf("%s%c", $str, (48 + $i) % 78);

	// Generate payload 
	do { 
		$countdown = $end - time(); 
		printf("%s", $str);
	} while($countdown > 0);
?>
