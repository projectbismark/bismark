<?php

$logname = "/tmp/stats";

/* PUT data comes in on the stdin stream */
$putdata = fopen("php://input", "r");
$stats = fopen($logname, "w");

/* Read the data 1 packet at a time */
$int_start = microtime(true);
$bytes = 0;
while ($data = fread($putdata, 1420)) {
	if (($curr = microtime(true)) > ($int_start + 1)) {
		fprintf($stats, "%u\n", $bytes * 8);
		$int_start = $curr;
		$bytes = 0;
	}
	$bytes += strlen($data);
}
$end = microtime(true);
fprintf($stats, "%f %f - %u %u\n", $int_start, $end, $bytes, ($bytes * 8)/($end - $int_start) );

fclose($putdata);
fclose($stats);

Header("HTTP/1.1 201 Created");
?>
