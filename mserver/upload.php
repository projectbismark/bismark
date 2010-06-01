<?php
/* PUT data comes in on the stdin stream */
$putdata = fopen("php://input", "r");

/* Read the data 1 packet at a time */
while ($data = fread($putdata, 1478));

fclose($putdata);
?>
