<?php
$key_file_path = '../../../encryption_key.key';
if (!file_exists(dirname($key_file_path))) {
    mkdir(dirname($key_file_path), 0700, true);
}

$key = bin2hex(random_bytes(32)); // AES-256 requires 256-bit key
file_put_contents($key_file_path, $key);
echo "Key generated and saved at $key_file_path\n";
