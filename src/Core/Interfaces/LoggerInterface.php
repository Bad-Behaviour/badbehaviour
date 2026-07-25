<?php

namespace BadBehaviour\Core\Interfaces;

interface LoggerInterface
{
	public function emergency(string $message, array $context = []): void;
	public function alert(string $message, array $context = []): void;
	public function critical(string $message, array $context = []): void;
	public function error(string $message, array $context = []): void;
	public function warning(string $message, array $context = []): void;
	public function notice(string $message, array $context = []): void;
	public function info(string $message, array $context = []): void;
	public function debug(string $message, array $context = []): void;
}
