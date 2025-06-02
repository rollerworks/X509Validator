<?php

declare(strict_types=1);

/*
 * This file is part of the Rollerworks X509Validator package.
 *
 * (c) Sebastiaan Stok <s.stok@rollerscapes.net>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Rollerworks\Component\X509Validator\Tests;

use Psr\Log\AbstractLogger;
use Psr\Log\InvalidArgumentException;
use Psr\Log\LogLevel;

/**
 * Used for testing purposes (copied from PHP-FIG repository).
 *
 * It records all records and gives you access to them for verification.
 *
 * @method bool hasEmergency(array $record)
 * @method bool hasAlert(array $record)
 * @method bool hasCritical(array $record)
 * @method bool hasError(array $record)
 * @method bool hasWarning(array $record)
 * @method bool hasNotice(array $record)
 * @method bool hasInfo(array $record)
 * @method bool hasDebug(array $record)
 * @method bool hasEmergencyRecords()
 * @method bool hasAlertRecords()
 * @method bool hasCriticalRecords()
 * @method bool hasErrorRecords()
 * @method bool hasWarningRecords()
 * @method bool hasNoticeRecords()
 * @method bool hasInfoRecords()
 * @method bool hasDebugRecords()
 * @method bool hasEmergencyThatContains(string $message)
 * @method bool hasAlertThatContains(string $message)
 * @method bool hasCriticalThatContains(string $message)
 * @method bool hasErrorThatContains(string $message)
 * @method bool hasWarningThatContains(string $message)
 * @method bool hasNoticeThatContains(string $message)
 * @method bool hasInfoThatContains(string $message)
 * @method bool hasDebugThatContains(string $message)
 * @method bool hasEmergencyThatMatches(string $message)
 * @method bool hasAlertThatMatches(string $message)
 * @method bool hasCriticalThatMatches(string $message)
 * @method bool hasErrorThatMatches(string $message)
 * @method bool hasWarningThatMatches(string $message)
 * @method bool hasNoticeThatMatches(string $message)
 * @method bool hasInfoThatMatches(string $message)
 * @method bool hasDebugThatMatches(string $message)
 * @method bool hasEmergencyThatPasses(string $message)
 * @method bool hasAlertThatPasses(string $message)
 * @method bool hasCriticalThatPasses(string $message)
 * @method bool hasErrorThatPasses(string $message)
 * @method bool hasWarningThatPasses(string $message)
 * @method bool hasNoticeThatPasses(string $message)
 * @method bool hasInfoThatPasses(string $message)
 * @method bool hasDebugThatPasses(string $message)
 *
 * @internal
 */
final class TestLogger extends AbstractLogger
{
    public array $records = [];
    public array $recordsByLevel = [];

    public function log($level, string | \Stringable $message, array $context = []): void
    {
        if (! \in_array($level, $this->getLogLevels(), true)) {
            throw new InvalidArgumentException(\sprintf('Log level "%1$s" is not valid', $level));
        }

        $record = [
            'level' => $level,
            'message' => $message,
            'context' => $context,
        ];

        $this->recordsByLevel[$record['level']][] = $record;
        $this->records[] = $record;
    }

    public static function formatMessage(string $message, string $level, array $context): string
    {
        $message = self::interpolateContext($message, $context);

        return "{$level} {$message}";
    }

    private static function interpolateContext(string $message, array $context): string
    {
        return preg_replace_callback('!\{([^}\s]*)\}!', static function ($matches) use ($context) {
            $key = $matches[1] ?? null;

            if (\array_key_exists($key, $context)) {
                return $context[$key];
            }

            return $matches[0];
        }, $message);
    }

    /** @return array<string, string> */
    public function getLogLevels(): array
    {
        static $constants;

        if (isset($constants)) {
            return $constants;
        }

        $reflection = new \ReflectionClass(LogLevel::class);
        $constants = $reflection->getConstants();

        return $constants;
    }

    /** @return array<int, array<string, mixed>> */
    public function getRecords(): array
    {
        return $this->records;
    }

    public function hasRecords(string $level): bool
    {
        return isset($this->recordsByLevel[$level]);
    }

    /** @param string|array<string, mixed> $record */
    public function hasRecord(array | string $record, string $level): bool
    {
        if (\is_string($record)) {
            $record = ['message' => $record];
        }

        return $this->hasRecordThatPasses(static function ($rec) use ($record) {
            if ($rec['message'] !== $record['message']) {
                return false;
            }

            if (isset($record['context']) && $rec['context'] !== $record['context']) {
                return false;
            }

            return true;
        }, $level);
    }

    public function hasRecordThatContains(string $message, string $level): bool
    {
        return $this->hasRecordThatPasses(static fn ($rec) => mb_strpos($rec['message'], $message) !== false, $level);
    }

    public function hasRecordThatMatches(string $regex, string $level): bool
    {
        return $this->hasRecordThatPasses(static fn ($rec) => preg_match($regex, $rec['message']) > 0, $level);
    }

    /**
     * Determines whether the logger has logged matching records of the specified level.
     *
     * @param callable(array{level: LogLevel::*, message: string, context: array<mixed>}, int): bool $predicate
     *                                                                                                          The function used to evaluate whether a record matches
     * @param LogLevel::*                                                                            $level     The level of the record
     */
    public function hasRecordThatPasses(callable $predicate, string $level): bool
    {
        if (! isset($this->recordsByLevel[$level])) {
            return false;
        }

        foreach ($this->recordsByLevel[$level] as $i => $rec) {
            if ($predicate($rec, $i)) {
                return true;
            }
        }

        return false;
    }

    /** @param array<int, mixed> $args */
    public function __call(string $method, array $args): mixed
    {
        if (preg_match('/(.*)(Debug|Info|Notice|Warning|Error|Critical|Alert|Emergency)(.*)/', $method, $matches) > 0) {
            $genericMethod = $matches[1] . ($matches[3] !== 'Records' ? 'Record' : '') . $matches[3];
            $level = mb_strtolower($matches[2]);

            if (method_exists($this, $genericMethod)) {
                $args[] = $level;

                return \call_user_func_array([$this, $genericMethod], $args);
            }
        }

        throw new \BadMethodCallException('Call to undefined method ' . self::class . '::' . $method . '()');
    }

    public function reset(): void
    {
        $this->records = [];
        $this->recordsByLevel = [];
    }
}
