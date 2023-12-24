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

namespace Rollerworks\Component\X509Validator\Violation;

use Rollerworks\Component\X509Validator\Violation;

/**
 * This exception class is used for when the data cannot be processed or parsed.
 */
final class UnprocessablePEM extends Violation
{
    public function __construct(private readonly string $certName, string $contents = '')
    {
        $previous = $contents !== '' ? new \InvalidArgumentException($contents) : null;
        parent::__construct('', 0, new \Error((string) openssl_error_string(), 1, $previous));
    }

    public function getTranslatorMsg(): string
    {
        if ($this->certName === '') {
            return 'Unable to process certificate. Only PEM encoded X.509 files are supported.';
        }

        return 'Unable to process certificate "{name}". Only PEM encoded X.509 files are supported.';
    }

    public function getParameters(): array
    {
        return ['name' => $this->certName];
    }
}
