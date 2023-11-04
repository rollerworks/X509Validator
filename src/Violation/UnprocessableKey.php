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

final class UnprocessableKey extends Violation
{
    public function __construct(string $message = '')
    {
        parent::__construct($message, 0, new \Error(openssl_error_string() ?: 'Unknown error', 1));
    }

    public function getTranslatorMsg(): string
    {
        return 'Unable to process PEM X.509 data of private key "{name}". Only PEM encoded X.509 files are supported.';
    }
}
