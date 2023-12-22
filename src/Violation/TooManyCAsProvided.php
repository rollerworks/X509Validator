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

final class TooManyCAsProvided extends Violation
{
    public function __construct()
    {
        parent::__construct('Too many CAs were provided. A maximum of 4 is accepted.');
    }

    public function getTranslatorMsg(): string
    {
        return 'Too many CAs were provided. A maximum of 4 is accepted.';
    }
}
