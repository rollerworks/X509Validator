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

final class ToManyCAsProvided extends Violation
{
    public function __construct()
    {
        parent::__construct('To many CAs were provided. A maximum of 3 is accepted.');
    }

    public function getTranslatorMsg(): string
    {
        return 'tls.violation.to_many_ca_provided';
    }
}
