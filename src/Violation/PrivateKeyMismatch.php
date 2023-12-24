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

final class PrivateKeyMismatch extends Violation
{
    public function __construct()
    {
        parent::__construct('The certificate does not match with the provided private-key.');
    }

    public function getTranslatorMsg(): string
    {
        return 'The certificate does not match with the provided private-key.';
    }
}
