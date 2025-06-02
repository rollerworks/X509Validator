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

final class CertificateHasExpired extends Violation
{
    private readonly \DateTimeInterface $expiredOn;

    public function __construct(\DateTimeInterface $expiredOn)
    {
        parent::__construct(\sprintf('The certificate has expired on "%s"', $expiredOn->format(\DATE_RFC3339)));

        $this->expiredOn = $expiredOn;
    }

    public function getTranslatorMsg(): string
    {
        return 'The certificate has expired on { expired_on, date, short }.';
    }

    public function getParameters(): array
    {
        return [
            'expired_on' => $this->expiredOn,
        ];
    }
}
