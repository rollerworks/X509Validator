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

use PHPUnit\Framework\Assert;
use Rollerworks\Component\X509Validator\Violation;
use Symfony\Component\Translation\Loader\XliffFileLoader;
use Symfony\Component\Translation\Translator;

trait TranslatorAssertionTrait
{
    private static function assertTranslationEquals(string $expected, Violation $e): void
    {
        static $translator;

        if (! isset($translator)) {
            $translator = new Translator('en');
            $translator->addLoader('xliff', new XliffFileLoader());
            $translator->addResource('xliff', \dirname(__DIR__) . '/Resources/translations/validators+intl-icu.en.xliff', 'en', 'validators+intl-icu');
        }

        Assert::assertEquals($expected, $e->trans($translator));
    }
}
