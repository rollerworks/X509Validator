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

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\DoesNotPerformAssertions;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Rollerworks\Component\PdbSfBridge\PdpManager;
use Rollerworks\Component\PdbSfBridge\PdpMockProvider;
use Rollerworks\Component\X509Validator\CertificateValidator;
use Rollerworks\Component\X509Validator\TranslatableArgument;
use Rollerworks\Component\X509Validator\Violation\CertificateHasExpired;
use Rollerworks\Component\X509Validator\Violation\GlobalWildcard;
use Rollerworks\Component\X509Validator\Violation\UnprocessablePEM;
use Rollerworks\Component\X509Validator\Violation\UnsupportedDomain;
use Rollerworks\Component\X509Validator\Violation\UnsupportedPurpose;
use Rollerworks\Component\X509Validator\Violation\WeakSignatureAlgorithm;
use Rollerworks\Component\X509Validator\X509Info;

/**
 * @internal
 */
final class CertificateValidatorTest extends TestCase
{
    private CertificateValidator $certificateValidator;
    private PdpManager $pdpManager;

    protected function setUp(): void
    {
        $this->pdpManager = PdpMockProvider::getPdpManager();
        $this->certificateValidator = new class($this->pdpManager) extends CertificateValidator {
            public ?string $now = '2013-05-29T14:12:14.000000+0000';

            protected function getNow(): \DateTimeImmutable
            {
                if (isset($this->now)) {
                    return new \DateTimeImmutable($this->now);
                }

                return parent::getNow();
            }
        };
    }

    #[Test]
    public function validate_certificate_is_actually_readable(): void
    {
        $certContents = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            MIIDKzCCAhMCCQDZHE66hI+pmjANBgkqhkiG9w0BAQUFADBUMRowGAYDVQQDDBFS
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            -----END CERTIFICATE-----
            CERT;

        try {
            $this->certificateValidator->validateCertificate($certContents);

            self::fail('Exception was expected.');
        } catch (UnprocessablePEM $e) {
            self::assertSame(['name' => ''], $e->getParameters());
            self::assertSame($certContents, $e->getPrevious()?->getPrevious()?->getMessage());
        }
    }

    #[Test]
    public function validate_certificate_is_expired(): void
    {
        $certContents = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            MIIDKzCCAhMCCQDZHE66hI+pmjANBgkqhkiG9w0BAQUFADBUMRowGAYDVQQDDBFS
            b2xsZXJzY2FwZXMgQ0F2MzEVMBMGA1UECgwMUm9sbGVyc2NhcGVzMRIwEAYDVQQH
            DAlSb3R0ZXJkYW0xCzAJBgNVBAYTAk5MMB4XDTE0MDcyNzEzMDIzM1oXDTE4MDcy
            NjEzMDIzM1owWzEhMB8GA1UEAwwYYm9wLmRldi5yb2xsZXJzY2FwZXMubmV0MRUw
            EwYDVQQKDAxSb2xsZXJzY2FwZXMxEjAQBgNVBAcMCVJvdHRlcmRhbTELMAkGA1UE
            BhMCTkwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFN7758InBPIIE
            Q/VoYrj/poR1bGEcupAB+Q68R2C5ac5EGQMwaODCphP1RetLGHJE+4hss9GzJb56
            LfLSKy500Zk6R50zUXNCJwvkMvODHTMDy0xORg7tMbe3kLnHH/lbhmeWmXt5qDxa
            S2jx5A2pKGmoLS8smYFlPRZ0yiK8Ugy5kDWCEFA31TIsGKcofOWcr+vfJ7HltXav
            h1VFZ2nzJC8xKaoFQO4uake225CZQ+W4yhIxu5beY/FXlh2PIZqd1rQhQLuV5gK4
            zGkjNkN6DVJ+7xwnYJ7yeXKlovwMOEJQG1LHnr16gFRRcFeVUHPZkW47QGOYh60n
            rG8/8/kLAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAKLWz2F2bJyhTlHxAORbdugm
            esBbPxlhkCitdXp7uAkQh+0HeJ+jFb+CA0blmGyY3j15t54WV9ySMV8tQRSk5sXl
            VVaJ4AF0uIvT5gbOvL8Vr2ZNiWp2S0Nqx28JVP/KNCAI3PBIWnDcQOON3gHQQi9O
            qmL+vAuODEQ2UvgCd2GgFPqsu79Y1PRbqRIwqNiFasHt9pQNlpzRM6AjtUMldShG
            rpz1WIZIIZuH+TC/iqD7UlSoLxJbe79a6dbBNw7bnWlo+HDl8YfmY6Ks3O6MCbYn
            qVBRc3K9ywcUYPJNVuUazdXuY6FSiGB1iOLxRHppQapmWK5GdtQFXW3GlkXFYf4=
            -----END CERTIFICATE-----
            CERT;

        $ca = <<<'CA'
            -----BEGIN CERTIFICATE-----
            MIIDezCCAmOgAwIBAgIJAJn2g4MHmUlvMA0GCSqGSIb3DQEBBQUAMFQxGjAYBgNV
            BAMMEVJvbGxlcnNjYXBlcyBDQXYzMRUwEwYDVQQKDAxSb2xsZXJzY2FwZXMxEjAQ
            BgNVBAcMCVJvdHRlcmRhbTELMAkGA1UEBhMCTkwwHhcNMTQwMzMwMTQzNjM5WhcN
            MTgwMzI5MTQzNjM5WjBUMRowGAYDVQQDDBFSb2xsZXJzY2FwZXMgQ0F2MzEVMBMG
            A1UECgwMUm9sbGVyc2NhcGVzMRIwEAYDVQQHDAlSb3R0ZXJkYW0xCzAJBgNVBAYT
            Ak5MMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9G4MAqOU6tgIw2gJ
            tZVul3Ef6W37fK2p8MooXJmFRNs6QGloy8bkbAG6rLrmPlOpG4LT6jDpiUOgk4IL
            v0HZr8tSaJCEUaYWYQkc58HqZK0FfVrrzAQC8lVcO2Xl0HehEoPAtVrX+1h2F6/E
            38xzmlbUo2Ileiy6ur0KjCo+p22fd+NIEwvtbd1uySA5GsyzIq0vqpRHJzihgXXU
            TIjxdxZqqHjGslT9Ei97XEYErjFrxlwk8lNFUvxE3u2Xhfhy6qNT1CpcPg8pRVHw
            IdYqn0ApJPxLchfGjuVmcgmnDeTmBtbNGBPw1dsmswm/nvZC8CiDuqgn6PVIhpio
            Eru22wIDAQABo1AwTjAdBgNVHQ4EFgQUAe/6RHDxw475z5c8niR0o4ZiYn0wHwYD
            VR0jBBgwFoAUAe/6RHDxw475z5c8niR0o4ZiYn0wDAYDVR0TBAUwAwEB/zANBgkq
            hkiG9w0BAQUFAAOCAQEA4VMyvK2I2naw+0rm4wu9rRWOoCYuRRchkE+CvFoUDnQq
            CvWKaQApPA2qud4gA+S743GduzSf4jfAe8yGY3oA+bUAnqupF+8l19b6GcMfEop7
            LRkeiSxAVrK2hHxGYMdLXBFqBMS5PaG2LT/m1zjk+j5CJVKAtWHlO8sERSyCqa04
            2wvjlA/ArnZkt8A56kOFeIK2UBOzTozYmW+D5ZkB41JtzquO7Rty/YhVpuOfCoLX
            HuwXgPLW3fDUFmEFnIMqDCxZA5NEc+1QapjBkC8cU4xPKjIE3Ljm4Nhq0I67ipC1
            Jzgsmb7yKoigkH/BZ5sm/spdlz3/eXuEtcC6gLfsPA==
            -----END CERTIFICATE-----
            CA;

        try {
            $this->certificateValidator->now = null;
            $this->certificateValidator->validateCertificate($certContents, ['root' => $ca]);

            self::fail('Exception was expected.');
        } catch (CertificateHasExpired $e) {
            self::assertEquals(['expired_on' => new \DateTimeImmutable('2018-07-26T13:02:33.000000+0000')], $e->getParameters());
        }
    }

    /** @param array<int, string> $domains */
    #[Test]
    #[DataProvider('provideValidate_certificate_host_contains_global_wildcardCases')]
    public function validate_certificate_host_contains_global_wildcard(array $domains, string $provided, string $suffixPattern): void
    {
        $this->certificateValidator = new FakedCertificateValidator($this->pdpManager);
        $this->certificateValidator->setFields([
            '_domains' => $domains,
            '_validTo' => new \DateTimeImmutable('+1 year'),
            'signatureTypeLN' => 'sha256WithEncryption',
        ]);

        try {
            $this->certificateValidator->validateCertificate('I am not a CERT', []);

            self::fail('Exception was expected.');
        } catch (GlobalWildcard $e) {
            self::assertSame([
                'provided' => $provided,
                'suffix_pattern' => $suffixPattern,
            ], $e->getParameters());
        }
    }

    /** @return \Generator<int, array{0: array<int, string>, 1: string, 2: string}> */
    public static function provideValidate_certificate_host_contains_global_wildcardCases(): iterable
    {
        yield [['example.com', '*'], '*', '*'];
        yield [['*.doodoodoodoodoodoo.com', '*.com'], '*.com', 'com'];
        yield [['*.doodoodoodoodoodoo.com', '*.com'], '*.com', 'com'];
        yield [['*.org.ae'], '*.org.ae', 'org.ae'];
        yield [['*.org'], '*.org', 'org'];
        yield [['*.qld.edu.au'], '*.qld.edu.au', 'qld.edu.au'];
    }

    /** @param array<int, string> $domains */
    #[Test]
    #[DataProvider('provideValidate_certificate_host_wildcard_without_known_prefixCases')]
    #[DoesNotPerformAssertions]
    public function validate_certificate_host_wildcard_without_known_prefix_does_not_fail(array $domains): void
    {
        $this->certificateValidator = new FakedCertificateValidator($this->pdpManager);
        $this->certificateValidator->setFields([
            '_domains' => $domains,
            '_validTo' => new \DateTimeImmutable('+1 year'),
            'signatureTypeLN' => 'sha256WithEncryption',
        ]);

        $cert = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh
            MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
            d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
            QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT
            MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
            b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG
            9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB
            CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97
            nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt
            43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P
            T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4
            gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO
            BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR
            TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw
            DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr
            hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg
            06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF
            PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls
            YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk
            CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=
            -----END CERTIFICATE-----
            CERT;

        $this->certificateValidator->validateCertificate($cert, []);
    }

    /** @return \Generator<int, array<int, array{0: string, 1: string}>> */
    public static function provideValidate_certificate_host_wildcard_without_known_prefixCases(): iterable
    {
        yield [['example.com', '*.doodoodooo']];
        yield [['example.com', '*.nope.net']];
    }

    #[Test]
    public function validate_certificate_signature_algorithm(): void
    {
        $certContents = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            MIIDKzCCAhMCCQDZHE66hI+pmjANBgkqhkiG9w0BAQUFADBUMRowGAYDVQQDDBFS
            b2xsZXJzY2FwZXMgQ0F2MzEVMBMGA1UECgwMUm9sbGVyc2NhcGVzMRIwEAYDVQQH
            DAlSb3R0ZXJkYW0xCzAJBgNVBAYTAk5MMB4XDTE0MDcyNzEzMDIzM1oXDTE4MDcy
            NjEzMDIzM1owWzEhMB8GA1UEAwwYYm9wLmRldi5yb2xsZXJzY2FwZXMubmV0MRUw
            EwYDVQQKDAxSb2xsZXJzY2FwZXMxEjAQBgNVBAcMCVJvdHRlcmRhbTELMAkGA1UE
            BhMCTkwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFN7758InBPIIE
            Q/VoYrj/poR1bGEcupAB+Q68R2C5ac5EGQMwaODCphP1RetLGHJE+4hss9GzJb56
            LfLSKy500Zk6R50zUXNCJwvkMvODHTMDy0xORg7tMbe3kLnHH/lbhmeWmXt5qDxa
            S2jx5A2pKGmoLS8smYFlPRZ0yiK8Ugy5kDWCEFA31TIsGKcofOWcr+vfJ7HltXav
            h1VFZ2nzJC8xKaoFQO4uake225CZQ+W4yhIxu5beY/FXlh2PIZqd1rQhQLuV5gK4
            zGkjNkN6DVJ+7xwnYJ7yeXKlovwMOEJQG1LHnr16gFRRcFeVUHPZkW47QGOYh60n
            rG8/8/kLAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAKLWz2F2bJyhTlHxAORbdugm
            esBbPxlhkCitdXp7uAkQh+0HeJ+jFb+CA0blmGyY3j15t54WV9ySMV8tQRSk5sXl
            VVaJ4AF0uIvT5gbOvL8Vr2ZNiWp2S0Nqx28JVP/KNCAI3PBIWnDcQOON3gHQQi9O
            qmL+vAuODEQ2UvgCd2GgFPqsu79Y1PRbqRIwqNiFasHt9pQNlpzRM6AjtUMldShG
            rpz1WIZIIZuH+TC/iqD7UlSoLxJbe79a6dbBNw7bnWlo+HDl8YfmY6Ks3O6MCbYn
            qVBRc3K9ywcUYPJNVuUazdXuY6FSiGB1iOLxRHppQapmWK5GdtQFXW3GlkXFYf4=
            -----END CERTIFICATE-----
            CERT;

        $ca = <<<'CA'
            -----BEGIN CERTIFICATE-----
            MIIDezCCAmOgAwIBAgIJAJn2g4MHmUlvMA0GCSqGSIb3DQEBBQUAMFQxGjAYBgNV
            BAMMEVJvbGxlcnNjYXBlcyBDQXYzMRUwEwYDVQQKDAxSb2xsZXJzY2FwZXMxEjAQ
            BgNVBAcMCVJvdHRlcmRhbTELMAkGA1UEBhMCTkwwHhcNMTQwMzMwMTQzNjM5WhcN
            MTgwMzI5MTQzNjM5WjBUMRowGAYDVQQDDBFSb2xsZXJzY2FwZXMgQ0F2MzEVMBMG
            A1UECgwMUm9sbGVyc2NhcGVzMRIwEAYDVQQHDAlSb3R0ZXJkYW0xCzAJBgNVBAYT
            Ak5MMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9G4MAqOU6tgIw2gJ
            tZVul3Ef6W37fK2p8MooXJmFRNs6QGloy8bkbAG6rLrmPlOpG4LT6jDpiUOgk4IL
            v0HZr8tSaJCEUaYWYQkc58HqZK0FfVrrzAQC8lVcO2Xl0HehEoPAtVrX+1h2F6/E
            38xzmlbUo2Ileiy6ur0KjCo+p22fd+NIEwvtbd1uySA5GsyzIq0vqpRHJzihgXXU
            TIjxdxZqqHjGslT9Ei97XEYErjFrxlwk8lNFUvxE3u2Xhfhy6qNT1CpcPg8pRVHw
            IdYqn0ApJPxLchfGjuVmcgmnDeTmBtbNGBPw1dsmswm/nvZC8CiDuqgn6PVIhpio
            Eru22wIDAQABo1AwTjAdBgNVHQ4EFgQUAe/6RHDxw475z5c8niR0o4ZiYn0wHwYD
            VR0jBBgwFoAUAe/6RHDxw475z5c8niR0o4ZiYn0wDAYDVR0TBAUwAwEB/zANBgkq
            hkiG9w0BAQUFAAOCAQEA4VMyvK2I2naw+0rm4wu9rRWOoCYuRRchkE+CvFoUDnQq
            CvWKaQApPA2qud4gA+S743GduzSf4jfAe8yGY3oA+bUAnqupF+8l19b6GcMfEop7
            LRkeiSxAVrK2hHxGYMdLXBFqBMS5PaG2LT/m1zjk+j5CJVKAtWHlO8sERSyCqa04
            2wvjlA/ArnZkt8A56kOFeIK2UBOzTozYmW+D5ZkB41JtzquO7Rty/YhVpuOfCoLX
            HuwXgPLW3fDUFmEFnIMqDCxZA5NEc+1QapjBkC8cU4xPKjIE3Ljm4Nhq0I67ipC1
            Jzgsmb7yKoigkH/BZ5sm/spdlz3/eXuEtcC6gLfsPA==
            -----END CERTIFICATE-----
            CA;

        try {
            $this->certificateValidator->validateCertificate($certContents, ['root' => $ca]);

            self::fail('Exception was expected.');
        } catch (WeakSignatureAlgorithm $e) {
            self::assertSame([
                'expected' => 'SHA256',
                'provided' => 'sha1WithRSAEncryption',
            ], $e->getParameters());
        }
    }

    #[Test]
    public function validate_certificate_data_is_readable(): void
    {
        $certContents = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            MIIDKzCCAhMCCQDZHE66hI+pmjANBgkqhkiG9w0BAQUFADBUMRowGAYDVQQDDBFS
            AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            -----END CERTIFICATE-----
            CERT;

        try {
            $this->certificateValidator->validateCertificate($certContents);

            self::fail('Exception was expected.');
        } catch (UnprocessablePEM $e) {
            self::assertSame($certContents, $e->getPrevious()?->getPrevious()?->getMessage());
            self::assertSame([
                'name' => '',
            ], $e->getParameters());
        }
    }

    #[Test]
    public function validate_certificate_purpose_is_not_supported(): void
    {
        $certContents = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            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
            -----END CERTIFICATE-----
            CERT;

        try {
            $this->certificateValidator->validateCertificatePurpose($certContents, CertificateValidator::PURPOSE_SMIME);

            self::fail('Exception was expected.');
        } catch (UnsupportedPurpose $e) {
            self::assertEquals(['required_purpose' => new TranslatableArgument('S/MIME signing', domain: 'messages')], $e->getParameters());
        }
    }

    #[Test]
    #[DoesNotPerformAssertions]
    public function validate_certificate_purpose_with_supported_purpose_works(): void
    {
        $certContents = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            MIIDKzCCAhMCCQDZHE66hI+pmjANBgkqhkiG9w0BAQUFADBUMRowGAYDVQQDDBFS
            b2xsZXJzY2FwZXMgQ0F2MzEVMBMGA1UECgwMUm9sbGVyc2NhcGVzMRIwEAYDVQQH
            DAlSb3R0ZXJkYW0xCzAJBgNVBAYTAk5MMB4XDTE0MDcyNzEzMDIzM1oXDTE4MDcy
            NjEzMDIzM1owWzEhMB8GA1UEAwwYYm9wLmRldi5yb2xsZXJzY2FwZXMubmV0MRUw
            EwYDVQQKDAxSb2xsZXJzY2FwZXMxEjAQBgNVBAcMCVJvdHRlcmRhbTELMAkGA1UE
            BhMCTkwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFN7758InBPIIE
            Q/VoYrj/poR1bGEcupAB+Q68R2C5ac5EGQMwaODCphP1RetLGHJE+4hss9GzJb56
            LfLSKy500Zk6R50zUXNCJwvkMvODHTMDy0xORg7tMbe3kLnHH/lbhmeWmXt5qDxa
            S2jx5A2pKGmoLS8smYFlPRZ0yiK8Ugy5kDWCEFA31TIsGKcofOWcr+vfJ7HltXav
            h1VFZ2nzJC8xKaoFQO4uake225CZQ+W4yhIxu5beY/FXlh2PIZqd1rQhQLuV5gK4
            zGkjNkN6DVJ+7xwnYJ7yeXKlovwMOEJQG1LHnr16gFRRcFeVUHPZkW47QGOYh60n
            rG8/8/kLAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAKLWz2F2bJyhTlHxAORbdugm
            esBbPxlhkCitdXp7uAkQh+0HeJ+jFb+CA0blmGyY3j15t54WV9ySMV8tQRSk5sXl
            VVaJ4AF0uIvT5gbOvL8Vr2ZNiWp2S0Nqx28JVP/KNCAI3PBIWnDcQOON3gHQQi9O
            qmL+vAuODEQ2UvgCd2GgFPqsu79Y1PRbqRIwqNiFasHt9pQNlpzRM6AjtUMldShG
            rpz1WIZIIZuH+TC/iqD7UlSoLxJbe79a6dbBNw7bnWlo+HDl8YfmY6Ks3O6MCbYn
            qVBRc3K9ywcUYPJNVuUazdXuY6FSiGB1iOLxRHppQapmWK5GdtQFXW3GlkXFYf4=
            -----END CERTIFICATE-----
            CERT;

        $this->certificateValidator->validateCertificatePurpose($certContents, CertificateValidator::PURPOSE_SSL_SERVER);
    }

    #[Test]
    #[DataProvider('provideValidate_certificate_host_is_not_supportedCases')]
    public function validate_certificate_host_is_not_supported(string $cert, string $hostPattern, string $supported): void
    {
        try {
            $this->certificateValidator->validateCertificateHost($cert, $hostPattern);

            self::fail('Exception was expected.');
        } catch (UnsupportedDomain $e) {
            self::assertSame(['required_pattern' => $hostPattern, 'supported' => $supported], $e->getParameters());
        }
    }

    /** @return \Generator<int, array{0: string, 1: string, 2: string}> */
    public static function provideValidate_certificate_host_is_not_supportedCases(): iterable
    {
        $cert1 = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            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
            -----END CERTIFICATE-----
            CERT;

        $cert2 = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            MIIDKzCCAhMCCQDZHE66hI+pmjANBgkqhkiG9w0BAQUFADBUMRowGAYDVQQDDBFS
            b2xsZXJzY2FwZXMgQ0F2MzEVMBMGA1UECgwMUm9sbGVyc2NhcGVzMRIwEAYDVQQH
            DAlSb3R0ZXJkYW0xCzAJBgNVBAYTAk5MMB4XDTE0MDcyNzEzMDIzM1oXDTE4MDcy
            NjEzMDIzM1owWzEhMB8GA1UEAwwYYm9wLmRldi5yb2xsZXJzY2FwZXMubmV0MRUw
            EwYDVQQKDAxSb2xsZXJzY2FwZXMxEjAQBgNVBAcMCVJvdHRlcmRhbTELMAkGA1UE
            BhMCTkwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFN7758InBPIIE
            Q/VoYrj/poR1bGEcupAB+Q68R2C5ac5EGQMwaODCphP1RetLGHJE+4hss9GzJb56
            LfLSKy500Zk6R50zUXNCJwvkMvODHTMDy0xORg7tMbe3kLnHH/lbhmeWmXt5qDxa
            S2jx5A2pKGmoLS8smYFlPRZ0yiK8Ugy5kDWCEFA31TIsGKcofOWcr+vfJ7HltXav
            h1VFZ2nzJC8xKaoFQO4uake225CZQ+W4yhIxu5beY/FXlh2PIZqd1rQhQLuV5gK4
            zGkjNkN6DVJ+7xwnYJ7yeXKlovwMOEJQG1LHnr16gFRRcFeVUHPZkW47QGOYh60n
            rG8/8/kLAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAKLWz2F2bJyhTlHxAORbdugm
            esBbPxlhkCitdXp7uAkQh+0HeJ+jFb+CA0blmGyY3j15t54WV9ySMV8tQRSk5sXl
            VVaJ4AF0uIvT5gbOvL8Vr2ZNiWp2S0Nqx28JVP/KNCAI3PBIWnDcQOON3gHQQi9O
            qmL+vAuODEQ2UvgCd2GgFPqsu79Y1PRbqRIwqNiFasHt9pQNlpzRM6AjtUMldShG
            rpz1WIZIIZuH+TC/iqD7UlSoLxJbe79a6dbBNw7bnWlo+HDl8YfmY6Ks3O6MCbYn
            qVBRc3K9ywcUYPJNVuUazdXuY6FSiGB1iOLxRHppQapmWK5GdtQFXW3GlkXFYf4=
            -----END CERTIFICATE-----
            CERT;

        yield [$cert1, 'example.com', 'slack.com, *.slack.com'];
        yield [$cert1, '*.t.slack.com', 'slack.com, *.slack.com'];
        yield [$cert2, 'example.com', 'bop.dev.rollerscapes.net'];
        yield [$cert2, 'bob.rollerscapes.com', 'bop.dev.rollerscapes.net'];
        yield [$cert2, '*.rollerscapes.com', 'bop.dev.rollerscapes.net'];
    }

    #[Test]
    #[DoesNotPerformAssertions]
    public function validate_certificate_host_is_supported(): void
    {
        $cert = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            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
            -----END CERTIFICATE-----
            CERT;

        $this->certificateValidator->validateCertificateHost($cert, '*.slack.com');
        $this->certificateValidator->validateCertificateHost($cert, 'test.slack.com');
        $this->certificateValidator->validateCertificateHost($cert, 'slack.com');
    }

    #[Test]
    public function validate_certificate_support(): void
    {
        $cert = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            MIIDKzCCAhMCCQDZHE66hI+pmjANBgkqhkiG9w0BAQUFADBUMRowGAYDVQQDDBFS
            b2xsZXJzY2FwZXMgQ0F2MzEVMBMGA1UECgwMUm9sbGVyc2NhcGVzMRIwEAYDVQQH
            DAlSb3R0ZXJkYW0xCzAJBgNVBAYTAk5MMB4XDTE0MDcyNzEzMDIzM1oXDTE4MDcy
            NjEzMDIzM1owWzEhMB8GA1UEAwwYYm9wLmRldi5yb2xsZXJzY2FwZXMubmV0MRUw
            EwYDVQQKDAxSb2xsZXJzY2FwZXMxEjAQBgNVBAcMCVJvdHRlcmRhbTELMAkGA1UE
            BhMCTkwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDFN7758InBPIIE
            Q/VoYrj/poR1bGEcupAB+Q68R2C5ac5EGQMwaODCphP1RetLGHJE+4hss9GzJb56
            LfLSKy500Zk6R50zUXNCJwvkMvODHTMDy0xORg7tMbe3kLnHH/lbhmeWmXt5qDxa
            S2jx5A2pKGmoLS8smYFlPRZ0yiK8Ugy5kDWCEFA31TIsGKcofOWcr+vfJ7HltXav
            h1VFZ2nzJC8xKaoFQO4uake225CZQ+W4yhIxu5beY/FXlh2PIZqd1rQhQLuV5gK4
            zGkjNkN6DVJ+7xwnYJ7yeXKlovwMOEJQG1LHnr16gFRRcFeVUHPZkW47QGOYh60n
            rG8/8/kLAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAKLWz2F2bJyhTlHxAORbdugm
            esBbPxlhkCitdXp7uAkQh+0HeJ+jFb+CA0blmGyY3j15t54WV9ySMV8tQRSk5sXl
            VVaJ4AF0uIvT5gbOvL8Vr2ZNiWp2S0Nqx28JVP/KNCAI3PBIWnDcQOON3gHQQi9O
            qmL+vAuODEQ2UvgCd2GgFPqsu79Y1PRbqRIwqNiFasHt9pQNlpzRM6AjtUMldShG
            rpz1WIZIIZuH+TC/iqD7UlSoLxJbe79a6dbBNw7bnWlo+HDl8YfmY6Ks3O6MCbYn
            qVBRc3K9ywcUYPJNVuUazdXuY6FSiGB1iOLxRHppQapmWK5GdtQFXW3GlkXFYf4=
            -----END CERTIFICATE-----
            CERT;

        $callback = static function (X509Info $fields, string $certContents, CertificateValidator $validator) use ($cert): never {
            self::assertSame($cert, $certContents);

            self::assertArrayHasKey('subject', $fields->allFields);
            self::assertArrayHasKey('_domains', $fields->allFields);

            throw new \RuntimeException('No, this is not valid. Or is it?');
        };

        $this->expectExceptionObject(new \RuntimeException('No, this is not valid. Or is it?'));

        $this->certificateValidator->validateCertificateSupport($cert, $callback);
    }
}

/**
 * @internal
 */
final class FakedCertificateValidator extends CertificateValidator
{
    private ?X509Info $fields;

    /** @param array<string, mixed> $fields */
    public function setFields(array $fields): void
    {
        $this->fields = new X509Info($fields);
    }

    protected function extractRawData(string $contents): X509Info
    {
        if (! isset($this->fields)) {
            return parent::extractRawData($contents);
        }

        return $this->fields;
    }
}
