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

use Ocsp\Ocsp;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Prophecy\Argument;
use Prophecy\PhpUnit\ProphecyTrait;
use Psr\Log\LoggerAwareInterface;
use Psr\Log\LoggerInterface;
use Rollerworks\Component\X509Validator\OCSPValidator;
use Rollerworks\Component\X509Validator\TranslatableArgument;
use Rollerworks\Component\X509Validator\Violation\CertificateIsRevoked;
use Rollerworks\Component\X509Validator\Violation\UnprocessablePEM;
use Symfony\Component\ErrorHandler\BufferingLogger;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * @internal
 */
final class OCSPValidatorTest extends TestCase
{
    use ProphecyTrait;
    use TranslatorAssertionTrait;

    private OCSPValidator $certificateValidator;

    protected function setUp(): void
    {
        /** @var HttpClientInterface&LoggerAwareInterface $httpClient */
        $httpClient = HttpClient::create();
        $httpClient->setLogger(new BufferingLogger());

        $this->certificateValidator = new OCSPValidator(
            httpClient: $httpClient,
            logger: $this->expectNoFailureLogs(),
        );
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
            $this->certificateValidator->validateStatus($certContents);

            self::fail('Exception was expected.');
        } catch (UnprocessablePEM $e) {
            self::assertSame(['name' => ''], $e->getParameters());
            self::assertSame($certContents, $e->getPrevious()?->getPrevious()?->getMessage());

            self::assertTranslationEquals('Unable to process certificate. Only PEM encoded X.509 files are supported.', $e);
        }
    }

    #[Test]
    public function validate_certificate_is_revoked(): void
    {
        $certContents = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            MIIG4DCCBmagAwIBAgIQBZy2esMzb+7oVrJyhjxvUzAKBggqhkjOPQQDAzBUMQsw
            CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xLDAqBgNVBAMTI0Rp
            Z2lDZXJ0IEc1IFRMUyBFQ0MgU0hBMzg0IDIwMjEgQ0ExMB4XDTIzMDMxNjAwMDAw
            MFoXDTI0MDQxNTIzNTk1OVowge8xEzARBgsrBgEEAYI3PAIBAxMCVVMxFTATBgsr
            BgEEAYI3PAIBAhMEVXRhaDEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24x
            FTATBgNVBAUTDDUyOTk1MzctMDE0MjELMAkGA1UEBhMCVVMxDTALBgNVBAgTBFV0
            YWgxDTALBgNVBAcTBExlaGkxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUcwRQYD
            VQQDEz5kaWdpY2VydC10bHMtZWNjLXAzODQtcm9vdC1nNS1yZXZva2VkLmNoYWlu
            LWRlbW9zLmRpZ2ljZXJ0LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
            ggEBAK3SEGd7aOOyi9rknL/GpNSovKvxOeJzrpO7Spq1Ag7KeAtx6kYDm7xgvOXM
            EPPylKDCvtXl1ic+PYBBVpNZEhHTVefdb9CzsTEcOYLaPFIAOnmie1HHczY57H2f
            JqvaYqE4VJWAHWuGMf90ZYSkqtoGJJsnLs/Ajd3lawIeUwPCDdWKQiUVG53Ruk5G
            KRct/Jnxo2qX1GMPt63Q4nvjb0p+4UvWYfBSCAD6UehkdGb1RkbEgKxwBUbFzh7p
            dQ1WDIVzV0C6OPdt4LUqvVYVw9DpmMSF3YUOvvDEhx1w5bR8JIzmlFYP/IMBx1Bl
            a9WWbVjCbASq6Z4XrWMpgNoYBEkCAwEAAaOCA7EwggOtMB8GA1UdIwQYMBaAFJtY
            3I2mZZjnvAb+GqQVoG/L5qmQMB0GA1UdDgQWBBSsdJukmxK5PpB8IpqyeWO1KJt1
            EzBJBgNVHREEQjBAgj5kaWdpY2VydC10bHMtZWNjLXAzODQtcm9vdC1nNS1yZXZv
            a2VkLmNoYWluLWRlbW9zLmRpZ2ljZXJ0LmNvbTAOBgNVHQ8BAf8EBAMCBaAwHQYD
            VR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMIGTBgNVHR8EgYswgYgwQqBAoD6G
            PGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEc1VExTRUNDU0hBMzg0
            MjAyMUNBMS0xLmNybDBCoECgPoY8aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0Rp
            Z2lDZXJ0RzVUTFNFQ0NTSEEzODQyMDIxQ0ExLTEuY3JsMEoGA1UdIARDMEEwCwYJ
            YIZIAYb9bAIBMDIGBWeBDAEBMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGln
            aWNlcnQuY29tL0NQUzCBgQYIKwYBBQUHAQEEdTBzMCQGCCsGAQUFBzABhhhodHRw
            Oi8vb2NzcC5kaWdpY2VydC5jb20wSwYIKwYBBQUHMAKGP2h0dHA6Ly9jYWNlcnRz
            LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEc1VExTRUNDU0hBMzg0MjAyMUNBMS0xLmNy
            dDAJBgNVHRMEAjAAMIIBfgYKKwYBBAHWeQIEAgSCAW4EggFqAWgAdgDuzdBk1dsa
            zsVct520zROiModGfLzs3sNRSFlGcR+1mwAAAYbrrv/aAAAEAwBHMEUCIBj/mZ6B
            QbGrMpNBZoWihQ7+ckmYk1ZbEi/sxPFluT++AiEAzdLuAClGxj5Qw/9yv9XcuVgo
            LJxuiPNFmI3cifmpY/UAdwA7U3d1Pi25gE6LMFsG/kA7Z9hPw/THvQANLXJv4frU
            FwAAAYbrrwAfAAAEAwBIMEYCIQCZUf8y3yPDyIA/hfhvZ21ukC3zcdunoqVq+TQW
            YksMpgIhALfmINPZJmrjy5T/zeHxCxHCHaBpRMIKGAej1JkgeknSAHUAdv+IPwq2
            +5VRwmHM9Ye6NLSkzbsp3GhCCp/mZ0xaOnQAAAGG668ATwAABAMARjBEAiBWGuOl
            X3fLXWfP3ihTE9q/c5sco24KNW0Ij6NaK40hcgIgFKryWdWqqZRoI9LgeBqkzs2p
            8ivZEu2wLXX+RoyoCL4wCgYIKoZIzj0EAwMDaAAwZQIxAKcEoh9LUSQ2h/XcESEG
            LxpGGAcssmrUXBDE0jJPSGgg1ypiE0ay+nYv3TIxVenpIQIweLQmI/ljlQtRBEEh
            JdnlcMbdN5VOUqtwqd3jEVBgU6vyUmRltnZybBAMUiBpWX+t
            -----END CERTIFICATE-----
            CERT;

        $ca1 = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            MIIDajCCAu+gAwIBAgIQBBxdKC6zcQ5rcsLavSZxbzAKBggqhkjOPQQDAzBOMQsw
            CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xJjAkBgNVBAMTHURp
            Z2lDZXJ0IFRMUyBFQ0MgUDM4NCBSb290IEc1MB4XDTIxMDQxNDAwMDAwMFoXDTMx
            MDQxMzIzNTk1OVowVDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
            bmMuMSwwKgYDVQQDEyNEaWdpQ2VydCBHNSBUTFMgRUNDIFNIQTM4NCAyMDIxIENB
            MTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLzRK0f/iJs+T+i9//yOWT++GUuwRjML
            dbsA+9YQsrHFyayUZeqYRATordp1DcodGY/1DxRAwDDEi0cmkfHX08nLQ0ujF1Vh
            dlBxYUPol2HLYjN3EzVAcDC8V5uiQc5zCqOCAYowggGGMBIGA1UdEwEB/wQIMAYB
            Af8CAQAwHQYDVR0OBBYEFJtY3I2mZZjnvAb+GqQVoG/L5qmQMB8GA1UdIwQYMBaA
            FMFRRVBZqz7nLFr6ICISB4CIfBFqMA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAU
            BggrBgEFBQcDAQYIKwYBBQUHAwIwegYIKwYBBQUHAQEEbjBsMCQGCCsGAQUFBzAB
            hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wRAYIKwYBBQUHMAKGOGh0dHA6Ly9j
            YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRMU0VDQ1AzODRSb290RzUuY3J0
            MEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdp
            Q2VydFRMU0VDQ1AzODRSb290RzUuY3JsMD0GA1UdIAQ2MDQwCwYJYIZIAYb9bAIB
            MAcGBWeBDAEBMAgGBmeBDAECATAIBgZngQwBAgIwCAYGZ4EMAQIDMAoGCCqGSM49
            BAMDA2kAMGYCMQDt1p2aebRUXBPN1FXg+V6oG+mRLdRC49k8dSxwRG77lsj1YqTO
            IvZuhDckSAkMNGICMQD4lvGyMGMQirgiqAaMdybUTpcDTLtRQPKiGVZOoSaRtq8o
            gRocsHZfwG69pfWn10Y=
            -----END CERTIFICATE-----
            CERT;

        $ca2 = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            MIIDIDCCAqagAwIBAgIQDdiPPdDfPycTMSudQiae5zAKBggqhkjOPQQDAzBhMQsw
            CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
            ZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMzAe
            Fw0yMjA5MjEwMDAwMDBaFw0zNzA5MjAyMzU5NTlaME4xCzAJBgNVBAYTAlVTMRcw
            FQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEmMCQGA1UEAxMdRGlnaUNlcnQgVExTIEVD
            QyBQMzg0IFJvb3QgRzUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATBRKHPEZdQmt4j
            gjUHzdDLGJ3S8X93NU873ZRyUu3CO/js+ntrWCDsma7J/GizdbnbCezIE/VOxgod
            ZjBMux9HCjxhEEIpfKUIDuAi6dM1aM6bY5+EtZlNWKCO9VTnlcmjggE0MIIBMDAP
            BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTBUUVQWas+5yxa+iAiEgeAiHwRajAf
            BgNVHSMEGDAWgBSz20ik+aHF2K42QcwRY2liKbxLxjAOBgNVHQ8BAf8EBAMCAYYw
            dgYIKwYBBQUHAQEEajBoMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
            dC5jb20wQAYIKwYBBQUHMAKGNGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9E
            aWdpQ2VydEdsb2JhbFJvb3RHMy5jcnQwQgYDVR0fBDswOTA3oDWgM4YxaHR0cDov
            L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsUm9vdEczLmNybDARBgNV
            HSAECjAIMAYGBFUdIAAwCgYIKoZIzj0EAwMDaAAwZQIwWaC7MYlkl+PK+/jDHt/6
            +exBh3Dt+pwj3KFpgZBWvKWLBGZUyX9WNBtj1eNgfCtXAjEApDGlZlvWDpn5/Dqe
            NzZ6X97ngPkW2Eygum0xfANTThtvuxA8KQr3/ME81/h/Tj9O
            -----END CERTIFICATE-----
            CERT;

        $ca3 = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            MIICPzCCAcWgAwIBAgIQBVVWvPJepDU1w6QP1atFcjAKBggqhkjOPQQDAzBhMQsw
            CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
            ZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMzAe
            Fw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVTMRUw
            EwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20x
            IDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEczMHYwEAYHKoZIzj0CAQYF
            K4EEACIDYgAE3afZu4q4C/sLfyHS8L6+c/MzXRq8NOrexpu80JX28MzQC7phW1FG
            fp4tn+6OYwwX7Adw9c+ELkCDnOg/QW07rdOkFFk2eJ0DQ+4QE2xy3q6Ip6FrtUPO
            Z9wj/wMco+I+o0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAd
            BgNVHQ4EFgQUs9tIpPmhxdiuNkHMEWNpYim8S8YwCgYIKoZIzj0EAwMDaAAwZQIx
            AK288mw/EkrRLTnDCgmXc/SINoyIJ7vmiI1Qhadj+Z4y3maTD/HMsQmP3Wyr+mt/
            oAIwOWZbwmSNuJ5Q3KjVSaLtx9zRSX8XAbjIho9OjIgrqJqpisXRAL34VOKa5Vt8
            sycX
            -----END CERTIFICATE-----
            CERT;

        $httpClient = HttpClient::create();

        $this->certificateValidator = new OCSPValidator(
            httpClient: $httpClient,
        );

        try {
            $this->certificateValidator->validateStatus($certContents, [
                'DigiCert G5 TLS ECC SHA384 2021 CA1' => $ca1,
                'DigiCert TLS ECC P384 Root G5' => $ca2,
                'DigiCert Global Root G3' => $ca3,
            ]);

            self::fail('Exception was expected.');
        } catch (CertificateIsRevoked $e) {
            self::assertEquals([
                'revoked_on' => new \DateTimeImmutable('2023-03-16T19:37:43.000000+0000'),
                'reason_code' => 'unspecified',
                'reason' => new TranslatableArgument('no specific reason was given'),
                'serial' => '7459839413651464540545224973334900563',
            ], $e->getParameters());

            self::assertTranslationEquals('The certificate with serial-number "7459839413651464540545224973334900563" was marked as revoked on 3/16/23 with reason: (unspecified) no specific reason was given.', $e);
        }
    }

    #[Test]
    public function validate_certificate_revocation_status_in_wrong_format_only_logs(): void
    {
        $certContents = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            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
            -----END CERTIFICATE-----
            CERT;

        $ca1 = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            MIIElDCCA3ygAwIBAgIQAf2j627KdciIQ4tyS8+8kTANBgkqhkiG9w0BAQsFADBh
            MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
            d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
            QTAeFw0xMzAzMDgxMjAwMDBaFw0yMzAzMDgxMjAwMDBaME0xCzAJBgNVBAYTAlVT
            MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJzAlBgNVBAMTHkRpZ2lDZXJ0IFNIQTIg
            U2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
            ANyuWJBNwcQwFZA1W248ghX1LFy949v/cUP6ZCWA1O4Yok3wZtAKc24RmDYXZK83
            nf36QYSvx6+M/hpzTc8zl5CilodTgyu5pnVILR1WN3vaMTIa16yrBvSqXUu3R0bd
            KpPDkC55gIDvEwRqFDu1m5K+wgdlTvza/P96rtxcflUxDOg5B6TXvi/TC2rSsd9f
            /ld0Uzs1gN2ujkSYs58O09rg1/RrKatEp0tYhG2SS4HD2nOLEpdIkARFdRrdNzGX
            kujNVA075ME/OV4uuPNcfhCOhkEAjUVmR7ChZc6gqikJTvOX6+guqw9ypzAO+sf0
            /RR3w6RbKFfCs/mC/bdFWJsCAwEAAaOCAVowggFWMBIGA1UdEwEB/wQIMAYBAf8C
            AQAwDgYDVR0PAQH/BAQDAgGGMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYY
            aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMHsGA1UdHwR0MHIwN6A1oDOGMWh0dHA6
            Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcmwwN6A1
            oDOGMWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RD
            QS5jcmwwPQYDVR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8v
            d3d3LmRpZ2ljZXJ0LmNvbS9DUFMwHQYDVR0OBBYEFA+AYRyCMWHVLyjnjUY4tCzh
            xtniMB8GA1UdIwQYMBaAFAPeUDVW0Uy7ZvCj4hsbw5eyPdFVMA0GCSqGSIb3DQEB
            CwUAA4IBAQAjPt9L0jFCpbZ+QlwaRMxp0Wi0XUvgBCFsS+JtzLHgl4+mUwnNqipl
            5TlPHoOlblyYoiQm5vuh7ZPHLgLGTUq/sELfeNqzqPlt/yGFUzZgTHbO7Djc1lGA
            8MXW5dRNJ2Srm8c+cftIl7gzbckTB+6WohsYFfZcTEDts8Ls/3HB40f/1LkAtDdC
            2iDJ6m6K7hQGrn2iWZiIqBtvLfTyyRRfJs8sjX7tN8Cp1Tm5gr8ZDOo0rwAhaPit
            c+LJMto4JQtV05od8GiG7S5BNO98pVAdvzr508EIDObtHopYJeS4d60tbvVS3bR0
            j6tJLp07kzQoH3jOlOrHvdPJbRzeXDLz
            -----END CERTIFICATE-----
            CERT;

        $ca2 = <<<'CERT'
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

        $responseFactory = static function ($method, $url, $options) {
            self::assertSame('http://ocsp.digicert.com/', $url);

            return new MockResponse($options['body'], ['response_headers' => ['content-type' => 'text/html']]);
        };
        $httpClient = new MockHttpClient($responseFactory);

        $ocspProphecy = $this->prophesize(Ocsp::class);
        $ocspProphecy->buildOcspRequestBodySingle(Argument::any())->willReturn('Valid');
        $ocspProphecy->decodeOcspResponseSingle(Argument::any())->shouldNotBeCalled();
        $ocsp = $ocspProphecy->reveal();

        $logger = new TestLogger();

        $this->certificateValidator = new OCSPValidator(
            httpClient: $httpClient,
            logger: $logger,
            ocsp: $ocsp,
        );

        $this->certificateValidator->validateStatus($certContents, [
            'DigiCert Global Root CA' => $ca2,
            'DigiCert SHA2 Secure Server CA' => $ca1,
        ]);

        self::assertTrue($logger->hasWarningThatContains('Unable to check OCSP status.'), 'Should have failed checking');
    }

    #[Test]
    public function validate_certificate_revocation_status_unavailable_only_logs(): void
    {
        $certContents = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            MIIHGTCCBgGgAwIBAgIQBh3eOmYhdHQ4TTZVG+hHijANBgkqhkiG9w0BAQsFADBN
            MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMScwJQYDVQQDEx5E
            aWdpQ2VydCBTSEEyIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMTgwMjA4MDAwMDAwWhcN
            MjEwMjEyMTIwMDAwWjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNV
            BAcTDVNhbiBGcmFuY2lzY28xITAfBgNVBAoTGFNsYWNrIFRlY2hub2xvZ2llcywg
            SW5jLjESMBAGA1UEAxMJc2xhY2suY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
            MIIBCgKCAQEAqb0QCgBUkwHwC1AUT1N1W6wfbKSUZGSQ9Pf7EovdVIt1f8hrq5KZ
            OvVUaU/5qsS9UMm1GGqhjVrFqRKv//rZ/VaIThNaLVGQ3yTWCmnPxTZBvEOH1oLP
            i2V+XgDcX2drRUUfFELQy8EZVABwQu5Y3FluB1S7Nv1EH2tOsug5koMIdtMetUo/
            nKPzpuVC/4C/8oPN3+37cSriAImfxrifrrSCLkMscnwh6VcSuajnlCgw/iVcQzEE
            0OGht+KmFgIvjTWmKLx44MvkKqPUnvBudKk4k+9V527g9uNM0rxCVXWb1hf5w08I
            VvEC5/N78HrBl/q/e2oaygp95z/CQ5aJqQIDAQABo4ID1zCCA9MwHwYDVR0jBBgw
            FoAUD4BhHIIxYdUvKOeNRji0LOHG2eIwHQYDVR0OBBYEFPla7+E8XELNsM7Mg46q
            uGwJyd0tMCEGA1UdEQQaMBiCCXNsYWNrLmNvbYILKi5zbGFjay5jb20wDgYDVR0P
            AQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjBrBgNVHR8E
            ZDBiMC+gLaArhilodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vc3NjYS1zaGEyLWc2
            LmNybDAvoC2gK4YpaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL3NzY2Etc2hhMi1n
            Ni5jcmwwTAYDVR0gBEUwQzA3BglghkgBhv1sAQEwKjAoBggrBgEFBQcCARYcaHR0
            cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAIBgZngQwBAgIwfAYIKwYBBQUHAQEE
            cDBuMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wRgYIKwYB
            BQUHMAKGOmh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJT
            ZWN1cmVTZXJ2ZXJDQS5jcnQwDAYDVR0TAQH/BAIwADCCAfYGCisGAQQB1nkCBAIE
            ggHmBIIB4gHgAHYApLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BAAAAFh
            d2Q95wAABAMARzBFAiEA42uacv79w94og76vu/L9nzZJAsU0398rJZuBAY8EY30C
            IFCuAzawnV4AOtOEEp7ybdy/0SLBgZ7bBO3gs0EhkOYCAHYAh3W/51l8+IxDmV+9
            827/Vo1HVjb/SrVgwbTq/16ggw8AAAFhd2Q9zQAABAMARzBFAiBIhbiWxOmsFEmC
            2I6ZBg8Qb+xSIv0AgqZTnIHSzaR0BwIhALoijpGV0JB2xBgW88noxeHdCeqWXQ/a
            HPDAd/Q37M+WAHYAu9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YUAAAFh
            d2Q+IAAABAMARzBFAiEA0p6Cq67EzeVhxYSpNJYU8Ys7Pj9c4EQPmPaAvnLDL0wC
            IBnOHO2DWoBi+LH6Z/uicH+4nbb4S15zV96NqFn9mXH0AHYAb1N2rDHwMRnYmQCk
            URX/dxUcEdkCwQApBo2yCJo32RMAAAFhd2Q/4AAABAMARzBFAiEA2C3VUu67nO5T
            e2Q8okaIkPftUdE+GHyKkZbqmJMg550CIBFZW53z4BUmtP4GDBEA85D/EnDBPOx2
            OC6cgoRW7sz/MA0GCSqGSIb3DQEBCwUAA4IBAQBUh0yybzRV4ednO+RM4uifnBkf
            S/9r4IHqvFyYgyofd1hygwD3i/pT10V+yF2teqL/FuwsInbjrvGpwFH/uiuhGgzc
            hJ5TOA0/+A/RYNo7sN7An9NBYvedJOlV0iDUhVuQpGefEY3VHqtg0qNu9YoAAl67
            pDCmmQQoNKHDdq2IFq8taF8ros+stqC+cPBipVLxXe9wAFnTkjq0VjB1VqKzLDQ+
            VGN9QV+gw0KI7opJ4K/UKOTnG7ON0zlKIqAK2pXUVsQa9Q5kMbakOk3930bGrkXW
            dqEt/Oc2qDvj/OFnFvaAiKhWUmwhu3IJT4B+W15sPYYBAC4N4FhjP+aGv6IK
            -----END CERTIFICATE-----
            CERT;

        $ca1 = <<<'CERT'
            -----BEGIN CERTIFICATE-----
            MIIElDCCA3ygAwIBAgIQAf2j627KdciIQ4tyS8+8kTANBgkqhkiG9w0BAQsFADBh
            MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
            d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD
            QTAeFw0xMzAzMDgxMjAwMDBaFw0yMzAzMDgxMjAwMDBaME0xCzAJBgNVBAYTAlVT
            MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJzAlBgNVBAMTHkRpZ2lDZXJ0IFNIQTIg
            U2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
            ANyuWJBNwcQwFZA1W248ghX1LFy949v/cUP6ZCWA1O4Yok3wZtAKc24RmDYXZK83
            nf36QYSvx6+M/hpzTc8zl5CilodTgyu5pnVILR1WN3vaMTIa16yrBvSqXUu3R0bd
            KpPDkC55gIDvEwRqFDu1m5K+wgdlTvza/P96rtxcflUxDOg5B6TXvi/TC2rSsd9f
            /ld0Uzs1gN2ujkSYs58O09rg1/RrKatEp0tYhG2SS4HD2nOLEpdIkARFdRrdNzGX
            kujNVA075ME/OV4uuPNcfhCOhkEAjUVmR7ChZc6gqikJTvOX6+guqw9ypzAO+sf0
            /RR3w6RbKFfCs/mC/bdFWJsCAwEAAaOCAVowggFWMBIGA1UdEwEB/wQIMAYBAf8C
            AQAwDgYDVR0PAQH/BAQDAgGGMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYY
            aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMHsGA1UdHwR0MHIwN6A1oDOGMWh0dHA6
            Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcmwwN6A1
            oDOGMWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RD
            QS5jcmwwPQYDVR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8v
            d3d3LmRpZ2ljZXJ0LmNvbS9DUFMwHQYDVR0OBBYEFA+AYRyCMWHVLyjnjUY4tCzh
            xtniMB8GA1UdIwQYMBaAFAPeUDVW0Uy7ZvCj4hsbw5eyPdFVMA0GCSqGSIb3DQEB
            CwUAA4IBAQAjPt9L0jFCpbZ+QlwaRMxp0Wi0XUvgBCFsS+JtzLHgl4+mUwnNqipl
            5TlPHoOlblyYoiQm5vuh7ZPHLgLGTUq/sELfeNqzqPlt/yGFUzZgTHbO7Djc1lGA
            8MXW5dRNJ2Srm8c+cftIl7gzbckTB+6WohsYFfZcTEDts8Ls/3HB40f/1LkAtDdC
            2iDJ6m6K7hQGrn2iWZiIqBtvLfTyyRRfJs8sjX7tN8Cp1Tm5gr8ZDOo0rwAhaPit
            c+LJMto4JQtV05od8GiG7S5BNO98pVAdvzr508EIDObtHopYJeS4d60tbvVS3bR0
            j6tJLp07kzQoH3jOlOrHvdPJbRzeXDLz
            -----END CERTIFICATE-----
            CERT;

        $ca2 = <<<'CERT'
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

        $responseFactory = static function ($method, $url, $options) {
            self::assertSame('http://ocsp.digicert.com/', $url);

            return new MockResponse($options['body'], ['response_headers' => ['content-type' => Ocsp::OCSP_RESPONSE_MEDIATYPE], 'http_code' => 500]);
        };
        $httpClient = new MockHttpClient($responseFactory);

        $ocspProphecy = $this->prophesize(Ocsp::class);
        $ocspProphecy->buildOcspRequestBodySingle(Argument::any())->willReturn('Valid');
        $ocspProphecy->decodeOcspResponseSingle(Argument::any())->shouldNotBeCalled();
        $ocsp = $ocspProphecy->reveal();

        $logger = new TestLogger();

        $this->certificateValidator = new OCSPValidator(
            httpClient: $httpClient,
            logger: $logger,
            ocsp: $ocsp,
        );

        $this->certificateValidator->validateStatus($certContents, [
            'DigiCert Global Root CA' => $ca2,
            'DigiCert SHA2 Secure Server CA' => $ca1,
        ]);

        self::assertTrue($logger->hasWarningThatContains('Unable to check OCSP status.'), 'Should have failed checking');
    }

    private function expectNoFailureLogs(): LoggerInterface
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::never())->method('error');
        $logger->expects(self::never())->method('warning');

        return $logger;
    }
}
